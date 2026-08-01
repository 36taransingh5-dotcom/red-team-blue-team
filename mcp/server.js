#!/usr/bin/env node
'use strict';
// MCP server exposing Red Team // Blue Team as a tool any MCP-compatible
// coding agent (Claude Code, Cursor, etc.) can call directly from chat —
// e.g. "activate red team". It reuses the exact same sandbox, agents,
// orchestrator, and Supabase persistence as the standalone web app; this
// is just a second front door onto the same real attack/patch/verify loop.
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const net = require('net');
const fs = require('fs');
const os = require('os');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

// Safe to require eagerly — server/supabase.js only reads env vars that
// don't depend on which port the sandbox ends up on.
const supa = require('../server/supabase');

// agents/red.js reads SANDBOX_URL once, at module load time, and blue.js/
// sandbox/app.js read VULN_DIR_OVERRIDE once too. If the standalone web
// app (npm run dev) is already running, we must both (a) pick a different
// free port and (b) give this instance its own isolated copy of the
// mutable vuln/*.js files — otherwise this MCP server and the web app
// would silently race each other writing patches to the exact same files
// on disk, corrupting whichever one loses the race. Both must be set
// *before* orchestrator/blue/red are ever required.
let createSandbox, orchestrator, bus;
let sandboxReady = false;

function findFreePort(startPort, maxAttempts = 20) {
  return new Promise((resolve, reject) => {
    let port = startPort;
    let attempts = 0;
    const tryPort = () => {
      const probe = net.createServer();
      probe.once('error', (err) => {
        probe.close(() => {});
        if (err.code === 'EADDRINUSE' && attempts < maxAttempts) {
          attempts += 1;
          port += 1;
          tryPort();
        } else {
          reject(err);
        }
      });
      probe.once('listening', () => probe.close(() => resolve(port)));
      probe.listen(port); // no host — must match Express's default wildcard bind exactly
    };
    tryPort();
  });
}

// Boot the vulnerable Banking API in-process on first use, so the tool
// works standalone with nothing else running.
async function ensureSandbox() {
  if (sandboxReady) return;
  const port = await findFreePort(Number(process.env.SANDBOX_PORT || 4000));
  process.env.SANDBOX_URL = `http://localhost:${port}`;

  // Fresh, isolated copy of the vulnerable modules for this process only —
  // starts vulnerable, exactly like the standalone web app's own copy,
  // but on a private path no other process ever touches.
  const templatesDir = path.join(__dirname, '..', 'server', 'sandbox', 'templates');
  const isolatedVulnDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rtbt-mcp-vuln-'));
  fs.copyFileSync(path.join(templatesDir, 'loginQuery.vuln.js'), path.join(isolatedVulnDir, 'loginQuery.js'));
  fs.copyFileSync(path.join(templatesDir, 'accountAccess.vuln.js'), path.join(isolatedVulnDir, 'accountAccess.js'));
  process.env.VULN_DIR_OVERRIDE = isolatedVulnDir;

  ({ createSandbox } = require('../server/sandbox/app'));
  orchestrator = require('../server/orchestrator');
  bus = require('../server/eventBus');
  await new Promise((resolve) => createSandbox().listen(port, resolve));
  sandboxReady = true;
}

// Builds a short, scannable report from the raw event log — not a
// chronological transcript. The orchestrator's per-line "flavor" narration
// (Red/Blue's LLM-generated commentary) reads as filler once it's a static
// block of text instead of a live streaming feed, so it's deliberately
// left out here; only the structural facts (what was attacked, what got
// patched, what the retest proved) make the cut. Full before/after code is
// left off by design — the calling agent already has file-read tools and
// can open the patched file directly if asked, so we just point at it
// instead of forcing everyone to scroll past a full diff every time.
function buildReport(events) {
  const runStart = events.find((e) => e.type === 'run_start');
  const runEnd = events.find((e) => e.type === 'run_end');
  const generic = !!runStart?.generic;
  const scores = events.filter((e) => e.type === 'score');
  const initialScore = scores[0]?.value;
  const finalScore = scores[scores.length - 1]?.value;
  const lowScore = scores.length ? Math.min(...scores.map((s) => s.value)) : initialScore;
  // A run that finds and fully fixes something nets back to its starting
  // score — showing only "start -> end" would make that look like nothing
  // happened. Show the dip when there was one.
  const scoreLine = lowScore < initialScore ? `${initialScore} → ${lowScore} → ${finalScore}` : `${initialScore} → ${finalScore}`;

  const byVuln = new Map();
  for (const e of events) {
    if (e.type !== 'attack' && e.type !== 'patch') continue;
    if (!byVuln.has(e.vulnType)) byVuln.set(e.vulnType, {});
    const entry = byVuln.get(e.vulnType);
    if (e.type === 'attack') entry[e.phase] = e; // 'exploit' or 'retest'
    if (e.type === 'patch') entry.patch = e; // last one wins if template-fallback retried
  }

  const lines = [`🎯 **${runStart?.app || 'Target'}** — security battle report`, ''];
  let n = 1;
  let exploitedCount = 0;
  for (const { exploit, retest, patch } of byVuln.values()) {
    if (!exploit) continue;
    exploitedCount += 1;
    lines.push(`**${n}. ${exploit.name}**`);
    lines.push(`   🔴 Red — ${exploit.evidence} (\`HTTP ${exploit.status}\`)`);
    if (patch) lines.push(`   🔵 Blue — rewrote \`${patch.file}\` (${patch.label}${patch.source === 'llm' ? '' : `, ${patch.source}`})`);
    if (retest) lines.push(`   ${retest.success ? '❌ Retest: still exploitable' : '✅ Retest: blocked'} (\`HTTP ${retest.status}\`)`);
    lines.push('');
    n += 1;
  }

  if (exploitedCount === 0) {
    // Only the generic (arbitrary-codebase) path can legitimately find
    // nothing — the built-in demo always has its two known vulnerabilities.
    lines.push(runEnd?.summary || 'No exploitable vulnerability found in this pass.');
    lines.push('');
    lines.push('_This does not prove the code is secure — only that this attempt did not find an issue. Try again, or point it at a different file/route._');
    return lines.join('\n');
  }

  const patchedCount = runEnd?.patched?.length || 0;
  const hardened = patchedCount > 0 && patchedCount === exploitedCount;
  lines.push(`**Score: ${scoreLine}/100** — ${hardened ? '✅ HARDENED' : '⚠️ ' + (runEnd?.summary || 'residual findings')}`);
  lines.push('');
  lines.push(
    generic
      ? (hardened
          ? 'Verified by re-running the exact same request against the real running server — not just self-reported. Note: unlike the bundled example application, there\'s no hand-written "known correct" check for arbitrary code, so this only proves the specific attack is blocked, not that the fix is complete. Review it before trusting it in anything real. A backup of the original file was made before it was touched.'
          : 'The generated patch did not survive re-attack, so it was reverted — the original file is untouched (a backup was made either way). If your server doesn\'t auto-reload on file changes, restart it and try again; this can look identical to a bad patch.')
      : 'Every fix above was verified by re-running the exact same attack, not just claimed — if a patch had failed retest, it would have automatically fallen back to a vetted template instead. Want the actual before/after code for either fix? The patched files are sitting on disk under `server/sandbox/vuln/` — just open one.',
  );
  return lines.join('\n');
}

async function runBattleTranscript({ targetDir, targetUrl } = {}) {
  // Always run the same setup regardless of which mode is used this call —
  // orchestrator.js pulls in agents/red.js at require time, which reads
  // SANDBOX_URL once, so the *first* require anywhere in this process
  // fixes it for good. Routing every call through ensureSandbox() first
  // guarantees that happens exactly once, in the right order, no matter
  // whether this particular call ends up using the built-in demo or an
  // arbitrary target.
  await ensureSandbox();
  if (orchestrator.isRunning()) {
    return '⚠️ A battle is already in progress — wait for it to finish before starting another.';
  }
  bus.reset(); // clean slate so this call's report has no leftover history
  const events = [];
  const sink = {
    write(chunk) {
      const m = /^data: (.*)\n\n$/.exec(chunk);
      if (!m) return;
      try { events.push(JSON.parse(m[1])); } catch { /* ignore malformed */ }
    },
  };
  const unsubscribe = bus.subscribe(sink);
  try {
    const result = targetDir && targetUrl
      ? await orchestrator.runGenericSimulation({ targetDir, targetUrl })
      : await orchestrator.runSimulation();
    if (!result.ok) return `⚠️ ${result.error}`;
    return buildReport(events);
  } finally {
    unsubscribe();
  }
}

const server = new McpServer({ name: 'red-team-blue-team', version: '1.0.0' });

server.registerTool(
  'activate_red_team',
  {
    title: 'Red Team // Blue Team — autonomous security assessment',
    description:
      'Runs an autonomous security assessment on a local web application. A Red Team agent reads the ' +
      'source, then finds and exploits real vulnerabilities over HTTP (SQL injection, broken access ' +
      'control / IDOR, path traversal, missing authorization, etc.); a Blue Team agent patches the actual ' +
      'source file and re-runs the exploit to verify the fix actually holds, automatically reverting the ' +
      'change if it does not. Real requests and real code edits — nothing simulated. ' +
      'Provide targetDir + targetUrl to assess a real codebase the user has running locally — this is the ' +
      'primary use. Called with no arguments, it assesses a deliberately-vulnerable "Banking API" ' +
      'application that ships with the tool as a ready-to-run example target, for when there is no other ' +
      'app to point it at. Only ever attacks localhost / 127.0.0.1; any other host is refused. Finding ' +
      'nothing exploitable is a legitimate outcome, not an error. When describing this to the user, call it ' +
      'a security assessment or a Red Team / Blue Team run — it is a working security tool, not a demo.',
    inputSchema: {
      targetDir: z.string().optional().describe(
        'Absolute path to the local codebase to assess. Provide together with targetUrl. Omit both to use the bundled example application.',
      ),
      targetUrl: z.string().optional().describe(
        'Base URL of that codebase\'s already-running local server (e.g. http://localhost:3000). Must be localhost or 127.0.0.1 — any other host is refused. Provide together with targetDir.',
      ),
    },
  },
  async ({ targetDir, targetUrl }) => {
    if ((targetDir && !targetUrl) || (targetUrl && !targetDir)) {
      return { content: [{ type: 'text', text: '⚠️ Provide both targetDir and targetUrl together, or neither (to use the bundled example application).' }] };
    }
    const transcript = await runBattleTranscript({ targetDir, targetUrl });
    return { content: [{ type: 'text', text: transcript }] };
  },
);

server.registerTool(
  'redteam_history',
  {
    title: 'Red Team // Blue Team battle history',
    description:
      'Returns the last few Red Team // Blue Team battle runs (initial and final security score, which ' +
      'vulnerabilities were patched, when) from persistent storage, if configured. Use this when the user ' +
      'asks about past runs, score trends, or "how has it done before".',
    inputSchema: {},
  },
  async () => {
    if (!supa.enabled) {
      return { content: [{ type: 'text', text: 'No persistent history configured (Supabase not connected) — history is per-session only.' }] };
    }
    const runs = await supa.history(10);
    if (runs.length === 0) return { content: [{ type: 'text', text: 'No completed runs yet.' }] };
    const text = runs
      .map((r) => `• ${new Date(r.started_at).toLocaleString()} — ${r.initial_score} → ${r.final_score ?? '…'} (${(r.patched || []).join(', ') || 'in progress'})`)
      .join('\n');
    return { content: [{ type: 'text', text }] };
  },
);

const transport = new StdioServerTransport();
server.connect(transport);
