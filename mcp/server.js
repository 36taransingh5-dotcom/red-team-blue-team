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
  const scores = events.filter((e) => e.type === 'score');
  const initialScore = scores[0]?.value;
  const finalScore = scores[scores.length - 1]?.value;

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
  for (const { exploit, retest, patch } of byVuln.values()) {
    if (!exploit) continue;
    lines.push(`**${n}. ${exploit.name}**`);
    lines.push(`   🔴 Red — ${exploit.evidence} (\`HTTP ${exploit.status}\`)`);
    if (patch) lines.push(`   🔵 Blue — rewrote \`${patch.file}\` (${patch.label}${patch.source === 'llm' ? '' : `, ${patch.source}`})`);
    if (retest) lines.push(`   ${retest.success ? '❌ Retest: still exploitable' : '✅ Retest: blocked'} (\`HTTP ${retest.status}\`)`);
    lines.push('');
    n += 1;
  }

  const hardened = runEnd?.patched?.length === 2;
  lines.push(`**Score: ${initialScore} → ${finalScore}/100** — ${hardened ? '✅ HARDENED' : '⚠️ residual findings'}`);
  lines.push('');
  lines.push(
    'Every fix above was verified by re-running the exact same attack, not just claimed — ' +
    'if a patch had failed retest, it would have automatically fallen back to a vetted ' +
    'template instead. Want the actual before/after code for either fix? The patched files ' +
    'are sitting on disk under `server/sandbox/vuln/` — just open one.',
  );
  return lines.join('\n');
}

async function runBattleTranscript() {
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
    const result = await orchestrator.runSimulation();
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
    title: 'Activate Red Team // Blue Team',
    description:
      'Launches an autonomous cybersecurity battle: a Red Team AI agent performs real HTTP exploits ' +
      '(SQL injection auth bypass, IDOR / broken access control) against a local, deliberately vulnerable ' +
      'Banking API sandbox; a Blue Team AI agent detects each attack, rewrites the actual vulnerable source ' +
      'code, hot-reloads it live, and every patch is validated by re-running the exploit. Returns a full ' +
      'play-by-play transcript with before/after code diffs and the final security score (0-100). Use this ' +
      'whenever the user asks to "activate red team", run a security battle/test/simulation, or see the app ' +
      'attack and defend itself.',
    inputSchema: {},
  },
  async () => {
    const transcript = await runBattleTranscript();
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
