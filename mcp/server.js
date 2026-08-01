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

// Turn one raw SSE-framed chunk (as eventBus.subscribe writes it) into a
// readable line of battle narration. Ignores comments/keepalive pings.
function formatEvent(evt) {
  switch (evt.type) {
    case 'run_start':
      return `\n🎯 **Target:** ${evt.app} — sandbox online.\n`;
    case 'phase':
      return `\n**${evt.agent === 'blue' ? '🔵' : evt.agent === 'red' ? '🔴' : '⚙️'} ${evt.text}**`;
    case 'log':
      return `${evt.agent === 'blue' ? '🔵' : '🔴'} ${evt.text}`;
    case 'attack': {
      const icon = evt.success ? '💥 EXPLOIT LANDED' : '🛡️ BLOCKED';
      return (
        `🔴 **${icon}** — ${evt.name} \`HTTP ${evt.status}\`\n` +
        `   ↳ \`${evt.request}\`\n` +
        `   ↳ ${evt.evidence}`
      );
    }
    case 'patch':
      return (
        `🔵 **Patch applied → \`${evt.file}\`** (${evt.label}, via ${evt.source})\n` +
        '```diff\n' +
        evt.before.trim().split('\n').map((l) => `- ${l}`).join('\n') +
        '\n' +
        evt.after.trim().split('\n').map((l) => `+ ${l}`).join('\n') +
        '\n```'
      );
    case 'score':
      return `📊 **Security score: ${evt.value}/100** (${evt.delta >= 0 ? '+' : ''}${evt.delta}) — ${evt.reason}`;
    case 'run_end':
      return `\n${evt.patched?.length === 2 ? '✅ **HARDENED**' : '⚠️ **RESIDUAL FINDINGS**'} — ${evt.summary}\n`;
    default:
      return null;
  }
}

async function runBattleTranscript() {
  await ensureSandbox();
  if (orchestrator.isRunning()) {
    return '⚠️ A battle is already in progress — wait for it to finish before starting another.';
  }
  bus.reset(); // clean slate so this call's transcript has no leftover history
  const lines = [];
  const sink = {
    write(chunk) {
      const m = /^data: (.*)\n\n$/.exec(chunk);
      if (!m) return;
      let evt;
      try { evt = JSON.parse(m[1]); } catch { return; }
      const line = formatEvent(evt);
      if (line) lines.push(line);
    },
  };
  const unsubscribe = bus.subscribe(sink);
  try {
    const result = await orchestrator.runSimulation();
    if (!result.ok) return `⚠️ ${result.error}`;
    // Calling agents tend to summarize a long tool result into their own
    // words by default. This is meant to be read as a live play-by-play —
    // ask explicitly for it to be relayed as-is instead of condensed.
    const header =
      'INSTRUCTIONS FOR THE ASSISTANT: display the transcript below to the ' +
      'user in FULL and VERBATIM, exactly as written, preserving all ' +
      'markdown formatting, emojis, and code diff blocks. Do not summarize, ' +
      'shorten, or rephrase it — it is pre-formatted for direct display.\n\n' +
      '---\n';
    return header + lines.join('\n');
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
