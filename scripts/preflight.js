#!/usr/bin/env node
'use strict';
// Pre-demo health check. Run this before you demo, live, to judges.
// Exercises the real stack end-to-end (not mocks): the web control API,
// a full attack -> patch -> verify battle, Supabase persistence (if
// configured), and the MCP server — the same two front doors judges may
// see. Exits non-zero if anything that would embarrass you live is broken.
//
// Usage: node scripts/preflight.js   (requires `npm run dev` already running)

const path = require('path');
const { spawn } = require('child_process');

const BASE = process.env.PREFLIGHT_BASE_URL || 'http://localhost:3001';
const results = [];

function pass(label, detail) { results.push({ ok: true, label, detail }); console.log(`  \x1b[32m✔\x1b[0m ${label}${detail ? ` — ${detail}` : ''}`); }
function fail(label, detail) { results.push({ ok: false, label, detail }); console.log(`  \x1b[31m✘\x1b[0m ${label}${detail ? ` — ${detail}` : ''}`); }
function section(title) { console.log(`\n\x1b[1m${title}\x1b[0m`); }

async function checkControlApiUp() {
  section('1. Control API');
  try {
    const res = await fetch(`${BASE}/api/status`, { signal: AbortSignal.timeout(3000) });
    const s = await res.json();
    pass('Control API reachable', BASE);
    pass('LLM agents', s.llm ? `ENABLED (${s.model})` : 'fallback mode — no OPENAI_API_KEY set');
    pass('Supabase persistence', s.persisted ? 'ENABLED' : 'disabled — history is in-memory only');
    if (!s.llm) console.log('    \x1b[33m→ recommend setting OPENAI_API_KEY before demoing — fallback mode still works but is less impressive.\x1b[0m');
    if (!s.persisted) console.log('    \x1b[33m→ optional: set SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY for a persistent Battle History panel.\x1b[0m');
    return s;
  } catch (err) {
    fail('Control API reachable', `${err.message} — is "npm run dev" running?`);
    return null;
  }
}

// Subscribes to the SSE timeline, triggers a real run, and collects every
// event until run_end (or a timeout) — the same signal the UI itself uses.
async function runFullBattle() {
  section('2. Full battle (real exploit -> real patch -> real re-attack)');

  // Fire the trigger BEFORE subscribing, not after. orchestrator.runSimulation()
  // calls bus.reset() synchronously before its first `await`, so by the time
  // this POST's response comes back, the server's event log is guaranteed
  // to already be reset. Only *then* do we open the SSE stream — so the
  // replay-on-subscribe a new client always gets can never hand us a stale,
  // already-finished previous run. Subscribing first (the naive order) races
  // exactly that: a full stale run_start..run_end can replay in the very
  // first chunk, long before this POST even lands, and a collector that
  // stops on the first run_end it sees would report false success without
  // ever having observed the real run at all.
  const startRes = await fetch(`${BASE}/api/simulate/start`, { method: 'POST' });
  const startBody = await startRes.json();
  if (!startBody.ok) { fail('Trigger simulation', startBody.error); return null; }
  pass('Simulation started');

  const events = [];
  const streamRes = await fetch(`${BASE}/api/stream`, { signal: AbortSignal.timeout(60000) });
  const reader = streamRes.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let done = false;

  const collect = (async () => {
    while (!done) {
      const { value, done: streamDone } = await reader.read();
      if (streamDone) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, idx + 2);
        buf = buf.slice(idx + 2);
        const m = /^data: (.*)\n\n$/.exec(chunk);
        if (!m) continue;
        try {
          const evt = JSON.parse(m[1]);
          if (evt.type === 'run_start') events.length = 0;
          events.push(evt);
          if (evt.type === 'run_end') { done = true; }
        } catch { /* ignore malformed */ }
      }
    }
  })();

  await Promise.race([
    collect,
    new Promise((_, rej) => setTimeout(() => rej(new Error('timed out after 60s')), 60000)),
  ]).catch((err) => fail('Battle completed within 60s', err.message));

  reader.cancel().catch(() => {});
  const runStartEvt = events.find((e) => e.type === 'run_start');
  const runEndEvt = events.find((e) => e.type === 'run_end');
  const elapsed = runStartEvt && runEndEvt ? ((runEndEvt.at - runStartEvt.at) / 1000).toFixed(1) : '?';

  const attacks = events.filter((e) => e.type === 'attack');
  const patches = events.filter((e) => e.type === 'patch');
  const runEnd = events.find((e) => e.type === 'run_end');
  const scoreEvents = events.filter((e) => e.type === 'score');
  const finalScore = scoreEvents.length ? scoreEvents[scoreEvents.length - 1].value : null;

  if (!runEnd) { fail('Battle reached run_end', `only got ${events.length} events in ${elapsed}s`); return null; }
  pass('Battle completed', `${elapsed}s, ${events.length} events`);

  const exploits = attacks.filter((a) => a.phase === 'exploit');
  const retests = attacks.filter((a) => a.phase === 'retest');
  if (exploits.length === 2 && exploits.every((a) => a.success)) pass('Both exploits actually landed (HTTP 200)');
  else fail('Both exploits landed', `${exploits.filter((a) => a.success).length}/2 succeeded`);

  if (retests.length === 2 && retests.every((a) => !a.success)) pass('Both re-attacks blocked after patching');
  else fail('Both re-attacks blocked', `${retests.filter((a) => !a.success).length}/2 blocked`);

  if (patches.length === 2) pass('Two patches applied', patches.map((p) => `${p.file} (${p.source})`).join(', '));
  else fail('Two patches applied', `only ${patches.length}`);

  const llmPatches = patches.filter((p) => p.source === 'llm').length;
  if (llmPatches < patches.length) {
    console.log(`    \x1b[33m→ ${patches.length - llmPatches}/${patches.length} patch(es) fell back to the vetted template (LLM output failed validation, or LLM disabled). Safe, but worth knowing before you say "the AI wrote this fix" on stage.\x1b[0m`);
  }

  if (finalScore >= 90) pass('Final security score', `${finalScore}/100`);
  else fail('Final security score', `only ${finalScore}/100 — expected ~96`);

  return { finalScore, patched: runEnd.patched };
}

async function checkSandboxLockedDown() {
  section('3. Sandbox actually locked down (direct check, bypasses self-reported events)');
  try {
    const idor = await fetch('http://localhost:4000/api/accounts/1', { signal: AbortSignal.timeout(3000) });
    const idorBody = await idor.json();
    if (!idorBody.ok) pass('IDOR blocked', `HTTP ${idor.status}`);
    else fail('IDOR blocked', 'account 1 was readable with no auth header!');
  } catch (err) { fail('IDOR check reachable', err.message); }

  try {
    const sqli = await fetch('http://localhost:4000/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: "' OR 1=1 --", password: 'x' }),
      signal: AbortSignal.timeout(3000),
    });
    const sqliBody = await sqli.json();
    if (!sqliBody.ok) pass('SQL injection blocked', `HTTP ${sqli.status}`);
    else fail('SQL injection blocked', 'the injection payload still authenticated!');
  } catch (err) { fail('SQLi check reachable', err.message); }
}

async function checkSupabaseHistory(status) {
  if (!status?.persisted) return;
  section('4. Supabase history');
  try {
    const res = await fetch(`${BASE}/api/history`, { signal: AbortSignal.timeout(5000) });
    const body = await res.json();
    if (body.runs?.length > 0) pass('Battle History has entries', `${body.runs.length} run(s), latest score ${body.runs[0].final_score}`);
    else fail('Battle History has entries', 'history endpoint returned zero runs after a completed battle');
  } catch (err) { fail('History endpoint reachable', err.message); }
}

// Speaks raw MCP JSON-RPC over stdio to mcp/server.js — the same protocol
// Claude Code / Cursor / Codex use — to prove the "activate red team"
// in-IDE path works independently of the web app.
async function checkMcpServer() {
  section('5. MCP server ("activate red team" in your coding agent)');
  const serverPath = path.join(__dirname, '..', 'mcp', 'server.js');
  const child = spawn('node', ['--experimental-sqlite', '--no-warnings', serverPath], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d.toString(); });

  let buf = '';
  const pending = new Map();
  let nextId = 1;
  child.stdout.on('data', (chunk) => {
    buf += chunk.toString();
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    }
  });
  const send = (method, params) => new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');

  try {
    await send('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'preflight', version: '1.0.0' } });
    notify('notifications/initialized', {});
    pass('MCP server starts and completes handshake');

    const list = await Promise.race([
      send('tools/list', {}),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timed out')), 10000)),
    ]);
    const names = (list.result?.tools || []).map((t) => t.name);
    if (names.includes('activate_red_team') && names.includes('redteam_history')) pass('Both tools registered', names.join(', '));
    else fail('Both tools registered', `got: ${names.join(', ') || 'none'}`);

    console.log('    running activate_red_team via MCP (boots its own sandbox, ~15-30s)...');
    const call = await Promise.race([
      send('tools/call', { name: 'activate_red_team', arguments: {} }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timed out after 60s')), 60000)),
    ]);
    const text = call.result?.content?.[0]?.text || '';
    if (call.error) fail('activate_red_team via MCP', JSON.stringify(call.error));
    else if (text.includes('HARDENED')) pass('activate_red_team via MCP reached HARDENED', `${text.length} chars of transcript`);
    else fail('activate_red_team via MCP reached HARDENED', text.slice(0, 200) || '(empty response)');
  } catch (err) {
    fail('MCP server round-trip', `${err.message}${stderr ? ` | stderr: ${stderr.slice(0, 300)}` : ''}`);
  } finally {
    child.kill();
  }
}

(async () => {
  console.log('\x1b[1m\nRed Team // Blue Team — pre-demo preflight\x1b[0m');
  const status = await checkControlApiUp();
  if (status) {
    await runFullBattle();
    await checkSandboxLockedDown();
    await checkSupabaseHistory(status);
  } else {
    console.log('\n\x1b[33mSkipping web-app checks — start the server first:\x1b[0m\n  npm run dev\n');
  }
  await checkMcpServer();

  const failures = results.filter((r) => !r.ok);
  console.log(`\n\x1b[1m${'='.repeat(50)}\x1b[0m`);
  if (failures.length === 0) {
    console.log(`\x1b[32m\x1b[1m✔ ${results.length}/${results.length} checks passed — you're demo ready.\x1b[0m`);
    process.exit(0);
  } else {
    console.log(`\x1b[31m\x1b[1m✘ ${failures.length}/${results.length} checks failed:\x1b[0m`);
    for (const f of failures) console.log(`  - ${f.label}: ${f.detail}`);
    process.exit(1);
  }
})();
