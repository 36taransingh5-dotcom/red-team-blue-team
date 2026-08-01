'use strict';
// The autonomous battle loop. Drives Red and Blue in turns, streams a
// dramatized-but-real timeline, validates every patch by re-running the
// exploit, and tracks the security score.
const bus = require('./eventBus');
const red = require('./agents/red');
const blue = require('./agents/blue');
const llm = require('./agents/llm');
const supa = require('./supabase');

const BEAT = Number(process.env.BEAT_MS || 650);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let running = false;
let score = 40;
let runId = null;

// Emits to the live SSE timeline and mirrors to Supabase (fire-and-forget —
// a slow or unreachable database must never stall or break the live demo).
function record(event) {
  const enriched = bus.emit(event);
  if (runId) supa.logEvent(runId, enriched).catch(() => {});
  return enriched;
}

function emitScore(delta, reason) {
  score = Math.max(0, Math.min(100, score + delta));
  record({ type: 'score', value: score, delta, reason });
}

async function phase(agent, text) {
  record({ type: 'phase', agent, text });
  await sleep(BEAT);
}

async function log(agent, text, tone) {
  record({ type: 'log', agent, text, tone });
  await sleep(BEAT * 0.6);
}

const EXPLOITS = { sqli: red.exploitSQLi, idor: red.exploitIDOR };

// Run one full attack→patch→verify cycle for a single vulnerability.
async function battleVuln(vulnType, ordinal) {
  const attack = EXPLOITS[vulnType];

  // 1. RED exploits.
  await phase('red', `Testing target: ${vulnType.toUpperCase()}`);
  const hit = await attack();
  record({ type: 'attack', phase: 'exploit', ...hit });
  await sleep(BEAT);
  if (!hit.success) {
    await log('red', `${hit.name} not exploitable. Moving on.`);
    return;
  }
  await log('red', await red.think(`Exploit landed: ${hit.name}. Evidence: ${hit.evidence}`), 'bad');

  // 2. BLUE detects + patches (real file write, LLM-generated when possible).
  await phase('blue', `Threat detected: ${hit.name}`);
  await log('blue', await blue.think(`Analyzing ${hit.name}. Root cause and fix?`));
  const patch = await blue.proposePatch(vulnType);
  record({
    type: 'patch',
    vulnType,
    file: patch.file,
    before: patch.before,
    after: patch.after,
    source: patch.source,
    label: patch.label,
  });
  await log('blue', `Patch written to ${patch.file} (${patch.label}, via ${patch.source}). Verifying…`);
  await sleep(BEAT);

  // 3. RED re-tests to VALIDATE the patch. If it still lands, Blue falls
  //    back to the vetted secure template and we re-verify.
  let verify = await attack();
  if (verify.success) {
    await log('blue', 'Generated patch failed validation. Applying vetted hardening.', 'warn');
    blue.applySecureTemplate(vulnType);
    record({ type: 'patch', vulnType, file: patch.file, before: patch.before,
      after: blue.readActive(vulnType), source: 'template (validated)', label: patch.label });
    await sleep(BEAT);
    verify = await attack();
  }
  record({ type: 'attack', phase: 'retest', ...verify });
  await sleep(BEAT);

  if (!verify.success) {
    await log('red', await red.think(`My ${vulnType} attack is now blocked (HTTP ${verify.status}).`), 'blocked');
    await log('blue', `${hit.name} remediated and verified.`, 'good');
    emitScore(vulnType === 'idor' ? 26 : 30, `${hit.name} patched & verified`);
  } else {
    await log('blue', 'Vulnerability persists — flagged for human review.', 'warn');
  }
}

async function runSimulation() {
  if (running) return { ok: false, error: 'simulation already running' };
  running = true;
  try {
    bus.reset();
    score = 40;
    blue.resetToVulnerable();
    runId = await supa.startRun({ model: llm.model, initialScore: score });
    record({ type: 'run_start', llm: llm.enabled, model: llm.model, app: 'Banking API Demo', persisted: supa.enabled });
    record({ type: 'score', value: score, delta: 0, reason: '2 critical vulnerabilities present' });
    await sleep(BEAT);

    await phase('red', 'Reconnaissance started');
    const recon = await red.recon();
    await log('red', `Target online: ${recon.service}. Endpoints mapped: ${recon.endpoints.join(', ')}.`);
    await log('red', await red.think('Beginning attack surface analysis on the banking API.'));

    await battleVuln('sqli', 1);
    await log('red', await red.think('Primary auth bypass closed. Searching for alternative paths.'));
    await battleVuln('idor', 2);

    // Final sweep — prove both attacks are dead.
    await phase('system', 'Final verification sweep');
    const s = await red.exploitSQLi();
    const i = await red.exploitIDOR();
    const patched = [!s.success && 'SQLi', !i.success && 'IDOR'].filter(Boolean);
    if (patched.length === 2) emitScore(0, 'All known vulnerabilities remediated');
    record({
      type: 'run_end',
      score,
      patched,
      summary:
        patched.length === 2
          ? 'Application hardened. Both critical vulnerabilities neutralized and verified.'
          : 'Simulation complete with residual findings.',
    });
    await supa.endRun(runId, { finalScore: score, patched });
    return { ok: true, score };
  } finally {
    running = false;
    runId = null;
  }
}

module.exports = { runSimulation, isRunning: () => running };
