'use strict';
// The autonomous battle loop. Drives Red and Blue in turns, streams a
// dramatized-but-real timeline, validates every patch by re-running the
// exploit, and tracks the security score.
const bus = require('./eventBus');
const red = require('./agents/red');
const blue = require('./agents/blue');
const llm = require('./agents/llm');
const supa = require('./supabase');
const genericRed = require('./agents/genericRed');
const genericBlue = require('./agents/genericBlue');

const SEVERITY_POINTS = { critical: 40, high: 25, medium: 15, low: 8 };

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
    record({ type: 'run_start', llm: llm.enabled, model: llm.model, app: 'Banking API (example target)', persisted: supa.enabled });
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

// Patch + verify one already-confirmed finding. Returns the vulnerability
// name if it was successfully remediated, or null otherwise (patch
// couldn't be safely applied, or didn't survive re-attack and was
// reverted) — either way the original file is never left in a worse or
// unverified state than before.
async function battleGenericFinding({ targetDir, finding }) {
  const findingId = `${finding.file}::${finding.name}`.replace(/[^a-zA-Z0-9]/g, '_');
  record({
    type: 'attack', phase: 'exploit', vulnType: findingId, name: finding.name,
    success: true, status: finding.status, request: finding.requestSummary, evidence: finding.evidence,
  });

  const severity = SEVERITY_POINTS[finding.severity] || SEVERITY_POINTS.medium;
  emitScore(-severity, `${finding.name} found in ${finding.file} (${finding.severity})`);
  await log('red', `Exploit landed: ${finding.name} in ${finding.file}. ${finding.evidence}`, 'bad');

  await phase('blue', `Threat detected: ${finding.name}`);
  const patchResult = await genericBlue.patchFinding({
    targetDir, file: finding.file, name: finding.name,
    description: finding.description, requestSummary: finding.requestSummary,
  });

  if (!patchResult.applied) {
    await log('blue', `Could not safely apply a fix: ${patchResult.reason}. Original file left untouched (backup at ${patchResult.backupPath}).`, 'warn');
    return null;
  }

  record({
    type: 'patch', vulnType: findingId, file: finding.file,
    before: patchResult.before, after: patchResult.after, source: 'llm', label: finding.name,
  });
  await log('blue', `Patch written to ${finding.file}. Verifying by re-running the same exploit…`);
  await sleep(BEAT);

  const retestResult = await genericRed.retest(finding);
  record({
    type: 'attack', phase: 'retest', vulnType: findingId, name: finding.name,
    success: retestResult.success, status: retestResult.status, request: retestResult.requestSummary, evidence: retestResult.evidence,
  });

  if (!retestResult.success) {
    emitScore(severity, `${finding.name} patched & verified`);
    await log('blue', `${finding.name} remediated and verified by re-attack.`, 'good');
    return finding.name;
  }

  genericBlue.revert(targetDir, finding.file, patchResult.backupPath);
  await log(
    'blue',
    `Patch did not survive re-attack — reverted ${finding.file} to its original state. ` +
      `(If your server doesn't hot-reload file changes, restart it and try again — this may be a false negative, not a bad patch.)`,
    'warn',
  );
  return null;
}

// Same battle loop shape as runSimulation, but against a real, arbitrary
// local codebase instead of the built-in Banking Demo — Red has to find
// vulnerabilities first (not guaranteed to find any at all), there's no
// vetted secure template to fall back to if a patch doesn't hold, and
// unlike the fixed demo (which always has exactly its two known bugs),
// a run here can surface anywhere from zero to several different findings.
async function runGenericSimulation({ targetDir, targetUrl }) {
  if (running) return { ok: false, error: 'simulation already running' };
  running = true;
  try {
    bus.reset();
    score = 100;
    runId = await supa.startRun({ model: llm.model, initialScore: score });
    record({
      type: 'run_start', llm: llm.enabled, model: llm.model,
      app: `${targetDir} (${targetUrl})`, persisted: supa.enabled, generic: true,
    });
    record({ type: 'score', value: score, delta: 0, reason: 'baseline — scanning for vulnerabilities' });
    await sleep(BEAT);

    await phase('red', 'Reconnaissance started');
    await log('red', `Scanning ${targetDir} for attack surface against ${targetUrl}...`);

    let findings, attempts;
    try {
      ({ findings, attempts } = await genericRed.reconAndExploitAll({ targetDir, targetUrl }));
    } catch (err) {
      record({ type: 'run_end', score, patched: [], generic: true, summary: `Aborted: ${err.message}` });
      return { ok: false, error: err.message };
    }

    const successfulKeys = new Set(findings.map((f) => `${f.file}::${f.name}`));
    for (const a of attempts) {
      if (successfulKeys.has(`${a.file}::${a.name}`)) continue; // gets its own full 'attack' event below
      await log('red', `Tried ${a.name} (${a.requestSummary}) — no luck: ${a.evidence}`);
    }
    if (attempts.length === 0) await log('red', 'No plausible vulnerability candidates found in the code shown.');

    if (findings.length === 0) {
      record({
        type: 'run_end', score, patched: [], generic: true,
        summary: `No exploitable vulnerability found${attempts.length ? ` (tried ${attempts.length})` : ''}. This does not prove the app is secure — only that this attempt did not find one.`,
      });
      await supa.endRun(runId, { finalScore: score, patched: [] });
      return { ok: true, score };
    }

    await log('red', `${findings.length} distinct vulnerabilit${findings.length === 1 ? 'y' : 'ies'} confirmed exploitable: ${findings.map((f) => f.name).join(', ')}. Working through them one at a time.`);

    const patched = [];
    for (const finding of findings) {
      const remediatedName = await battleGenericFinding({ targetDir, finding });
      if (remediatedName) patched.push(remediatedName);
    }

    record({
      type: 'run_end', score, patched, generic: true,
      summary: patched.length === findings.length
        ? `All ${findings.length} found vulnerabilit${findings.length === 1 ? 'y' : 'ies'} remediated and verified.`
        : `${patched.length}/${findings.length} found vulnerabilities remediated — the rest are flagged for human review.`,
    });
    await supa.endRun(runId, { finalScore: score, patched });
    return { ok: true, score };
  } finally {
    running = false;
    runId = null;
  }
}

module.exports = { runSimulation, runGenericSimulation, isRunning: () => running };
