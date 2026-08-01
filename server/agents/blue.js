'use strict';
// BLUE TEAM — defensive agent. Reads the vulnerable module, generates a
// hardened rewrite (LLM when available), writes it to the live sandbox,
// and exposes a known-good fallback for when a generated patch fails
// validation. Patches are REAL file writes; the sandbox hot-reloads them.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { narrate, generatePatch } = require('./llm');
const { db } = require('../sandbox/db');

// Must resolve identically to sandbox/app.js's VULN_DIR — same override,
// so Blue writes patches to exactly the files the live sandbox re-requires.
const VULN_DIR = process.env.VULN_DIR_OVERRIDE || path.join(__dirname, '..', 'sandbox', 'vuln');
const TPL_DIR = path.join(__dirname, '..', 'sandbox', 'templates');

const MAP = {
  sqli: {
    file: 'loginQuery.js',
    secure: 'loginQuery.secure.js',
    vuln: 'loginQuery.vuln.js',
    guidance: 'Use a parameterized query (mode "param") so user input can never alter SQL structure.',
    label: 'parameterized query',
  },
  idor: {
    file: 'accountAccess.js',
    secure: 'accountAccess.secure.js',
    vuln: 'accountAccess.vuln.js',
    guidance: 'The function signature is ({ callerId, callerRole, targetId }) — role is passed separately as callerRole, never compare callerId to the string "admin". Deny if callerId is null/undefined. Otherwise allow only if callerRole === "admin" or callerId === targetId.',
    label: 'ownership + auth enforcement',
  },
};

// Functional checks run against a candidate module before it's ever written
// into the live sandbox. LLM output can be syntactically broken, a
// half-finished stub, or — the harder case — perfectly valid JS that
// returns the right *shape* while getting the security decision wrong
// (e.g. a fake "isAdmin" check that can never be true). A shape check
// can't catch that; only actually exercising the real decision can. These
// checks mirror exactly what Red re-attacks with, so a patch that passes
// here is guaranteed to survive the live retest too.
const VALIDATORS = {
  sqli: (fn) => {
    const bad = fn("' OR 1=1 --", 'x');
    const good = fn('admin', 'S3cur3-Vault-2026');
    for (const r of [bad, good]) {
      if (!r || typeof r.sql !== 'string' || !Array.isArray(r.params)) {
        throw new Error('unexpected return shape');
      }
    }
    const run = (r) => {
      const stmt = db.prepare(r.sql);
      return r.mode === 'param' ? stmt.get(...r.params) : stmt.get();
    };
    if (run(bad)) throw new Error('injection payload still authenticates — SQL not safely parameterized');
    if (!run(good)) throw new Error('legitimate login now fails — patch broke normal auth');
  },
  idor: (fn) => {
    const owner = fn({ callerId: 2, callerRole: 'customer', targetId: 2 });
    const stranger = fn({ callerId: 2, callerRole: 'customer', targetId: 1 });
    const admin = fn({ callerId: 1, callerRole: 'admin', targetId: 2 });
    const anon = fn({ callerId: null, callerRole: null, targetId: 1 });
    for (const r of [owner, stranger, admin, anon]) {
      if (!r || typeof r.allow !== 'boolean') throw new Error('unexpected return shape');
    }
    if (owner.allow !== true) throw new Error('owner must be able to read their own account');
    if (stranger.allow !== false) throw new Error('a non-owner, non-admin caller must be denied');
    if (admin.allow !== true) throw new Error('admin must be able to read any account');
    if (anon.allow !== false) throw new Error('unauthenticated caller must be denied');
  },
};

// Load candidate code from a throwaway temp file (so syntax errors surface
// as a catchable require() throw, never touching the live module) and
// exercise it with representative inputs before it's trusted.
function validateCandidate(vulnType, code) {
  const tmpFile = path.join(os.tmpdir(), `rtbt-candidate-${crypto.randomBytes(6).toString('hex')}.js`);
  try {
    fs.writeFileSync(tmpFile, code);
    delete require.cache[require.resolve(tmpFile)];
    const fn = require(tmpFile);
    if (typeof fn !== 'function') throw new Error('module.exports is not a function');
    VALIDATORS[vulnType](fn);
    return true;
  } catch {
    return false;
  } finally {
    try { delete require.cache[require.resolve(tmpFile)]; } catch { /* not loaded */ }
    try { fs.unlinkSync(tmpFile); } catch { /* already gone */ }
  }
}

const BLUE_SYS =
  'You are BLUE TEAM, a careful defensive security engineer in an autonomous ' +
  'cyber range. Speak in short, calm operator lines (max 18 words).';

async function think(context) {
  return narrate({ system: BLUE_SYS, user: context, fallback: context, maxTokens: 40 });
}

function readActive(vulnType) {
  return fs.readFileSync(path.join(VULN_DIR, MAP[vulnType].file), 'utf8');
}

// Attempt an LLM-generated patch; return the candidate + provenance.
// Does NOT decide validity — the orchestrator validates by re-attacking.
async function proposePatch(vulnType) {
  const cfg = MAP[vulnType];
  const before = readActive(vulnType);
  const candidate = await generatePatch({
    vulnType,
    vulnerableCode: before,
    guidance: cfg.guidance,
  });
  let after = candidate;
  let source = 'llm';
  if (!after || !validateCandidate(vulnType, after)) {
    after = fs.readFileSync(path.join(TPL_DIR, cfg.secure), 'utf8');
    source = candidate ? 'template (llm output failed validation)' : 'template';
  }
  fs.writeFileSync(path.join(VULN_DIR, cfg.file), after);
  return { before, after, source, label: cfg.label, file: cfg.file };
}

// Force the vetted secure template (used if a generated patch fails re-test).
function applySecureTemplate(vulnType) {
  const cfg = MAP[vulnType];
  const after = fs.readFileSync(path.join(TPL_DIR, cfg.secure), 'utf8');
  fs.writeFileSync(path.join(VULN_DIR, cfg.file), after);
  return { after, file: cfg.file, label: cfg.label };
}

// Reset the sandbox to its fully vulnerable state for a fresh simulation.
function resetToVulnerable() {
  for (const key of Object.keys(MAP)) {
    const cfg = MAP[key];
    const src = fs.readFileSync(path.join(TPL_DIR, cfg.vuln), 'utf8');
    fs.writeFileSync(path.join(VULN_DIR, cfg.file), src);
  }
}

module.exports = { think, proposePatch, applySecureTemplate, resetToVulnerable, readActive, MAP };
