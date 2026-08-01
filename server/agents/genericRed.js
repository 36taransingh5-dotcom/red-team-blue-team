'use strict';
// RED TEAM, generic-target mode — reads a real, arbitrary local codebase
// for the first time and tries to find and exploit a genuine vulnerability
// against a real running server, instead of the two pre-written exploits
// used against the built-in Banking Demo. This is inherently less
// predictable than the fixed demo: an LLM is reasoning about code it has
// never seen and generating a real HTTP request from that reasoning.
//
// Safety: only ever attacks localhost — this is a hard requirement, not a
// suggestion, enforced in code below.
const fs = require('fs');
const path = require('path');
const llm = require('./llm');

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.cache']);
const CODE_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts']);
const SUSPICIOUS_PATTERNS = [
  /req\.(params|query|body)/,
  /readFileSync|readFile\(|createReadStream/,
  /SELECT|INSERT INTO|UPDATE .* SET|DELETE FROM/i,
  /\bexec\(|execSync|spawn\(/,
  /\beval\(/,
  /\.(get|post|put|delete|patch)\(\s*['"`]/, // route definitions
  /path\.join/,
];

function assertLocalhost(targetUrl) {
  const url = new URL(targetUrl);
  if (!['localhost', '127.0.0.1'].includes(url.hostname)) {
    throw new Error(`refusing to attack non-local target: ${url.hostname} (only localhost/127.0.0.1 allowed)`);
  }
  return url;
}

function walkCodeFiles(rootDir, maxFiles = 60) {
  const results = [];
  function walk(dir, depth) {
    if (results.length >= maxFiles || depth > 6) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (results.length >= maxFiles) return;
      if (entry.name.startsWith('.') || SKIP_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full, depth + 1);
      else if (CODE_EXTS.has(path.extname(entry.name))) results.push(full);
    }
  }
  walk(rootDir, 0);
  return results;
}

// Cheap, local pre-filter so we only send the LLM the files most likely to
// matter, keeping token usage and latency bounded regardless of repo size.
function shortlistFiles(rootDir, maxSelected = 6, maxBytesEach = 6000) {
  const files = walkCodeFiles(rootDir);
  const scored = [];
  for (const full of files) {
    let content;
    try { content = fs.readFileSync(full, 'utf8'); } catch { continue; }
    let score = 0;
    for (const pattern of SUSPICIOUS_PATTERNS) if (pattern.test(content)) score += 1;
    if (score === 0) continue;
    scored.push({ file: path.relative(rootDir, full), content: content.slice(0, maxBytesEach), score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxSelected);
}

// Asks for several candidates, not one guess — a single-shot proposal
// both picks only one vulnerability out of possibly several real ones,
// and for anything requiring a guess (e.g. how many "../" a path
// traversal needs), one attempt has no room to be wrong and recover.
// Real pentesting tries a few angles; this mirrors that instead of
// betting everything on the model's first idea.
async function proposeExploits({ targetDir, targetUrl, maxCandidates = 8 }) {
  const shortlisted = shortlistFiles(targetDir);
  if (shortlisted.length === 0) return [];

  const filesBlock = shortlisted.map((f) => `--- ${f.file} ---\n${f.content}`).join('\n\n');

  const result = await llm.askJSON({
    system:
      'You are RED TEAM, an ethical penetration tester. You will be shown real source ' +
      'files from a running local server and must propose up to ' + maxCandidates + ' concrete, ' +
      'exploitable vulnerabilities. Look across ALL the files shown, not just the first issue ' +
      'you notice — actively look for DIFFERENT vulnerability classes across DIFFERENT routes ' +
      '(e.g. SQL injection in one endpoint, broken access control / IDOR in another, path ' +
      'traversal in a third, missing authorization, hardcoded secrets exposed via an endpoint) ' +
      'rather than only elaborating on one. Order candidates most to least likely to succeed. ' +
      'If a vulnerability requires guessing something (like how many "../" a path traversal ' +
      'needs to escape a nested directory), include a couple of candidates trying different ' +
      'depths/values for THAT one, but don\'t let that crowd out other distinct vulnerabilities ' +
      'in other routes. Respond with ONLY a JSON object, no prose, no markdown fences, shaped ' +
      'exactly like:\n' +
      '{"candidates": [{"file": "relative/path.js", "name": "short vulnerability name", ' +
      '"severity": "critical"|"high"|"medium"|"low", "description": "one sentence root cause", ' +
      '"request": {"method": "GET", "path": "/exact/path?with=query"}, ' +
      '"successHint": "one sentence describing what a successful exploit response would look like"}]}\n' +
      'If you genuinely see nothing exploitable, respond {"candidates": []}. Only propose ' +
      'requests with method GET, POST, PUT, PATCH, or DELETE against the given target base URL — ' +
      'no other hosts.',
    user: `Target base URL: ${targetUrl}\n\nCandidate source files:\n\n${filesBlock}`,
    maxTokens: 1400,
  });

  const candidates = Array.isArray(result?.candidates) ? result.candidates : [];
  return candidates
    .filter((c) => c && c.file && c.request?.path)
    .slice(0, maxCandidates)
    .map((c) => ({ ...c, targetDir, targetUrl }));
}

async function executeProposal(proposal) {
  const base = assertLocalhost(proposal.targetUrl);
  const url = new URL(proposal.request.path, base);
  const method = (proposal.request.method || 'GET').toUpperCase();
  const requestSummary = `${method} ${url.pathname}${url.search}`;

  let res, body;
  try {
    res = await fetch(url, { method, signal: AbortSignal.timeout(8000) });
    body = await res.text();
  } catch (err) {
    return { ...proposal, requestSummary, success: false, status: null, evidence: `Request failed: ${err.message}` };
  }

  const verdict = await llm.askJSON({
    system:
      'You are RED TEAM judging whether an exploit attempt actually succeeded. ' +
      'Respond ONLY as JSON: {"success": true|false, "evidence": "one sentence, concrete, ' +
      'quoting or describing the specific data/behavior that proves it (or disproves it)"}.',
    user:
      `Vulnerability hypothesis: ${proposal.name} — ${proposal.description}\n` +
      `Expected sign of success: ${proposal.successHint}\n` +
      `Request sent: ${requestSummary}\n` +
      `Response status: ${res.status}\n` +
      `Response body (truncated): ${body.slice(0, 1500)}`,
    maxTokens: 200,
  });

  const success = verdict?.success === true;
  const evidence = verdict?.evidence || (success ? 'Exploit appears to have succeeded.' : `No evidence of success (HTTP ${res.status}).`);
  return { ...proposal, requestSummary, success, status: res.status, evidence };
}

// Full recon -> propose -> try-every-candidate pass. Returns every
// DISTINCT vulnerability that actually landed (deduped by name+file, so a
// few depth-guesses for the same path-traversal don't count as separate
// findings), up to maxFindings — not just the first one, so a run can show
// real variety (e.g. SQL injection AND broken access control) instead of
// stopping the moment anything works. attempts includes every candidate
// tried, successful or not, so failed guesses stay visible.
async function reconAndExploitAll({ targetDir, targetUrl, maxFindings = 3 }) {
  assertLocalhost(targetUrl); // fail fast, before any file reads or LLM calls
  const candidates = await proposeExploits({ targetDir, targetUrl });
  const attempts = [];
  const findings = [];
  const seen = new Set();
  for (const candidate of candidates) {
    const key = `${candidate.file}::${candidate.name}`;
    if (seen.has(key)) continue; // already have a working example of this one
    const result = await executeProposal(candidate);
    attempts.push(result);
    if (result.success) {
      findings.push(result);
      seen.add(key);
      if (findings.length >= maxFindings) break;
    }
  }
  return { findings, attempts };
}

// Re-run the exact same request that worked before, to validate a patch.
async function retest(finding) {
  return executeProposal(finding);
}

module.exports = { reconAndExploitAll, retest, assertLocalhost, shortlistFiles };
