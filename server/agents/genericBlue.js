'use strict';
// BLUE TEAM, generic-target mode — patches a real file in a real,
// arbitrary codebase based on whatever Red found. There's no hand-written
// secure template to fall back to here (unlike the Banking Demo), so the
// safety net is: back up before ever writing, validate the generated code
// at least parses (`node --check`) before trusting it, and if the retest
// afterward shows the exploit still works, revert to the backup rather
// than leaving a broken or ineffective edit in the user's real code.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const llm = require('./llm');

// Refuse to touch anything outside the target directory — a defensive
// check against a path like "../../../../etc/passwd" ever reaching a write.
function resolveInside(targetDir, relFile) {
  const root = path.resolve(targetDir);
  const full = path.resolve(root, relFile);
  if (full !== root && !full.startsWith(root + path.sep)) {
    throw new Error(`refusing to write outside the target directory: ${relFile}`);
  }
  return full;
}

function backupFile(targetDir, relFile, content) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = path.join(targetDir, '.redteam-backups', stamp, relFile);
  fs.mkdirSync(path.dirname(backupPath), { recursive: true });
  fs.writeFileSync(backupPath, content);
  return backupPath;
}

// The only validation that's generically possible for arbitrary code we've
// never seen before: does it at least parse? This is much weaker than the
// Banking Demo's semantic checks (which know exactly what "correct" means
// for those two specific vulnerabilities) — real correctness is only
// proven by the re-attack that follows.
function syntaxCheck(code) {
  const tmpFile = path.join(os.tmpdir(), `rtbt-generic-${crypto.randomBytes(6).toString('hex')}.js`);
  try {
    fs.writeFileSync(tmpFile, code);
    execFileSync(process.execPath, ['--check', tmpFile], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  } finally {
    try { fs.unlinkSync(tmpFile); } catch { /* already gone */ }
  }
}

async function patchFinding({ targetDir, file, name, description, requestSummary }) {
  const fullPath = resolveInside(targetDir, file);
  const before = fs.readFileSync(fullPath, 'utf8');
  const backupPath = backupFile(targetDir, file, before);

  const after = await llm.generateGenericPatch({ before, name, description, requestUsed: requestSummary });
  if (!after) return { applied: false, before, after: null, backupPath, file, reason: 'no LLM patch generated (is OPENAI_API_KEY set?)' };
  if (!syntaxCheck(after)) return { applied: false, before, after, backupPath, file, reason: 'generated patch failed a basic syntax check' };

  fs.writeFileSync(fullPath, after);
  return { applied: true, before, after, backupPath, file };
}

function revert(targetDir, file, backupPath) {
  const fullPath = resolveInside(targetDir, file);
  fs.writeFileSync(fullPath, fs.readFileSync(backupPath, 'utf8'));
}

module.exports = { patchFinding, revert, backupFile, syntaxCheck, resolveInside };
