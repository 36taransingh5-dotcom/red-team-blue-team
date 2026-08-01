'use strict';
// The deliberately vulnerable "Banking API Demo" that Red attacks and
// Blue defends. Runs on :4000. The security-critical logic lives in
// swappable modules under ./vuln that are re-required on every request,
// so Blue's patches take effect live with no restart.
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { db } = require('./db');

const VULN_DIR = path.join(__dirname, 'vuln');

// Re-require a security module fresh each call so live patches apply.
function loadModule(file) {
  const full = path.join(VULN_DIR, file);
  delete require.cache[require.resolve(full)];
  return require(full);
}

// Naive in-memory session store.
const sessions = new Map(); // token -> { userId, role }

function createSandbox() {
  const app = express();
  app.use(express.json());

  // --- Auth: vulnerable to SQL injection (loginQuery.js) ---
  // Wrapped in try/catch as defense-in-depth: Blue's validator vets every
  // patch before it's written, but a hot-swapped module is still live code
  // and must never be allowed to crash the request path.
  app.post('/api/login', (req, res) => {
    try {
      const { username = '', password = '' } = req.body || {};
      const buildLoginQuery = loadModule('loginQuery.js');
      const { sql, params, mode } = buildLoginQuery(username, password);
      const stmt = db.prepare(sql);
      const row = mode === 'param' ? stmt.get(...params) : stmt.get();
      if (!row) return res.status(401).json({ ok: false, error: 'invalid credentials' });
      const token = crypto.randomBytes(12).toString('hex');
      sessions.set(token, { userId: row.id, role: row.role });
      return res.json({ ok: true, token, user: row });
    } catch (err) {
      return res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // --- Account read: vulnerable to IDOR / broken access control ---
  app.get('/api/accounts/:id', (req, res) => {
    try {
      const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const session = sessions.get(token);
      const targetId = Number(req.params.id);
      const accountAccess = loadModule('accountAccess.js');
      const decision = accountAccess({
        callerId: session ? session.userId : null,
        callerRole: session ? session.role : null,
        targetId,
      });
      if (!decision.allow) {
        return res.status(decision.status || 403).json({ ok: false, error: decision.reason });
      }
      const acct = db
        .prepare('SELECT id, username, role, balance, ssn FROM users WHERE id = ?')
        .get(targetId);
      if (!acct) return res.status(404).json({ ok: false, error: 'no such account' });
      return res.json({ ok: true, account: acct });
    } catch (err) {
      return res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'banking-api-demo' }));

  return app;
}

module.exports = { createSandbox, VULN_DIR };
