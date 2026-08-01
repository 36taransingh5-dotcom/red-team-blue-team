'use strict';
// A small, deliberately vulnerable "Notes API" — ships as a ready-made
// second target to try the generic (arbitrary-codebase) Red/Blue flow
// against, distinct from the built-in Banking Demo: a different domain,
// with three DIFFERENT vulnerability classes (SQL injection, broken
// access control, and path traversal) so a run against it can show real
// variety, not just a renamed clone of the built-in demo's two bugs.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const app = express();
app.use(express.json());

const ATTACH_DIR = path.join(__dirname, 'attachments');

const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT, owner TEXT)');
const seed = db.prepare('INSERT INTO notes (id, title, body, owner) VALUES (?, ?, ?, ?)');
seed.run(1, 'Q4 board notes', 'Layoffs planned for January, keep confidential.', 'ceo');
seed.run(2, 'Grocery list', 'Eggs, milk, bread.', 'alice');

// VULNERABILITY 1: SQL injection — the search term is concatenated
// directly into the query instead of being parameterized.
app.get('/notes/search', (req, res) => {
  const q = req.query.q || '';
  const sql = `SELECT id, title, body, owner FROM notes WHERE title LIKE '%${q}%'`;
  try {
    const rows = db.prepare(sql).all();
    res.json(rows);
  } catch (err) {
    res.status(400).json({ error: 'bad query' });
  }
});

// VULNERABILITY 2: Broken access control — returns any note by id with no
// ownership check or authentication at all.
app.get('/notes/:id', (req, res) => {
  const note = db.prepare('SELECT id, title, body, owner FROM notes WHERE id = ?').get(Number(req.params.id));
  if (!note) return res.status(404).json({ error: 'not found' });
  res.json(note);
});

// VULNERABILITY 3: Path traversal — reads whatever file the caller asks
// for, unsanitized, letting them escape the intended attachments folder.
app.get('/notes/:id/attachment', (req, res) => {
  const file = req.query.file || '';
  const fullPath = path.join(ATTACH_DIR, file);
  try {
    const contents = fs.readFileSync(fullPath, 'utf8');
    res.type('text/plain').send(contents);
  } catch (err) {
    res.status(404).json({ error: 'attachment not found' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, service: 'mini-notes-api' }));

const PORT = process.env.PORT || 4500;
app.listen(PORT, () => console.log(`mini-notes-api listening on :${PORT}`));
