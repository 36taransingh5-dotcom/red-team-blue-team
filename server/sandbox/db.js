'use strict';
// In-memory SQLite for the deliberately vulnerable "Banking API Demo".
// Uses Node's built-in node:sqlite (no native compile needed).
const { DatabaseSync } = require('node:sqlite');

const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT,
    balance INTEGER,
    ssn TEXT
  );
`);

const seed = db.prepare(
  'INSERT INTO users (id, username, password, role, balance, ssn) VALUES (?,?,?,?,?,?)'
);
seed.run(1, 'admin', 'S3cur3-Vault-2026', 'admin', 9847500, '412-55-9930');
seed.run(2, 'j.morgan', 'hunter2', 'customer', 4200, '556-21-7781');
seed.run(3, 'a.chen', 'letmein!', 'customer', 88150, '901-44-2210');

module.exports = { db };
