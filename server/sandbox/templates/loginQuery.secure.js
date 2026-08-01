'use strict';
// LOGIN QUERY BUILDER  —  HARDENED VERSION
// Uses a parameterized query so user input can never alter SQL structure.
module.exports = function buildLoginQuery(username, password) {
  const sql =
    'SELECT id, username, role, balance FROM users ' +
    'WHERE username = ? AND password = ?';
  return { sql, params: [username, password], mode: 'param' };
};
