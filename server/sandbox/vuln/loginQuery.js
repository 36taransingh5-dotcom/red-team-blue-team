'use strict';
// LOGIN QUERY BUILDER  —  SECURE VERSION
module.exports = function buildLoginQuery(username, password) {
  const sql =
    "SELECT id, username, role, balance FROM users " +
    "WHERE username = ? AND password = ?";
  return { sql, params: [username, password], mode: 'param' };
};