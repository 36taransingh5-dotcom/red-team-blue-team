'use strict';
// LOGIN QUERY BUILDER  —  SECURE VERSION
module.exports = function buildLoginQuery(username, password) {
  const sql =
    "SELECT id, username, role, balance FROM users " +
    "WHERE username = ? AND password = ?";
  const params = [username, password];
  return { sql, params, mode: 'param' };
};