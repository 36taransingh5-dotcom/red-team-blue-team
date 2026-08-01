'use strict';
// LOGIN QUERY BUILDER  —  VULNERABLE VERSION
// Builds the authentication SQL by concatenating raw user input.
// This allows classic SQL injection auth bypass, e.g.
//   username: ' OR 1=1 --
module.exports = function buildLoginQuery(username, password) {
  const sql =
    "SELECT id, username, role, balance FROM users " +
    "WHERE username = '" + username + "' AND password = '" + password + "'";
  return { sql, params: [], mode: 'raw' };
};
