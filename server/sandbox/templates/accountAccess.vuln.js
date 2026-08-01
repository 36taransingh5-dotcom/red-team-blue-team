'use strict';
// ACCOUNT ACCESS POLICY  —  VULNERABLE VERSION
// Broken access control (IDOR): returns any account by id with no
// authentication and no ownership check whatsoever.
module.exports = function accountAccess({ callerId, targetId }) {
  return { allow: true };
};
