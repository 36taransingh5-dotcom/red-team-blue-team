'use strict';
// ACCOUNT ACCESS POLICY  —  HARDENED VERSION
// Requires a valid session and enforces ownership: a caller may only
// read their own account (admins may read any).
module.exports = function accountAccess({ callerId, callerRole, targetId }) {
  if (!callerId) {
    return { allow: false, status: 401, reason: 'authentication required' };
  }
  if (callerRole === 'admin' || callerId === targetId) {
    return { allow: true };
  }
  return { allow: false, status: 403, reason: 'you may only access your own account' };
};
