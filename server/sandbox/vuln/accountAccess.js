'use strict';
// ACCOUNT ACCESS POLICY  —  SECURE VERSION
module.exports = function accountAccess({ callerId, callerRole, targetId }) {
  if (callerId == null) {
    return { allow: false };
  }
  if (callerRole === 'admin' || callerId === targetId) {
    return { allow: true };
  }
  return { allow: false };
};