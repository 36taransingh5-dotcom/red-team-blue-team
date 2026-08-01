'use strict';
// Tiny pub/sub that fans out timeline events to all connected SSE clients
// and keeps a replayable log so late-joining clients see history.
const clients = new Set();
const log = [];
let seq = 0;

function subscribe(res) {
  clients.add(res);
  // Replay history so a client that connects mid-battle is caught up.
  for (const evt of log) {
    res.write(`data: ${JSON.stringify(evt)}\n\n`);
  }
  return () => clients.delete(res);
}

function emit(event) {
  const enriched = { seq: seq++, at: Date.now(), ...event };
  log.push(enriched);
  const payload = `data: ${JSON.stringify(enriched)}\n\n`;
  for (const res of clients) {
    try { res.write(payload); } catch { /* client gone */ }
  }
  return enriched;
}

function reset() {
  log.length = 0;
  seq = 0;
}

module.exports = { subscribe, emit, reset, getLog: () => log.slice() };
