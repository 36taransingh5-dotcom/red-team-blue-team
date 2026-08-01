'use strict';
// Boots two Express apps in one process:
//   :4000  the deliberately vulnerable "Banking API Demo" sandbox
//   :3001  the mission-control API (SSE timeline + simulation control)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createSandbox } = require('./sandbox/app');
const bus = require('./eventBus');
const orchestrator = require('./orchestrator');
const llm = require('./agents/llm');
const supa = require('./supabase');

const SANDBOX_PORT = 4000;
const CONTROL_PORT = 3001;

// --- Vulnerable sandbox ---
createSandbox().listen(SANDBOX_PORT, () => {
  console.log(`[sandbox] Banking API Demo listening on :${SANDBOX_PORT}`);
});

// --- Mission control API ---
const control = express();
control.use(cors());
control.use(express.json());

// SSE timeline stream.
control.get('/api/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.write(': connected\n\n');
  const unsub = bus.subscribe(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(ping); unsub(); });
});

control.post('/api/simulate/start', async (_req, res) => {
  if (orchestrator.isRunning()) {
    return res.status(409).json({ ok: false, error: 'simulation already running' });
  }
  // Fire and forget — progress streams over SSE.
  orchestrator.runSimulation().catch((err) => {
    console.error('[orchestrator] run failed:', err);
    bus.emit({ type: 'log', agent: 'system', text: `Run error: ${err.message}`, tone: 'warn' });
  });
  res.json({ ok: true, started: true });
});

control.get('/api/status', (_req, res) => {
  res.json({ ok: true, running: orchestrator.isRunning(), llm: llm.enabled, model: llm.model, persisted: supa.enabled });
});

control.get('/api/history', async (_req, res) => {
  const runs = await supa.history(10);
  res.json({ ok: true, persisted: supa.enabled, runs });
});

control.listen(CONTROL_PORT, () => {
  console.log(`[control] Mission control API on :${CONTROL_PORT}`);
  console.log(`[control] LLM agents: ${llm.enabled ? `ENABLED (${llm.model})` : 'fallback mode (no OPENAI_API_KEY)'}`);
  console.log(`[control] Supabase persistence: ${supa.enabled ? 'ENABLED' : 'disabled (no SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)'}`);
});
