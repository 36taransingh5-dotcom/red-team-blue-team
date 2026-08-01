'use strict';
// Persistence layer for run history and the event timeline. Mirrors
// agents/llm.js's pattern: if SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY
// aren't set (or Supabase is unreachable), every function becomes a no-op
// so the live demo never depends on this to work.
const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

let client = null;
if (url && key) {
  try {
    const { createClient } = require('@supabase/supabase-js');
    client = createClient(url, key, { auth: { persistSession: false } });
  } catch (err) {
    console.warn('[supabase] client unavailable, persistence disabled:', err.message);
  }
}

async function startRun({ model, initialScore }) {
  if (!client) return null;
  const { data, error } = await client
    .from('runs')
    .insert({ llm_model: model, initial_score: initialScore })
    .select('id')
    .single();
  if (error) { console.warn('[supabase] startRun failed:', error.message); return null; }
  return data.id;
}

async function logEvent(runId, event) {
  if (!client || !runId) return;
  const { error } = await client
    .from('run_events')
    .insert({ run_id: runId, seq: event.seq, type: event.type, payload: event });
  if (error) console.warn('[supabase] logEvent failed:', error.message);
}

async function endRun(runId, { finalScore, patched }) {
  if (!client || !runId) return;
  const { error } = await client
    .from('runs')
    .update({ ended_at: new Date().toISOString(), final_score: finalScore, patched })
    .eq('id', runId);
  if (error) console.warn('[supabase] endRun failed:', error.message);
}

async function history(limit = 10) {
  if (!client) return [];
  const { data, error } = await client
    .from('runs')
    .select('id, started_at, ended_at, initial_score, final_score, patched, llm_model')
    .order('started_at', { ascending: false })
    .limit(limit);
  if (error) { console.warn('[supabase] history failed:', error.message); return []; }
  return data;
}

module.exports = { enabled: !!client, startRun, logEvent, endRun, history };
