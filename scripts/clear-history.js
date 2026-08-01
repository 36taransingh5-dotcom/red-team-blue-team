#!/usr/bin/env node
'use strict';
// Wipes all persisted Battle History from Supabase (runs + run_events),
// so the dashboard's history panel starts empty. Handy right before a
// demo, or between takes. No-op with a clear message if Supabase isn't
// configured. Run: npm run clear-history
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!url || !key) {
  console.log('Supabase not configured (no SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY) — nothing to clear. History is in-memory only.');
  process.exit(0);
}

(async () => {
  const { createClient } = require('@supabase/supabase-js');
  const db = createClient(url, key, { auth: { persistSession: false } });

  // Delete children first, then parents. (runs has ON DELETE CASCADE for
  // run_events, so deleting runs alone would suffice, but being explicit
  // keeps this correct even if the schema changes.)
  const ev = await db.from('run_events').delete().not('id', 'is', null);
  if (ev.error) { console.error('Failed to clear run_events:', ev.error.message); process.exit(1); }

  const runs = await db.from('runs').delete().not('id', 'is', null);
  if (runs.error) { console.error('Failed to clear runs:', runs.error.message); process.exit(1); }

  // Confirm it's empty.
  const { count } = await db.from('runs').select('*', { count: 'exact', head: true });
  console.log(`Battle History cleared. runs table now has ${count ?? 0} row(s).`);
  process.exit(0);
})().catch((err) => { console.error('clear-history failed:', err.message); process.exit(1); });
