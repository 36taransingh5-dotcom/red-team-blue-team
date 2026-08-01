-- Red Team // Blue Team — persistence layer.
-- Run this once in the Supabase SQL editor for your project
-- (Project → SQL Editor → New query → paste → Run).

create table if not exists runs (
  id uuid primary key default gen_random_uuid(),
  started_at timestamptz not null default now(),
  ended_at timestamptz,
  initial_score int not null default 40,
  final_score int,
  patched jsonb,
  llm_model text
);

create table if not exists run_events (
  id bigint generated always as identity primary key,
  run_id uuid not null references runs(id) on delete cascade,
  seq int not null,
  type text not null,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists run_events_run_id_idx on run_events (run_id);

-- RLS is ON with no policies defined, so anon/authenticated roles are
-- default-denied on both tables. The server only ever writes with the
-- service_role key (never exposed to the browser), which always bypasses
-- RLS regardless — so this costs nothing functionally and just means
-- these tables stay locked down if the anon key is ever used directly.
alter table runs enable row level security;
alter table run_events enable row level security;
