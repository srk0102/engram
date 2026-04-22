-- Engram v0.2.0 core schema. Idempotent.
-- Unopinionated: no fixed decision enum, no hardcoded fingerprint fields.
-- The developer controls what "a decision" looks like and when two
-- situations are "the same."
-- ============================================================

create schema if not exists engram;

create table if not exists engram.migrations (
  name       text primary key,
  sha256     text not null,
  applied_at timestamptz not null default now()
);

-- --------------------------------------------------------------
-- user_events -- universal signal stream. Feed ANY event type
-- with ANY metadata. Retrieval + baseline + anomaly read from here.
-- --------------------------------------------------------------
create table if not exists engram.user_events (
  id          bigserial primary key,
  user_id     text    not null,
  event_type  text    not null,
  metadata    jsonb   not null default '{}',
  session_id  text,
  ip_region   text,
  ua_class    text,
  created_at  bigint  not null default extract(epoch from now())::bigint * 1000
);
create index if not exists engram_ue_user_created
  on engram.user_events(user_id, created_at desc);
create index if not exists engram_ue_user_type
  on engram.user_events(user_id, event_type);
create index if not exists engram_ue_type_created
  on engram.user_events(event_type, created_at desc);

-- --------------------------------------------------------------
-- cache -- dev-supplied cache_key -> brain-produced decision.
-- decision is jsonb: whatever shape the developer's Zod/Valibot/
-- Yup schema returned. No enum, no CHECK constraint.
-- --------------------------------------------------------------
create table if not exists engram.cache (
  id              text primary key,
  namespace       text  not null default 'default',
  cache_key       text  not null,
  decision        jsonb not null,
  confidence      float not null default 0.5
                    check (confidence >= 0 and confidence <= 1),
  hit_count       integer not null default 0,
  success_count   integer not null default 0,
  failure_count   integer not null default 0,
  meta            jsonb   not null default '{}',
  created_at      bigint  not null default extract(epoch from now())::bigint * 1000,
  updated_at      bigint  not null default extract(epoch from now())::bigint * 1000,
  expires_at      bigint
);
create unique index if not exists engram_cache_ns_key
  on engram.cache(namespace, cache_key);
create index if not exists engram_cache_ns_created
  on engram.cache(namespace, created_at desc);

-- --------------------------------------------------------------
-- audit -- state-change log: learn / feedback / eviction.
-- --------------------------------------------------------------
create table if not exists engram.audit (
  id          bigserial primary key,
  cache_id    text,
  namespace   text not null,
  cache_key   text,
  source      text not null,
  decision    jsonb,
  created_at  bigint not null default extract(epoch from now())::bigint * 1000
);
create index if not exists engram_audit_ns on engram.audit(namespace, created_at desc);

alter table engram.user_events enable row level security;
alter table engram.cache       enable row level security;
alter table engram.audit       enable row level security;
