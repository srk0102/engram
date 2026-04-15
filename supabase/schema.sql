create schema if not exists engram;

create table if not exists engram.patterns (
  id            text primary key,
  namespace     text not null default 'default',
  fingerprint   jsonb not null,
  context_shape jsonb,
  decision      text not null
                  check (decision in
                    ('allow','block','flag')),
  reason        jsonb,
  confidence    float default 0.5
                  check (confidence >= 0
                    and confidence <= 1),
  hit_count     integer default 0,
  success_count integer default 0,
  failure_count integer default 0,
  meta          jsonb default '{}',
  created_at    bigint not null default
                  extract(epoch from now())::bigint
                  * 1000,
  updated_at    bigint not null default
                  extract(epoch from now())::bigint
                  * 1000,
  expires_at    bigint
);

create index if not exists engram_ns
  on engram.patterns(namespace);

create index if not exists engram_ns_created
  on engram.patterns(namespace, created_at);

create index if not exists engram_decision
  on engram.patterns(namespace, decision);

create table if not exists engram.audit (
  id          bigserial primary key,
  pattern_id  text,
  namespace   text not null,
  decision    text not null,
  source      text not null,
  fingerprint jsonb,
  created_at  bigint not null default
                extract(epoch from now())::bigint
                * 1000
);

create index if not exists engram_audit_ns
  on engram.audit(namespace, created_at);

create table if not exists engram.quarantine (
  id                text primary key,
  namespace         text not null,
  fingerprint       jsonb not null,
  decision          text not null,
  confidence        float default 0.5,
  reason            jsonb,
  observation_count integer default 1,
  negative_feedback integer default 0,
  first_seen        bigint not null default
                      extract(epoch from now())::bigint
                      * 1000,
  last_seen         bigint not null default
                      extract(epoch from now())::bigint
                      * 1000
);

alter table engram.patterns
  enable row level security;
alter table engram.audit
  enable row level security;
alter table engram.quarantine
  enable row level security;
