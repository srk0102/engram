-- ============================================================
-- Register Engram as a pg_tle extension.
--
-- Run this ONCE per Supabase project. After this, anyone on
-- the project can do: CREATE EXTENSION engram;
--
-- Prerequisites:
--   CREATE EXTENSION pg_tle;   (one time)
--   CREATE EXTENSION pg_cron;  (usually already enabled)
--
-- To update later:
--   Run tle-register.sql again with the new version.
--   Then: ALTER EXTENSION engram UPDATE TO '1.0.2';
-- ============================================================

create extension if not exists pg_tle;

-- Uninstall previous version if exists (idempotent re-registration).
select pgtle.uninstall_extension_if_exists('engram');

select pgtle.install_extension(
  'engram',
  '1.0.2',
  'Your API learns to defend itself. Behavior gate for Supabase APIs.',
$_pg_tle_$

-- Schema
create schema if not exists engram;

-- 1. Patterns
create table if not exists engram.patterns (
  id              text primary key,
  namespace       text not null default 'default',
  fingerprint     jsonb not null,
  context_shape   jsonb,
  decision        text not null
                    check (decision in ('allow','block','flag','fraud','bot','churn_risk')),
  reason          jsonb,
  confidence      float default 0.5
                    check (confidence >= 0 and confidence <= 1),
  hit_count       integer default 0,
  success_count   integer default 0,
  failure_count   integer default 0,
  meta            jsonb default '{}',
  created_at      bigint not null default extract(epoch from now())::bigint * 1000,
  updated_at      bigint not null default extract(epoch from now())::bigint * 1000,
  expires_at      bigint
);
create index if not exists engram_patterns_ns         on engram.patterns(namespace);
create index if not exists engram_patterns_ns_dec     on engram.patterns(namespace, decision);
create index if not exists engram_patterns_ns_created on engram.patterns(namespace, created_at);

-- 2. Audit
create table if not exists engram.audit (
  id          bigserial primary key,
  pattern_id  text,
  namespace   text not null,
  decision    text not null,
  source      text not null,
  fingerprint jsonb,
  created_at  bigint not null default extract(epoch from now())::bigint * 1000
);
create index if not exists engram_audit_ns on engram.audit(namespace, created_at);

-- 3. Rollups
create table if not exists engram.rollups (
  namespace      text    not null,
  pattern_id     text    not null,
  window_start   bigint  not null,
  hit_count      integer not null default 0,
  latency_sum_us bigint  not null default 0,
  latency_max_us integer not null default 0,
  decisions      jsonb   not null default '{}',
  primary key (namespace, pattern_id, window_start)
);
create index if not exists engram_rollups_ns on engram.rollups(namespace, window_start);

-- 4. Route visits
create table if not exists engram.route_visits (
  id          bigserial primary key,
  user_id     uuid,
  endpoint    text    not null,
  ip          text,
  ua          text,
  decision    text    not null default 'allow',
  entered_at  timestamptz not null default now(),
  finished_at timestamptz,
  status_code int
);
create index if not exists engram_rv_user on engram.route_visits(user_id, entered_at desc);
create index if not exists engram_rv_ep   on engram.route_visits(endpoint, entered_at desc);
create index if not exists engram_rv_ts   on engram.route_visits(entered_at desc);

-- 5. Churn queue
create table if not exists engram.churn_queue (
  user_id          uuid primary key,
  first_flagged_at timestamptz not null default now(),
  last_flagged_at  timestamptz not null default now(),
  flag_count       int not null default 1,
  current_signals  jsonb not null default '{}',
  resolved_at      timestamptz,
  resolved_by      text
);
create index if not exists engram_churn_active
  on engram.churn_queue(last_flagged_at desc) where resolved_at is null;

-- RLS + Grants
alter table engram.patterns       enable row level security;
alter table engram.audit          enable row level security;
alter table engram.rollups        enable row level security;
alter table engram.route_visits   enable row level security;
alter table engram.churn_queue    enable row level security;

revoke all on schema engram from public;
grant usage on schema engram to authenticated, service_role;

revoke all on all tables in schema engram from public, anon, authenticated;
grant select                 on engram.patterns        to service_role;
grant select                 on engram.audit           to service_role;
grant select                 on engram.rollups         to service_role;
grant select, insert, update on engram.route_visits    to service_role;
grant select, insert, update on engram.churn_queue     to service_role;

grant usage, select on sequence engram.route_visits_id_seq to service_role;
grant usage, select on sequence engram.audit_id_seq        to service_role;

-- hash_fingerprint
create or replace function engram.hash_fingerprint(fp jsonb, ns text default 'default')
returns text language plpgsql as $fn$
begin
  return md5(
    ns || ':' ||
    coalesce(fp->>'authenticated','')       || ':' ||
    coalesce(fp->>'ua_class','')            || ':' ||
    coalesce(fp->>'last_payment_status','') || ':' ||
    coalesce(case
      when (fp->>'account_age_days')::int is null then 'n'
      when (fp->>'account_age_days')::int < 1     then 'age_0'
      when (fp->>'account_age_days')::int < 3     then 'age_1_3'
      when (fp->>'account_age_days')::int < 7     then 'age_3_7'
      when (fp->>'account_age_days')::int < 30    then 'age_7_30'
      else 'age_30_plus' end, 'n') || ':' ||
    coalesce(case
      when (fp->>'uploads_last_hour')::int is null then 'n'
      when (fp->>'uploads_last_hour')::int = 0     then 'u0'
      when (fp->>'uploads_last_hour')::int <= 2    then 'u1_2'
      when (fp->>'uploads_last_hour')::int <= 9    then 'u3_9'
      else 'u10_plus' end, 'n') || ':' ||
    coalesce(case
      when (fp->>'credits_remaining')::int is null then 'n'
      when (fp->>'credits_remaining')::int = 0     then 'c0'
      when (fp->>'credits_remaining')::int < 5     then 'c_low'
      when (fp->>'credits_remaining')::int < 20    then 'c_med'
      else 'c_high' end, 'n')
  );
end; $fn$;

-- lookup
create or replace function engram.lookup(
  fp jsonb, ns text default 'default', threshold float default 0.8
) returns table (
  pattern_id text, decision text, confidence float,
  reason jsonb, source text, hit_count integer
) language plpgsql as $fn$
declare pid text; rec engram.patterns%rowtype;
begin
  pid := engram.hash_fingerprint(fp, ns);
  select * into rec from engram.patterns
   where id = pid and namespace = ns
     and (expires_at is null or expires_at > extract(epoch from now())::bigint * 1000);
  if found and rec.confidence >= threshold then
    update engram.patterns p set
      hit_count = p.hit_count + 1,
      updated_at = extract(epoch from now())::bigint * 1000
     where p.id = pid and p.namespace = ns;
    return query select rec.id, rec.decision, rec.confidence, rec.reason,
      'pattern_store'::text, rec.hit_count + 1;
  end if;
end; $fn$;

-- learn
create or replace function engram.learn(
  fp jsonb, ns text, p_decision text, p_confidence float,
  p_reason jsonb, p_meta jsonb default '{}'
) returns text language plpgsql as $fn$
declare pid text;
begin
  pid := engram.hash_fingerprint(fp, ns);
  insert into engram.patterns (
    id, namespace, fingerprint, decision, confidence, reason, meta,
    hit_count, created_at, updated_at
  ) values (
    pid, ns, fp, p_decision, p_confidence, p_reason, p_meta, 1,
    extract(epoch from now())::bigint * 1000,
    extract(epoch from now())::bigint * 1000
  ) on conflict (id) do update set
    hit_count = engram.patterns.hit_count + 1,
    updated_at = extract(epoch from now())::bigint * 1000;
  insert into engram.audit (pattern_id, namespace, decision, source, fingerprint)
    values (pid, ns, p_decision, 'learned', fp);
  return pid;
end; $fn$;

-- classify
create or replace function engram.classify(fp jsonb)
returns jsonb language plpgsql as $fn$
declare
  age     int  := coalesce((fp->>'account_age_days')::int, 0);
  uph     int  := coalesce((fp->>'uploads_last_hour')::int, 0);
  u7d     int  := coalesce((fp->>'uploads_last_7d')::int, 0);
  credits int  := coalesce((fp->>'credits_remaining')::int, 0);
  la      int  := coalesce((fp->>'last_activity_days')::int, -1);
  ps      text := coalesce(fp->>'last_payment_status', 'none');
  ua      text := coalesce(fp->>'ua_class', 'browser');
  auth    bool := coalesce((fp->>'authenticated')::bool, false);
begin
  if age < 1 and uph >= 10 then
    return jsonb_build_object('decision','fraud','confidence',0.95,
      'reason',jsonb_build_object('source','classify','rule','fraud_new_burst',
        'explanation','new account + burst velocity',
        'signals',jsonb_build_object('account_age_days',age,'uploads_last_hour',uph)));
  end if;
  if age < 1 and ps = 'success' and uph >= 5 then
    return jsonb_build_object('decision','fraud','confidence',0.90,
      'reason',jsonb_build_object('source','classify','rule','fraud_new_paid_fast',
        'explanation','new paid account with rapid consumption',
        'signals',jsonb_build_object('account_age_days',age,'last_payment_status',ps,'uploads_last_hour',uph)));
  end if;
  if (ua = 'missing' or ua = 'suspicious') and uph >= 5 then
    return jsonb_build_object('decision','bot','confidence',0.92,
      'reason',jsonb_build_object('source','classify','rule','bot_ua_velocity',
        'explanation','non-browser UA with request velocity',
        'signals',jsonb_build_object('ua_class',ua,'uploads_last_hour',uph)));
  end if;
  if not auth and uph >= 3 then
    return jsonb_build_object('decision','bot','confidence',0.85,
      'reason',jsonb_build_object('source','classify','rule','bot_anon_velocity',
        'explanation','anonymous caller with velocity',
        'signals',jsonb_build_object('authenticated',auth,'uploads_last_hour',uph)));
  end if;
  if age >= 7 and credits > 0 and la >= 14 then
    return jsonb_build_object('decision','churn_risk','confidence',0.80,
      'reason',jsonb_build_object('source','classify','rule','churn_idle_with_credits',
        'explanation','paid user idle with unspent credits',
        'signals',jsonb_build_object('account_age_days',age,'credits_remaining',credits,'last_activity_days',la)));
  end if;
  if coalesce((fp->>'visited_generate_no_complete')::bool,false) and age >= 3 and u7d = 0 then
    return jsonb_build_object('decision','churn_risk','confidence',0.75,
      'reason',jsonb_build_object('source','classify','rule','churn_visited_no_complete',
        'explanation','visited generate but did not complete',
        'signals',jsonb_build_object('account_age_days',age,'uploads_last_7d',u7d)));
  end if;
  if age >= 1 and age < 3 and uph >= 4 then
    if uph >= 8 then
      return jsonb_build_object('decision','fraud','confidence',0.88,
        'reason',jsonb_build_object('source','classify','rule','young_account_bot_velocity',
          'explanation','young account high velocity escalated to fraud',
          'signals',jsonb_build_object('account_age_days',age,'uploads_last_hour',uph)));
    else
      return jsonb_build_object('decision','flag','confidence',0.75,
        'reason',jsonb_build_object('source','classify','rule','flag_young_velocity',
          'explanation','young account elevated velocity',
          'signals',jsonb_build_object('account_age_days',age,'uploads_last_hour',uph)));
    end if;
  end if;
  if uph >= 15 then
    return jsonb_build_object('decision','flag','confidence',0.82,
      'reason',jsonb_build_object('source','classify','rule','velocity_absolute',
        'explanation','high request velocity regardless of account age',
        'signals',jsonb_build_object('uploads_last_hour',uph,'account_age_days',age)));
  end if;
  return jsonb_build_object('decision','allow','confidence',0.85,
    'reason',jsonb_build_object('source','classify','rule','allow_default',
      'explanation','normal user behavior'));
end; $fn$;

-- decide
create or replace function engram.decide(fp jsonb, ns text default 'behavior')
returns jsonb language plpgsql security definer set search_path = engram, pg_temp as $fn$
declare l record; c jsonb; pid text;
begin
  select * into l from engram.lookup(fp, ns) limit 1;
  if found then
    return jsonb_build_object('decision',l.decision,'confidence',l.confidence,
      'reason',l.reason,'source','pattern_store','pattern_id',l.pattern_id,'hit_count',l.hit_count);
  end if;
  c := engram.classify(fp);
  pid := engram.learn(fp, ns, c->>'decision', (c->>'confidence')::float, c->'reason', '{}'::jsonb);
  return jsonb_build_object('decision',c->>'decision','confidence',(c->>'confidence')::float,
    'reason',c->'reason','source','classify','pattern_id',pid,'hit_count',1);
end; $fn$;

-- feedback
create or replace function engram.feedback(p_id text, ns text, was_correct boolean)
returns void language plpgsql as $fn$
begin
  if was_correct then
    update engram.patterns set success_count=success_count+1,
      confidence=least(confidence*1.1,1.0),updated_at=extract(epoch from now())::bigint*1000
     where id=p_id and namespace=ns;
  else
    update engram.patterns set failure_count=failure_count+1,
      confidence=greatest(confidence*0.7,0.0),updated_at=extract(epoch from now())::bigint*1000
     where id=p_id and namespace=ns;
    delete from engram.patterns where id=p_id and namespace=ns and confidence<0.2;
  end if;
end; $fn$;

-- record_behavior
create or replace function engram.record_behavior(
  p_user uuid, p_endpoint text, p_ip text, p_ua text, p_decision text default 'allow'
) returns bigint language plpgsql security definer set search_path = engram, pg_temp as $fn$
declare new_id bigint;
begin
  insert into engram.route_visits(user_id,endpoint,ip,ua,decision)
    values(p_user,p_endpoint,p_ip,p_ua,p_decision) returning id into new_id;
  return new_id;
end; $fn$;

-- finish_behavior
create or replace function engram.finish_behavior(p_id bigint, p_status int)
returns void language plpgsql security definer set search_path = engram, pg_temp as $fn$
begin update engram.route_visits set finished_at=now(),status_code=p_status where id=p_id; end; $fn$;

-- enqueue_churn
create or replace function engram.enqueue_churn(p_user uuid, p_signals jsonb)
returns void language plpgsql security definer set search_path = engram, pg_temp as $fn$
begin
  insert into engram.churn_queue(user_id,first_flagged_at,last_flagged_at,flag_count,current_signals)
    values(p_user,now(),now(),1,p_signals)
  on conflict(user_id) do update set last_flagged_at=excluded.last_flagged_at,
    flag_count=engram.churn_queue.flag_count+1,current_signals=excluded.current_signals,
    resolved_at=null,resolved_by=null;
end; $fn$;

-- stats
create or replace function engram.stats(ns text default 'default')
returns jsonb language plpgsql as $fn$
declare r jsonb;
begin
  select jsonb_build_object('total_patterns',count(*),'by_decision',
    (select coalesce(jsonb_object_agg(decision,n),'{}') from
      (select decision,count(*) as n from engram.patterns where namespace=ns group by decision)s),
    'avg_confidence',round(coalesce(avg(confidence),0)::numeric,3),
    'total_hits',coalesce(sum(hit_count),0))
  into r from engram.patterns where namespace=ns;
  return r;
end; $fn$;

-- prune_rollups
create or replace function engram.prune_rollups(older_than_ms bigint)
returns integer language plpgsql as $fn$
declare n integer;
begin
  delete from engram.rollups where window_start<extract(epoch from now())*1000-older_than_ms;
  get diagnostics n=row_count; return n;
end; $fn$;

-- list_patterns
create or replace function engram.list_patterns(p_ns text default null, p_limit int default 100)
returns jsonb language plpgsql security definer set search_path = engram, pg_temp as $fn$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id',p.id,'namespace',p.namespace,'decision',p.decision,
      'confidence',p.confidence,'hit_count',p.hit_count,
      'success_count',p.success_count,'failure_count',p.failure_count,
      'rule',p.reason->>'rule','explanation',p.reason->>'explanation',
      'signals',p.reason->'signals',
      'created_at',to_timestamp(p.created_at/1000)::text,
      'updated_at',to_timestamp(p.updated_at/1000)::text
    ) order by p.hit_count desc)
    from engram.patterns p where (p_ns is null or p.namespace=p_ns) limit p_limit
  ),'[]'::jsonb);
end; $fn$;

-- get_pattern
create or replace function engram.get_pattern(p_id text)
returns jsonb language plpgsql security definer set search_path = engram, pg_temp as $fn$
declare rec engram.patterns%rowtype;
begin
  select * into rec from engram.patterns where id=p_id;
  if not found then return null; end if;
  return jsonb_build_object(
    'id',rec.id,'namespace',rec.namespace,'fingerprint',rec.fingerprint,
    'decision',rec.decision,'reason',rec.reason,'confidence',rec.confidence,
    'hit_count',rec.hit_count,'success_count',rec.success_count,
    'failure_count',rec.failure_count,'meta',rec.meta,
    'created_at',to_timestamp(rec.created_at/1000)::text,
    'updated_at',to_timestamp(rec.updated_at/1000)::text,
    'expires_at',case when rec.expires_at is not null then to_timestamp(rec.expires_at/1000)::text else null end);
end; $fn$;

-- list_visits
create or replace function engram.list_visits(p_endpoint text default null, p_decision text default null, p_limit int default 50)
returns jsonb language plpgsql security definer set search_path = engram, pg_temp as $fn$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id',rv.id,'user_id',rv.user_id,'endpoint',rv.endpoint,
      'decision',rv.decision,'status_code',rv.status_code,'ip',rv.ip,'ua',rv.ua,
      'entered_at',rv.entered_at::text,'finished_at',rv.finished_at::text,
      'duration_s',case when rv.finished_at is not null
        then round(extract(epoch from(rv.finished_at-rv.entered_at))::numeric,3)else null end
    ) order by rv.entered_at desc)
    from engram.route_visits rv
    where (p_endpoint is null or rv.endpoint=p_endpoint)
      and (p_decision is null or rv.decision=p_decision) limit p_limit
  ),'[]'::jsonb);
end; $fn$;

-- list_audit
create or replace function engram.list_audit(p_ns text default null, p_limit int default 50)
returns jsonb language plpgsql security definer set search_path = engram, pg_temp as $fn$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id',a.id,'pattern_id',a.pattern_id,'namespace',a.namespace,
      'decision',a.decision,'source',a.source,'fingerprint',a.fingerprint,
      'created_at',to_timestamp(a.created_at/1000)::text
    ) order by a.created_at desc)
    from engram.audit a where (p_ns is null or a.namespace=p_ns) limit p_limit
  ),'[]'::jsonb);
end; $fn$;

-- list_churn_queue
create or replace function engram.list_churn_queue(p_resolved boolean default false)
returns jsonb language plpgsql security definer set search_path = engram, pg_temp as $fn$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'user_id',cq.user_id,'first_flagged_at',cq.first_flagged_at::text,
      'last_flagged_at',cq.last_flagged_at::text,'flag_count',cq.flag_count,
      'current_signals',cq.current_signals,
      'resolved_at',cq.resolved_at::text,'resolved_by',cq.resolved_by
    ) order by cq.last_flagged_at desc)
    from engram.churn_queue cq where (p_resolved=true or cq.resolved_at is null)
  ),'[]'::jsonb);
end; $fn$;

-- dashboard
create or replace function engram.dashboard()
returns jsonb language plpgsql security definer set search_path = engram, pg_temp as $fn$
declare pat_summary jsonb; visit_summary jsonb; churn_n int;
begin
  select jsonb_build_object(
    'total',count(*),'total_hits',coalesce(sum(hit_count),0),
    'by_decision',coalesce((select jsonb_object_agg(decision,n)from(select decision,count(*)as n from engram.patterns group by decision)s),'{}'),
    'avg_confidence',round(coalesce(avg(confidence),0)::numeric,3)
  ) into pat_summary from engram.patterns;
  select jsonb_build_object(
    'total',count(*),
    'by_decision',coalesce((select jsonb_object_agg(decision,n)from(select decision,count(*)as n from engram.route_visits group by decision)s),'{}'),
    'by_endpoint',coalesce((select jsonb_object_agg(endpoint,n)from(select endpoint,count(*)as n from engram.route_visits group by endpoint)s),'{}')
  ) into visit_summary from engram.route_visits;
  select count(*) into churn_n from engram.churn_queue where resolved_at is null;
  return jsonb_build_object('patterns',pat_summary,'route_visits',visit_summary,'churn_queue_unresolved',churn_n,'version','v1.0.2');
end; $fn$;

-- Grants
grant execute on function engram.hash_fingerprint(jsonb,text) to authenticated,service_role;
grant execute on function engram.lookup(jsonb,text,float) to authenticated,service_role;
grant execute on function engram.learn(jsonb,text,text,float,jsonb,jsonb) to authenticated,service_role;
grant execute on function engram.classify(jsonb) to authenticated,service_role;
grant execute on function engram.decide(jsonb,text) to authenticated,service_role;
grant execute on function engram.feedback(text,text,boolean) to authenticated,service_role;
grant execute on function engram.record_behavior(uuid,text,text,text,text) to authenticated,service_role;
grant execute on function engram.finish_behavior(bigint,int) to authenticated,service_role;
grant execute on function engram.enqueue_churn(uuid,jsonb) to authenticated,service_role;
grant execute on function engram.stats(text) to authenticated,service_role;
grant execute on function engram.prune_rollups(bigint) to authenticated,service_role;
grant execute on function engram.list_patterns(text,int) to authenticated,service_role;
grant execute on function engram.get_pattern(text) to authenticated,service_role;
grant execute on function engram.list_visits(text,text,int) to authenticated,service_role;
grant execute on function engram.list_audit(text,int) to authenticated,service_role;
grant execute on function engram.list_churn_queue(boolean) to authenticated,service_role;
grant execute on function engram.dashboard() to authenticated,service_role;

-- pg_cron retention
do $cr$ begin perform cron.unschedule('engram_route_visits_retention');
  exception when others then null; end $cr$;
select cron.schedule('engram_route_visits_retention','17 * * * *',
  'delete from engram.route_visits where entered_at < now() - interval ''7 days''');

$_pg_tle_$
);
