-- Engram v0.2.0 functions.
-- Unopinionated primitives:
--   record_event   -- insert a signal
--   retrieve       -- pull recent events + optional per-type summary
--   cache_lookup   -- dev-supplied cache_key -> cached decision (or null)
--   cache_store    -- upsert a dev-supplied decision into cache
--   feedback       -- confidence decay / eviction
--   user_baseline  -- (utility) 30-day per-event-type stats
--   detect_anomaly -- (utility) score current signals against baseline
-- No classify(). No hash_fingerprint(). No hardcoded decision enum.
-- ============================================================

-- --------------------------------------------------------------
-- record_event
-- --------------------------------------------------------------
create or replace function engram.record_event(
  p_user_id    text,
  p_event_type text,
  p_metadata   jsonb default '{}',
  p_session_id text  default null,
  p_ip_region  text  default null,
  p_ua_class   text  default null
) returns void
language plpgsql
as $$
begin
  insert into engram.user_events
    (user_id, event_type, metadata, session_id, ip_region, ua_class)
  values
    (p_user_id, p_event_type, coalesce(p_metadata, '{}'::jsonb),
     p_session_id, p_ip_region, p_ua_class);
end; $$;

-- --------------------------------------------------------------
-- retrieve -- events + per-type summary (when p_aggregate=true)
--
-- Returns:
--   {
--     user_id:   text,
--     window_ms: bigint,
--     events:    [ { id, user_id, event_type, metadata, ..., created_at } ],
--     summary:   { <event_type>: { count, days_seen, avg_per_day,
--                                  first_seen, last_seen,
--                                  sample_metadata } }   -- only if p_aggregate
--   }
-- --------------------------------------------------------------
create or replace function engram.retrieve(
  p_user_id     text,
  p_event_types text[] default null,
  p_lookback_ms bigint default 2592000000,  -- 30 days
  p_limit       int    default 200,
  p_aggregate   bool   default true
) returns jsonb
language plpgsql
as $$
declare
  now_ms   bigint := extract(epoch from now())::bigint * 1000;
  since_ms bigint := now_ms - coalesce(p_lookback_ms, 2592000000::bigint);
  events_arr jsonb;
  summary    jsonb;
begin
  select coalesce(jsonb_agg(row_json order by created_at desc), '[]'::jsonb)
    into events_arr
  from (
    select
      jsonb_build_object(
        'id',         id,
        'user_id',    user_id,
        'event_type', event_type,
        'metadata',   metadata,
        'session_id', session_id,
        'ip_region',  ip_region,
        'ua_class',   ua_class,
        'created_at', created_at
      ) as row_json,
      created_at
    from engram.user_events
    where user_id = p_user_id
      and created_at >= since_ms
      and (p_event_types is null or event_type = any(p_event_types))
    order by created_at desc
    limit greatest(p_limit, 0)
  ) s;

  if p_aggregate then
    select jsonb_object_agg(event_type, stats)
      into summary
    from (
      select
        event_type,
        jsonb_build_object(
          'count',        count(*),
          'days_seen',    count(distinct (created_at / 86400000)),
          'avg_per_day',  round(
                            (count(*)::numeric /
                             greatest(count(distinct (created_at / 86400000)), 1)
                            )::numeric, 3),
          'first_seen',   min(created_at),
          'last_seen',    max(created_at),
          'sample_metadata', (
            select metadata
              from engram.user_events ue2
             where ue2.user_id    = p_user_id
               and ue2.event_type = ue.event_type
               and ue2.created_at >= since_ms
             order by ue2.created_at desc
             limit 1
          )
        ) as stats
      from engram.user_events ue
      where user_id = p_user_id
        and created_at >= since_ms
        and (p_event_types is null or event_type = any(p_event_types))
      group by event_type
    ) s;
  end if;

  return jsonb_build_object(
    'user_id',   p_user_id,
    'window_ms', coalesce(p_lookback_ms, 2592000000::bigint),
    'events',    events_arr,
    'summary',   coalesce(summary, '{}'::jsonb)
  );
end; $$;

-- --------------------------------------------------------------
-- cache_lookup -- returns the cached decision if present AND
-- confidence meets the threshold. Bumps hit_count on hit.
--
-- Returns jsonb:
--   { hit: true,  id, cache_key, decision, confidence, hit_count, meta }
--   { hit: false }
-- --------------------------------------------------------------
create or replace function engram.cache_lookup(
  p_cache_key text,
  p_namespace text    default 'default',
  p_threshold float   default 0.5
) returns jsonb
language plpgsql
as $$
declare
  rec engram.cache%rowtype;
  now_ms bigint := extract(epoch from now())::bigint * 1000;
begin
  select * into rec
    from engram.cache
   where namespace = p_namespace
     and cache_key = p_cache_key
     and (expires_at is null or expires_at > now_ms);

  if not found or rec.confidence < p_threshold then
    return jsonb_build_object('hit', false);
  end if;

  update engram.cache c
     set hit_count  = c.hit_count + 1,
         updated_at = now_ms
   where c.namespace = p_namespace
     and c.cache_key = p_cache_key;

  return jsonb_build_object(
    'hit',        true,
    'id',         rec.id,
    'cache_key',  rec.cache_key,
    'decision',   rec.decision,
    'confidence', rec.confidence,
    'hit_count',  rec.hit_count + 1,
    'meta',       rec.meta
  );
end; $$;

-- --------------------------------------------------------------
-- cache_store -- upsert a decision by (namespace, cache_key).
-- Returns the cache row id.
-- --------------------------------------------------------------
create or replace function engram.cache_store(
  p_cache_key  text,
  p_namespace  text    default 'default',
  p_decision   jsonb   default 'null'::jsonb,
  p_confidence float   default 0.5,
  p_meta       jsonb   default '{}'::jsonb
) returns text
language plpgsql
as $$
declare
  cid    text;
  now_ms bigint := extract(epoch from now())::bigint * 1000;
begin
  cid := md5(p_namespace || ':' || p_cache_key);

  insert into engram.cache
    (id, namespace, cache_key, decision, confidence, meta,
     hit_count, created_at, updated_at)
  values
    (cid, p_namespace, p_cache_key, p_decision, p_confidence, p_meta,
     1, now_ms, now_ms)
  on conflict (id) do update set
    decision   = excluded.decision,
    confidence = excluded.confidence,
    meta       = excluded.meta,
    updated_at = now_ms,
    hit_count  = engram.cache.hit_count + 1;

  insert into engram.audit (cache_id, namespace, cache_key, source, decision)
    values (cid, p_namespace, p_cache_key, 'learned', p_decision);

  return cid;
end; $$;

-- --------------------------------------------------------------
-- feedback -- confidence decay; evict below 0.2
-- --------------------------------------------------------------
create or replace function engram.feedback(
  p_cache_id  text,
  p_namespace text,
  was_correct boolean
) returns void
language plpgsql
as $$
declare
  now_ms bigint := extract(epoch from now())::bigint * 1000;
begin
  if was_correct then
    update engram.cache
       set success_count = success_count + 1,
           confidence    = least(confidence * 1.1, 1.0),
           updated_at    = now_ms
     where id = p_cache_id and namespace = p_namespace;
  else
    update engram.cache
       set failure_count = failure_count + 1,
           confidence    = greatest(confidence * 0.7, 0.0),
           updated_at    = now_ms
     where id = p_cache_id and namespace = p_namespace;

    delete from engram.cache
      where id = p_cache_id
        and namespace = p_namespace
        and confidence < 0.2;
  end if;

  insert into engram.audit (cache_id, namespace, source, decision)
    values (p_cache_id, p_namespace,
      case when was_correct then 'feedback_ok' else 'feedback_fail' end,
      null);
end; $$;

-- --------------------------------------------------------------
-- Utilities: user_baseline + detect_anomaly (off the decide path).
-- Kept so devs who want the behavioural stats still get them.
-- --------------------------------------------------------------
create or replace function engram.user_baseline(p_user_id text)
returns jsonb
language plpgsql
as $$
declare
  distinct_days int;
  result        jsonb;
  window_ms     bigint := 30::bigint * 24 * 60 * 60 * 1000;
  now_ms        bigint := extract(epoch from now())::bigint * 1000;
  since_ms      bigint := now_ms - window_ms;
begin
  select count(distinct (created_at / 86400000))
    into distinct_days
    from engram.user_events
   where user_id = p_user_id
     and created_at >= since_ms;

  if distinct_days is null or distinct_days < 3 then
    return null;
  end if;

  select jsonb_object_agg(event_type, summary)
    into result
  from (
    select
      event_type,
      jsonb_build_object(
        'count',       count(*),
        'days_seen',   count(distinct (created_at / 86400000)),
        'avg_per_day', round(
                         (count(*)::numeric /
                          greatest(count(distinct (created_at / 86400000)), 1)
                         )::numeric, 3),
        'first_seen',  min(created_at),
        'last_seen',   max(created_at),
        'sample_metadata', (
          select metadata
            from engram.user_events ue2
           where ue2.user_id    = p_user_id
             and ue2.event_type = ue.event_type
             and ue2.created_at >= since_ms
           order by ue2.created_at desc
           limit 1
        )
      ) as summary
    from engram.user_events ue
    where user_id = p_user_id
      and created_at >= since_ms
    group by event_type
  ) s;

  return jsonb_build_object(
    'user_id',       p_user_id,
    'window_days',   30,
    'distinct_days', distinct_days,
    'computed_at',   now_ms,
    'event_types',   coalesce(result, '{}'::jsonb)
  );
end; $$;

create or replace function engram.detect_anomaly(
  p_user_id text,
  p_current jsonb
) returns jsonb
language plpgsql
as $$
declare
  baseline       jsonb;
  event_types    jsonb;
  anomalies      jsonb   := '[]'::jsonb;
  max_ratio      numeric := 0;
  score          numeric := 0;
  kv             record;
  baseline_entry jsonb;
  current_val    numeric;
  baseline_avg   numeric;
  ratio          numeric;
begin
  baseline := engram.user_baseline(p_user_id);
  if baseline is null then
    return jsonb_build_object(
      'anomaly_score',    0,
      'anomalies',        '[]'::jsonb,
      'baseline',         null,
      'current',          coalesce(p_current, '{}'::jsonb),
      'should_ask_brain', false,
      'reason',           'insufficient baseline (<3 days of history)'
    );
  end if;

  event_types := baseline->'event_types';

  for kv in select * from jsonb_each(coalesce(p_current, '{}'::jsonb)) loop
    begin
      current_val := (kv.value #>> '{}')::numeric;
    exception when others then
      continue;
    end;

    baseline_entry := event_types->(kv.key);
    if baseline_entry is null then
      anomalies := anomalies || jsonb_build_array(jsonb_build_object(
        'event_type',   kv.key,
        'kind',         'new_event_type',
        'current',      current_val,
        'baseline_avg', null,
        'ratio',        null
      ));
      max_ratio := greatest(max_ratio, 1.0);
      continue;
    end if;

    baseline_avg := coalesce((baseline_entry->>'avg_per_day')::numeric, 0);
    if baseline_avg <= 0 then
      if current_val > 0 then
        anomalies := anomalies || jsonb_build_array(jsonb_build_object(
          'event_type',   kv.key,
          'kind',         'zero_baseline_nonzero_current',
          'current',      current_val,
          'baseline_avg', baseline_avg,
          'ratio',        null
        ));
        max_ratio := greatest(max_ratio, 1.0);
      end if;
      continue;
    end if;

    ratio := current_val / baseline_avg;
    if ratio >= 3 or ratio <= 0.1 then
      anomalies := anomalies || jsonb_build_array(jsonb_build_object(
        'event_type',   kv.key,
        'kind',         case when ratio >= 3 then 'burst' else 'silence' end,
        'current',      current_val,
        'baseline_avg', baseline_avg,
        'ratio',        round(ratio, 3)
      ));
      max_ratio := greatest(
        max_ratio,
        least(1.0, case when ratio >= 3 then (ratio - 1) / 10 else (1 - ratio) end)
      );
    end if;
  end loop;

  score := round(max_ratio, 3);
  return jsonb_build_object(
    'anomaly_score',    score,
    'anomalies',        anomalies,
    'baseline',         baseline,
    'current',          coalesce(p_current, '{}'::jsonb),
    'should_ask_brain', score > 0.6
  );
end; $$;

-- --------------------------------------------------------------
-- Observability
-- --------------------------------------------------------------
create or replace function engram.stats(p_namespace text default null)
returns jsonb
language plpgsql
as $$
declare r jsonb;
begin
  select jsonb_build_object(
    'total_cached',   count(*),
    'avg_confidence', round(coalesce(avg(confidence), 0)::numeric, 3),
    'total_hits',     coalesce(sum(hit_count), 0)
  ) into r
  from engram.cache
  where (p_namespace is null or namespace = p_namespace);
  return r;
end; $$;

create or replace function engram.list_cache(
  p_namespace text default null,
  p_limit     int  default 100
) returns jsonb
language plpgsql
as $$
begin
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id',            c.id,
      'namespace',     c.namespace,
      'cache_key',     c.cache_key,
      'decision',      c.decision,
      'confidence',    c.confidence,
      'hit_count',     c.hit_count,
      'success_count', c.success_count,
      'failure_count', c.failure_count,
      'meta',          c.meta,
      'created_at',    to_timestamp(c.created_at / 1000)::text,
      'updated_at',    to_timestamp(c.updated_at / 1000)::text
    ) order by c.hit_count desc)
    from engram.cache c
    where (p_namespace is null or c.namespace = p_namespace)
    limit p_limit
  ), '[]'::jsonb);
end; $$;

create or replace function engram.dashboard()
returns jsonb
language plpgsql
as $$
declare cache_summary jsonb; events_summary jsonb;
begin
  select jsonb_build_object(
    'total',       count(*),
    'total_hits',  coalesce(sum(hit_count), 0),
    'avg_confidence', round(coalesce(avg(confidence), 0)::numeric, 3),
    'by_namespace', coalesce((
      select jsonb_object_agg(namespace, n)
        from (select namespace, count(*) as n from engram.cache group by namespace) s
    ), '{}')
  ) into cache_summary from engram.cache;

  select jsonb_build_object(
    'total', count(*),
    'by_event_type', coalesce((
      select jsonb_object_agg(event_type, n)
        from (select event_type, count(*) as n from engram.user_events group by event_type) s
    ), '{}')
  ) into events_summary from engram.user_events;

  return jsonb_build_object(
    'cache',   cache_summary,
    'events',  events_summary,
    'version', '@engram/core@0.2.0'
  );
end; $$;
