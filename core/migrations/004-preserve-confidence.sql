-- Migration 004: preserve confidence + counters on cache_store upsert.
--
-- The v0.2.0 cache_store() upsert did `confidence = excluded.confidence`
-- on conflict, which reset the row to the caller's passed-in confidence
-- every time the brain stored again (e.g. when two concurrent cache
-- misses for the same key both finished and stored). That clobbered any
-- feedback gains the row had accumulated.
--
-- This override keeps the upsert ADDITIVE:
--   - decision   refreshes (brain might have sharpened its wording)
--   - meta       refreshes (any new metadata overrides)
--   - updated_at bumps
--   - confidence stays at whatever feedback() has moved it to
--   - hit_count / success_count / failure_count are not touched
--
-- Feedback is the ONLY mechanism that now moves confidence. cache_store
-- is a pure insert-or-refresh of the semantic content.

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
    meta       = excluded.meta,
    updated_at = now_ms;

  return cid;
end;
$$;
