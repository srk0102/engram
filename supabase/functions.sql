create or replace function engram.hash_fingerprint(
  fp jsonb,
  ns text default 'default'
) returns text
language plpgsql
as $$
begin
  return md5(
    ns || ':' ||
    coalesce(fp->>'endpoint', '') || ':' ||
    coalesce(fp->>'method', '') || ':' ||
    coalesce(fp->>'ua_score_bucket', '') || ':' ||
    coalesce(fp->>'header_bucket', '') || ':' ||
    coalesce((fp->>'has_referer')::text, 'false')
  );
end;
$$;

create or replace function engram.lookup(
  fp jsonb,
  ns text default 'default',
  threshold float default 0.8
) returns table (
  decision   text,
  confidence float,
  reason     jsonb,
  source     text,
  hit_count  integer
)
language plpgsql
as $$
declare
  pid text;
  rec engram.patterns%rowtype;
begin
  pid := engram.hash_fingerprint(fp, ns);

  select * into rec
  from engram.patterns
  where id = pid
    and namespace = ns
    and (expires_at is null or
         expires_at >
           extract(epoch from now())::bigint
           * 1000);

  if found and rec.confidence >= threshold then
    update engram.patterns
    set
      hit_count  = hit_count + 1,
      updated_at =
        extract(epoch from now())::bigint * 1000
    where id = pid and namespace = ns;

    return query select
      rec.decision,
      rec.confidence,
      rec.reason,
      'pattern_store'::text,
      rec.hit_count + 1;
  end if;
end;
$$;

create or replace function engram.learn(
  fp           jsonb,
  ns           text,
  p_decision   text,
  p_confidence float,
  p_reason     jsonb,
  p_meta       jsonb default '{}'
) returns void
language plpgsql
as $$
declare
  pid text;
begin
  pid := engram.hash_fingerprint(fp, ns);

  insert into engram.patterns (
    id, namespace, fingerprint,
    decision, confidence, reason, meta,
    hit_count, created_at, updated_at
  ) values (
    pid, ns, fp,
    p_decision, p_confidence,
    p_reason, p_meta,
    1,
    extract(epoch from now())::bigint * 1000,
    extract(epoch from now())::bigint * 1000
  )
  on conflict (id) do update set
    hit_count  = engram.patterns.hit_count + 1,
    updated_at =
      extract(epoch from now())::bigint * 1000;

  insert into engram.audit (
    pattern_id, namespace,
    decision, source, fingerprint
  ) values (
    pid, ns,
    p_decision, 'learned', fp
  );
end;
$$;

create or replace function engram.feedback(
  p_id         text,
  ns           text,
  was_correct  boolean
) returns void
language plpgsql
as $$
begin
  if was_correct then
    update engram.patterns
    set
      success_count = success_count + 1,
      confidence    = least(confidence * 1.1, 1.0),
      updated_at    =
        extract(epoch from now())::bigint * 1000
    where id = p_id and namespace = ns;
  else
    update engram.patterns
    set
      failure_count = failure_count + 1,
      confidence    =
        greatest(confidence * 0.7, 0.0),
      updated_at    =
        extract(epoch from now())::bigint * 1000
    where id = p_id and namespace = ns;

    delete from engram.patterns
    where id = p_id
      and namespace = ns
      and confidence < 0.2;
  end if;
end;
$$;

create or replace function engram.stats(
  ns text default 'default'
) returns jsonb
language plpgsql
as $$
declare
  result jsonb;
begin
  select jsonb_build_object(
    'total_patterns',  count(*),
    'block_patterns',  count(*)
      filter (where decision = 'block'),
    'allow_patterns',  count(*)
      filter (where decision = 'allow'),
    'flag_patterns',   count(*)
      filter (where decision = 'flag'),
    'avg_confidence',
      round(avg(confidence)::numeric, 3),
    'total_hits',      sum(hit_count)
  ) into result
  from engram.patterns
  where namespace = ns;

  return result;
end;
$$;
