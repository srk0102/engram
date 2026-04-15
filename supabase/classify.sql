create or replace function engram.classify(
  fp jsonb
) returns jsonb
language plpgsql
as $$
declare
  ua    float;
  hdrs  integer;
  rpm   float;
  tms   float;
  dec   text    := 'allow';
  conf  float   := 0.85;
  expl  text    := 'normal behavior pattern';
begin
  ua   := coalesce((fp->>'user_agent_score')::float, 1.0);
  hdrs := coalesce((fp->>'header_count')::integer, 10);
  rpm  := coalesce((fp->>'requests_per_minute')::float, 0);
  tms  := coalesce((fp->>'timing_ms')::float, 1000);

  if tms < 100 and rpm > 60 then
    dec  := 'block';
    conf := 0.92;
    expl := 'high frequency automated pattern';
  elsif hdrs < 3 then
    dec  := 'flag';
    conf := 0.88;
    expl := 'missing standard browser headers';
  elsif rpm > 80 then
    dec  := 'flag';
    conf := 0.82;
    expl := 'elevated request rate';
  elsif ua = 0 then
    dec  := 'flag';
    conf := 0.80;
    expl := 'no user agent detected';
  end if;

  return jsonb_build_object(
    'decision',    dec,
    'confidence',  conf,
    'reason', jsonb_build_object(
      'source',      'classify',
      'explanation', expl,
      'signals', jsonb_build_object(
        'ua_score',            ua,
        'header_count',        hdrs,
        'requests_per_minute', rpm,
        'timing_ms',           tms
      )
    )
  );
end;
$$;
