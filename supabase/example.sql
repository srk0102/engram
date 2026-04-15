-- Test Engram is working

-- 1. Classify a suspicious request
select engram.classify(
  jsonb_build_object(
    'endpoint',            '/api/products',
    'method',              'GET',
    'user_agent_score',    0,
    'header_count',        2,
    'requests_per_minute', 95,
    'timing_ms',           45
  )
);

-- 2. Store the pattern
select engram.learn(
  jsonb_build_object(
    'endpoint',         '/api/products',
    'method',           'GET',
    'ua_score_bucket',  'none',
    'header_bucket',    'minimal'
  ),
  'default',
  'block',
  0.92,
  jsonb_build_object(
    'source',      'classify',
    'explanation', 'high frequency bot'
  )
);

-- 3. Look it up next time
select * from engram.lookup(
  jsonb_build_object(
    'endpoint',        '/api/products',
    'method',          'GET',
    'ua_score_bucket', 'none',
    'header_bucket',   'minimal'
  ),
  'default'
);

-- 4. Check stats
select engram.stats('default');

-- 5. View all patterns in dashboard
select
  id,
  namespace,
  decision,
  confidence,
  hit_count,
  fingerprint->>'endpoint' as endpoint,
  reason->>'explanation'   as reason,
  to_timestamp(created_at / 1000) as created
from engram.patterns
order by hit_count desc;
