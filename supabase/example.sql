-- ============================================================
-- Engram v1.0.0 — Test examples
-- Run these after install.sql to verify everything works.
-- ============================================================

-- 1. Classify a real user (normal behavior)
select engram.classify(jsonb_build_object(
  'authenticated',       true,
  'account_age_days',    45,
  'uploads_last_hour',   2,
  'credits_remaining',   10,
  'last_payment_status', 'success',
  'ua_class',            'browser'
));
-- Expected: {"decision":"allow","confidence":0.85,...}

-- 2. Classify a bot (burst velocity, missing UA)
select engram.classify(jsonb_build_object(
  'authenticated',       true,
  'account_age_days',    0,
  'uploads_last_hour',   15,
  'credits_remaining',   0,
  'last_payment_status', 'none',
  'ua_class',            'missing'
));
-- Expected: {"decision":"fraud","confidence":0.95,...}

-- 3. Classify a churn risk (paid, idle, has credits)
select engram.classify(jsonb_build_object(
  'authenticated',       true,
  'account_age_days',    60,
  'uploads_last_hour',   0,
  'credits_remaining',   5,
  'last_activity_days',  20,
  'last_payment_status', 'success',
  'ua_class',            'browser'
));
-- Expected: {"decision":"churn_risk","confidence":0.80,...}

-- 4. Full decide flow (lookup -> classify -> learn)
--    First call: source=classify (learns the pattern)
select engram.decide(jsonb_build_object(
  'authenticated',       true,
  'account_age_days',    30,
  'uploads_last_hour',   1,
  'credits_remaining',   8,
  'last_payment_status', 'success',
  'ua_class',            'browser'
), 'example');
-- Expected: source=classify, hit_count=1

--    Second call: same features -> source=pattern_store (brain silent)
select engram.decide(jsonb_build_object(
  'authenticated',       true,
  'account_age_days',    30,
  'uploads_last_hour',   1,
  'credits_remaining',   8,
  'last_payment_status', 'success',
  'ua_class',            'browser'
), 'example');
-- Expected: source=pattern_store, hit_count=2

-- 5. Check stats
select engram.stats('example');

-- 6. View all learned patterns
select
  id,
  namespace,
  decision,
  confidence,
  hit_count,
  reason->>'rule'        as rule,
  reason->>'explanation' as explanation,
  to_timestamp(created_at / 1000) as created
from engram.patterns
order by hit_count desc;

-- 7. Cleanup example data
delete from engram.patterns where namespace = 'example';
delete from engram.audit    where namespace = 'example';
