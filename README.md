<p align="center">
  <img src="engram-svgrepo-com.svg" width="120" height="120" alt="Engram"/>
</p>

<h1 align="center">Engram</h1>

<p align="center">
  Your API learns to defend itself.
</p>

<p align="center">
  <a href="https://github.com/srk0102/engram"><img src="https://img.shields.io/badge/version-v1.0.0-059669" alt="version"/></a>
  <a href="https://github.com/srk0102/engram"><img src="https://img.shields.io/badge/tests-11%20passing-059669" alt="tests"/></a>
  <a href="https://github.com/srk0102/SCP"><img src="https://img.shields.io/badge/built_on-scp--protocol-4F46E5" alt="scp"/></a>
  <a href="https://supabase.com"><img src="https://img.shields.io/badge/runs_on-supabase-3ECF8E" alt="supabase"/></a>
</p>

---

## The problem

Every API trusts every request equally. A real user uploading their resume and a bot scraping 10,000 resumes per hour hit the same endpoint, run the same LLM call, cost the same money.

Rate limiters count requests. They don't understand behavior. A bot that sends 29 requests per minute passes a 30/min limit. A real user who uploads 5 resumes in quick succession gets blocked.

## The insight

Behavior has shape. A real user has an account age, a payment history, a session pattern. A bot has none of these — or has them in combinations that look wrong.

Classify the shape once. Cache the decision. Next request with the same shape: return the cached decision. Brain silent.

| Request | What happens | Latency | Cost |
|--------:|-------------|--------:|-----:|
| 1 (new shape) | Classify → learn pattern | ~100ms | ~0 |
| 2 (same shape) | Return cached decision | <1ms | $0 |
| 1000 (same shape) | Still cached | <1ms | $0 |

The brain teaches once. The pattern store remembers.

## Install in Supabase

```sql
-- Paste supabase/install.sql into your Supabase SQL Editor.
-- Run once. Done.
```

After running:

1. Go to **Settings → API → Exposed schemas** → add `engram`
2. Verify: `select engram.classify('{"account_age_days":0,"uploads_last_hour":15,"ua_class":"missing"}'::jsonb);`
3. Expected: `{"decision":"fraud","confidence":0.95,...}`

No new infrastructure. No code changes. Uses your existing Postgres.

## What gets created

```
engram schema
├── patterns              behavior fingerprints → cached decisions
├── audit                 state-change log (learn, feedback, eviction)
├── rollups               per-minute hit/latency aggregates
├── route_visits          one row per gated request (7-day TTL)
├── churn_queue           users flagged as churn risk
└── shadow_comparisons    A/B comparison logs

12 functions              classify, decide, lookup, learn, feedback,
                          user_signals, record_behavior, finish_behavior,
                          enqueue_churn, stats, hash_fingerprint, prune_rollups

pg_cron job               sweeps route_visits > 7 days, hourly
```

All tables have RLS enabled. `anon` and `authenticated` have zero table-level grants. Functions use `SECURITY DEFINER` where needed. Only `service_role` can read tables directly.

## Quick start — Supabase only (2 minutes)

```sql
-- 1. Classify a real user
select engram.classify(jsonb_build_object(
  'authenticated',       true,
  'account_age_days',    45,
  'uploads_last_hour',   2,
  'credits_remaining',   10,
  'last_payment_status', 'success',
  'ua_class',            'browser'
));
-- → {"decision":"allow","confidence":0.85}

-- 2. Classify a bot
select engram.classify(jsonb_build_object(
  'authenticated',       true,
  'account_age_days',    0,
  'uploads_last_hour',   15,
  'ua_class',            'missing'
));
-- → {"decision":"fraud","confidence":0.95}

-- 3. Full decide flow (lookup → classify → learn)
select engram.decide(jsonb_build_object(
  'authenticated', true,
  'account_age_days', 30,
  'uploads_last_hour', 1,
  'ua_class', 'browser'
), 'my_app');
-- First call:  source=classify, hit_count=1 (brain called)
-- Second call: source=pattern_store, hit_count=2 (brain silent)
```

## Quick start — Node.js / Next.js (5 minutes)

```typescript
import { withEngram } from '@/lib/engram'

export const POST = withEngram(async (request) => {
  // Your handler runs unchanged.
  // If fraud/bot: this line never executes. 403/429 already returned.
  // If allow/flag/churn: runs normally.
  const data = await doExpensiveWork(request)
  return NextResponse.json(data)
}, { namespace: 'my_route' })
```

`withEngram` does four things:

1. **Assembles context** — one RPC to `user_signals()` returns account age, credits, upload count, payment status, visit count. One round trip.
2. **Decides** — checks pattern cache, classifies on miss, learns the result.
3. **Acts** — fraud → 403, bot → 429, churn → enqueue, flag → tag, allow → pass.
4. **Records** — logs the visit to `route_visits` for the dashboard.

**Fail-open by design.** If Supabase is down, if the RPC times out, if anything inside Engram throws — your handler runs anyway. Engram never blocks a legitimate user because it crashed.

## Behavior rules

Rules are evaluated in priority order. First match wins.

| # | Rule | Signals | Decision |
|---|------|---------|----------|
| 1 | `fraud_new_burst` | age < 1 day AND uploads/hr ≥ 10 | fraud |
| 2 | `fraud_new_paid_fast` | age < 1 day AND paid AND uploads ≥ 5 | fraud |
| 3 | `bot_ua_velocity` | UA suspicious + uploads ≥ 5 | bot |
| 4 | `bot_anon_velocity` | not authenticated + uploads ≥ 3 | bot |
| 5 | `churn_idle_with_credits` | age ≥ 7d AND credits > 0 AND idle 14d+ | churn_risk |
| 6 | `churn_visited_no_complete` | visited but no output in 7d | churn_risk |
| 7 | `young_account_bot_velocity` | age 1-3d AND uploads ≥ 8 | fraud |
| 8 | `flag_young_velocity` | age 1-3d AND uploads 4-7 | flag |
| 9 | `velocity_absolute` | uploads/hr ≥ 15 (any age) | flag |
| 10 | `allow_default` | everything else | allow |

Rules live in `engram.classify()`. Edit them in SQL to match your product.

## Dashboard

```
GET /api/engram/dashboard     → JSON summary of all learned patterns
/admin/engram                 → visual dashboard (dark theme)
```

Shows: patterns by decision, top blocked with reasons, route visits by endpoint, churn queue, audit log, SCP cache rates, Plexa vertical memory stats.

## How it connects to SCP and Plexa

```
Request arrives
  │
  ├─ ENGRAM (before everything)
  │   Watches user behavior.
  │   Blocks bots/fraud before handler runs.
  │   Allows real users silently.
  │
  ├─ Your handler runs (only for real users)
  │
  └─ SCP + PLEXA (after response, fire-and-forget)
      Builds product intelligence.
      Section-level structural caching.
      Holistic scoring with vertical memory.
      Brain goes silent after learning.
```

Engram = who is this user and should I trust them.
SCP + Plexa = what does this content say and how good is it.

Completely separate concerns. Can be deployed independently.

## Signals Engram watches

| Signal | Source | Used for |
|--------|--------|----------|
| `account_age_days` | `profiles.created_at` | New account fraud detection |
| `uploads_last_hour` | count over `generations` | Burst velocity detection |
| `credits_remaining` | `profiles.extraction_credits` | Churn risk (paid but idle) |
| `last_payment_status` | latest `payment_events` | Card fraud correlation |
| `ua_class` | request `User-Agent` header | Bot/headless detection |
| `visits_last_hour` | `engram.route_visits` count | Session frequency |
| `authenticated` | Supabase auth session | Anonymous bot detection |

All signals assembled in one RPC call (`user_signals`). One round trip per request.

## Security model

```
anon              → zero access (cannot read tables, cannot call functions)
authenticated     → EXECUTE on functions only (no table reads)
service_role      → EXECUTE + SELECT on tables (for dashboard)
tables            → RLS enabled, no policies (locked by default)
functions         → SECURITY DEFINER where they touch other schemas
```

## Status

```
Supabase extension    v1.0.0    install.sql, one-paste
Node.js middleware    v1.0.0    withEngram() wrapper
Dashboard             v1.0.0    API + visual page
E2E tests            11/11     automated, all passing
License              MIT
```

## Links

- [SCP Protocol](https://github.com/srk0102/SCP) — body-level pattern caching
- [Plexa](https://github.com/srk0102/plexa) — multi-body orchestration
- [Supabase](https://supabase.com) — the database Engram runs on
