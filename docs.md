# Engram — Documentation

Complete technical reference for installing, configuring, and using Engram.

---

## Table of contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [How decisions work](#how-decisions-work)
4. [Classification rules](#classification-rules)
5. [Write APIs](#write-apis)
6. [Read APIs](#read-apis)
7. [Node.js integration](#nodejs-integration)
8. [Schema reference](#schema-reference)
9. [Security model](#security-model)
10. [Retention and cleanup](#retention-and-cleanup)

---

## Installation

### Step 1: Run the SQL

Open your Supabase project. Go to **SQL Editor**. Paste the entire contents of [`supabase/install.sql`](supabase/install.sql). Run it.

This creates:
- The `engram` schema
- 6 tables with indexes
- 18 functions
- RLS on all tables
- A pg_cron job for automatic cleanup

### Step 2: Expose the schema

Go to **Settings → API → Exposed schemas**. Add `engram` to the list alongside `public`. Click Apply.

### Step 3: Verify

Run this in the SQL Editor:

```sql
select engram.classify(
  '{"account_age_days":0,"uploads_last_hour":15,"ua_class":"missing"}'::jsonb
);
```

You should see: `{"decision":"fraud","confidence":0.95,...}`

If you see that, Engram is installed.

---

## Configuration

Engram works out of the box with zero configuration. The default rules cover:

- New account fraud (burst signups + rapid usage)
- Bot detection (missing UA, anonymous velocity)
- Churn risk (paid users going idle)
- Young account velocity flagging

To customize rules, edit the `engram.classify()` function directly in your SQL Editor. Rules are plain `IF/THEN` statements in PL/pgSQL — no config files, no YAML, no environment variables.

---

## How decisions work

Every request that passes through Engram gets one of five decisions:

### allow
Normal user. Request passes silently. No logging beyond a rollup counter. This is what 95%+ of your traffic should see.

### flag
Suspicious but not certain. Request passes through — the user gets their response normally. But the request is tagged internally so you can review it later via `engram.list_visits(null, 'flag')`.

Use case: young accounts with moderate activity. You don't want to block them (they might be real), but you want to watch.

### fraud
Blocked. Returns 403 before your handler runs. Your LLM is never called. Your database is never queried. Credits are not deducted. Cost for this request: $0.

Use case: brand-new account uploading 15 resumes in one hour with no user agent.

### bot
Blocked. Returns 429 with a Retry-After header. Same as fraud in terms of blocking, but semantically different — this is automated traffic, not necessarily malicious.

Use case: someone running a script against your API without authentication.

### churn_risk
Passes through. User gets their response normally. But the user is added to a churn queue that you can poll.

Use case: a paying user who hasn't used the product in 20 days but still has credits remaining.

---

## Classification rules

Rules are evaluated top to bottom. First match wins.

```
1. fraud_new_burst
   Account < 1 day old AND 10+ uploads per hour
   → fraud (0.95 confidence)

2. fraud_new_paid_fast
   Account < 1 day old AND has paid AND 5+ uploads per hour
   → fraud (0.90 confidence)

3. bot_ua_velocity
   User agent is missing or suspicious AND 5+ uploads per hour
   → bot (0.92 confidence)

4. bot_anon_velocity
   Not authenticated AND 3+ uploads per hour
   → bot (0.85 confidence)

5. churn_idle_with_credits
   Account 7+ days old AND has credits AND inactive 14+ days
   → churn_risk (0.80 confidence)

6. churn_visited_no_complete
   Visited generate endpoint but no completion in 7 days
   → churn_risk (0.75 confidence)

7. young_account_bot_velocity
   Account 1-3 days old AND 8+ uploads per hour
   → fraud (0.88 confidence, escalated)

8. flag_young_velocity
   Account 1-3 days old AND 4-7 uploads per hour
   → flag (0.75 confidence)

9. velocity_absolute
   15+ uploads per hour regardless of account age
   → flag (0.82 confidence)

10. allow_default
    Everything else
    → allow (0.85 confidence)
```

### Adding your own rules

Open `engram.classify()` in the SQL Editor. Add a new `IF` block before the `allow_default` return. Example:

```sql
-- Block users from a specific country
if (fp->>'country')::text = 'XX' and uph >= 5 then
  return jsonb_build_object(
    'decision', 'block',
    'confidence', 0.85,
    'reason', jsonb_build_object(
      'source', 'classify',
      'rule', 'geo_block',
      'explanation', 'blocked region with velocity'
    )
  );
end if;
```

No deployment needed. No code changes. SQL only.

---

## Write APIs

These functions change state. Call them from your backend.

### `engram.classify(features jsonb) → jsonb`

Pure classification. Does not cache. Does not learn. Stateless.

```sql
select engram.classify(jsonb_build_object(
  'authenticated', true,
  'account_age_days', 45,
  'uploads_last_hour', 2,
  'ua_class', 'browser'
));
```

### `engram.decide(features jsonb, namespace text) → jsonb`

The main entry point. Checks cache first, classifies on miss, learns the result.

```sql
-- First call: classifies, learns, returns source=classify
select engram.decide('{"account_age_days":30,"ua_class":"browser"}'::jsonb, 'my_app');

-- Second call with same features: returns source=pattern_store (cached)
select engram.decide('{"account_age_days":30,"ua_class":"browser"}'::jsonb, 'my_app');
```

### `engram.learn(features, namespace, decision, confidence, reason, meta) → text`

Store a pattern manually. Returns the pattern ID.

### `engram.feedback(pattern_id, namespace, was_correct) → void`

Reinforce or weaken a cached pattern. Correct decisions increase confidence. Wrong decisions decrease it. Below 0.2 confidence, patterns auto-evict.

### `engram.record_behavior(user_id, endpoint, ip, ua, decision) → bigint`

Log a route visit. Returns the visit ID for later `finish_behavior()`.

### `engram.finish_behavior(visit_id, status_code) → void`

Mark a visit as completed with the HTTP status code.

### `engram.enqueue_churn(user_id, signals) → void`

Add or update a user in the churn queue. Upserts — same user flagged twice just increments the counter.

### `engram.user_signals(user_id) → jsonb`

Assembles all behavior context for a user in one query. Returns account age, credits, upload counts, payment status, visit count. Use this to build the features object for `classify()` or `decide()`.

---

## Read APIs

These functions query what Engram has learned. All return JSON.

### `engram.dashboard() → jsonb`

Everything in one call. Pattern counts by decision, route visits by endpoint, churn queue status.

```sql
select engram.dashboard();
```

```json
{
  "patterns": {
    "total": 16,
    "total_hits": 3025,
    "by_decision": {"allow": 11, "block": 2, "fraud": 3},
    "avg_confidence": 0.878
  },
  "route_visits": {
    "total": 7,
    "by_decision": {"allow": 6, "fraud": 1},
    "by_endpoint": {"/api/parse-resume": 7}
  },
  "churn_queue_unresolved": 0,
  "version": "v1.0.2"
}
```

### `engram.list_patterns(namespace, limit) → jsonb`

All learned patterns. Filter by namespace or get everything.

```sql
-- All patterns, top 10 by hit count
select engram.list_patterns(null, 10);

-- Patterns for a specific namespace
select engram.list_patterns('my_app', 50);
```

### `engram.get_pattern(pattern_id) → jsonb`

Full detail on a single pattern including fingerprint, meta, timestamps.

### `engram.list_visits(endpoint, decision, limit) → jsonb`

Route visit history. Filter by endpoint, decision, or both.

```sql
-- All fraud-blocked visits
select engram.list_visits(null, 'fraud', 20);

-- All visits to a specific endpoint
select engram.list_visits('/api/parse-resume', null, 50);
```

### `engram.list_audit(namespace, limit) → jsonb`

Audit log — every learn, feedback, and eviction event.

### `engram.list_churn_queue(include_resolved) → jsonb`

Current churn queue. Pass `true` to include resolved entries.

### `engram.stats(namespace) → jsonb`

Summary for a single namespace.

---

## Node.js integration

### Basic: wrap your route handler

```typescript
import { withEngram } from './lib/engram'

export const POST = withEngram(async (request) => {
  // This code only runs for allowed requests.
  // Bots and fraudsters never reach this line.
  const data = await yourExpensiveOperation()
  return Response.json(data)
}, { namespace: 'my_route' })
```

### What `withEngram` does

1. Reads cookies → resolves user ID via Supabase auth
2. Calls `engram.user_signals(user_id)` → gets account age, credits, etc.
3. Calls `engram.decide(features, namespace)` → gets cached or fresh decision
4. Applies the action:
   - `fraud` → returns 403, your handler never runs
   - `bot` → returns 429, your handler never runs
   - `churn_risk` → adds to queue, your handler runs normally
   - `flag` → tags the request, your handler runs normally
   - `allow` → your handler runs normally
5. Records the visit to `route_visits`

### Fail-open guarantee

If Supabase is down, if the RPC times out, if any error occurs inside Engram — your handler runs anyway. Engram will never block a legitimate user because it crashed. This is enforced by a `try/catch` around the entire gate logic.

### Custom action handlers

```typescript
export const POST = withEngram(handler, {
  namespace: 'uploads',
  onFraud: async (req, verdict) => {
    // Custom: log to your analytics, send Slack alert, etc.
    await sendSlackAlert(verdict)
    return new Response('blocked', { status: 403 })
  },
  onChurnRisk: async (req, verdict) => {
    // Custom: trigger an email campaign
    await triggerWinbackEmail(req)
  },
})
```

---

## Schema reference

### engram.patterns

| Column | Type | Description |
|--------|------|-------------|
| id | text PK | MD5 hash of bucketed behavior features |
| namespace | text | Logical partition (e.g. 'my_app') |
| fingerprint | jsonb | The raw features used to compute the hash |
| decision | text | allow, block, flag, fraud, bot, churn_risk |
| reason | jsonb | {source, rule, explanation, signals} |
| confidence | float | 0.0 - 1.0, increases/decreases via feedback |
| hit_count | int | How many times this pattern was served from cache |
| success_count | int | Reinforced by positive feedback |
| failure_count | int | Weakened by negative feedback |
| meta | jsonb | Developer-defined extensions |
| created_at | bigint | Epoch milliseconds |
| updated_at | bigint | Epoch milliseconds |
| expires_at | bigint | Optional TTL (epoch ms), null = no expiry |

### engram.route_visits

| Column | Type | Description |
|--------|------|-------------|
| id | bigserial PK | Auto-increment |
| user_id | uuid | Nullable (anonymous requests have null) |
| endpoint | text | Route path (e.g. '/api/parse-resume') |
| ip | text | Client IP from X-Forwarded-For or similar |
| ua | text | Raw User-Agent header |
| decision | text | What Engram decided for this request |
| entered_at | timestamptz | When the request entered the gate |
| finished_at | timestamptz | When the handler completed |
| status_code | int | HTTP status returned to client |

Rows older than 7 days are automatically deleted by pg_cron.

### engram.churn_queue

| Column | Type | Description |
|--------|------|-------------|
| user_id | uuid PK | One row per user, upserted on re-flag |
| first_flagged_at | timestamptz | When first flagged |
| last_flagged_at | timestamptz | Most recent flag |
| flag_count | int | How many times this user was flagged |
| current_signals | jsonb | The signals that triggered the latest flag |
| resolved_at | timestamptz | Null until manually resolved |
| resolved_by | text | Who resolved it |

### engram.audit

One row per state change (pattern learned, feedback applied, pattern evicted).

### engram.rollups

Per-minute aggregated hit counts and latency stats per pattern. Used for time-series analysis without querying individual visits.

### engram.shadow_comparisons

A/B comparison logs from shadow mode testing. Records old path vs new path output side by side.

---

## Security model

```
Role              Schema access    Table access      Function access
─────────────────────────────────────────────────────────────────────
anon              none             none              none
authenticated     USAGE            none              EXECUTE on all
service_role      USAGE            SELECT (+some)    EXECUTE on all
```

- **anon** cannot see or call anything in the engram schema
- **authenticated** can call functions but cannot `SELECT * FROM engram.patterns`
- **service_role** (your backend) can read tables directly for dashboards
- All tables have **RLS enabled** with no policies — locked by default
- Functions that cross schemas use **SECURITY DEFINER** with explicit `search_path`

---

## Retention and cleanup

### route_visits

Automatically cleaned by a pg_cron job running hourly at minute :17. Rows older than 7 days are deleted. No action needed.

To change the retention period, update the cron job:

```sql
-- Change to 30 days
select cron.unschedule('engram_route_visits_retention');
select cron.schedule(
  'engram_route_visits_retention',
  '17 * * * *',
  $$ delete from engram.route_visits where entered_at < now() - interval '30 days' $$
);
```

### patterns

Patterns do not expire by default. To add TTL:

```sql
-- Expire patterns after 90 days of no hits
update engram.patterns
set expires_at = updated_at + (90 * 86400000)
where expires_at is null;
```

### rollups

Clean manually or via cron:

```sql
-- Delete rollups older than 7 days
select engram.prune_rollups(7 * 86400 * 1000);
```

---

## Behavior features reference

These are the fields `engram.classify()` reads from the input JSON:

| Field | Type | What it means |
|-------|------|---------------|
| `authenticated` | boolean | Is the user logged in? |
| `account_age_days` | int | Days since account creation |
| `uploads_last_hour` | int | Uploads/generations in last 60 minutes |
| `uploads_last_7d` | int | Uploads/generations in last 7 days |
| `credits_remaining` | int | Unused credits on the account |
| `last_activity_days` | int | Days since last upload/generation |
| `last_payment_status` | text | 'success', 'error', 'expired', or 'none' |
| `visits_last_hour` | int | Route visits logged by Engram in last hour |
| `ua_class` | text | 'browser', 'suspicious', or 'missing' |
| `visited_generate_no_complete` | boolean | Visited generate but no output in 7 days |

All fields are optional. Missing fields default to safe values (0 for numbers, 'none' for strings, false for booleans).
