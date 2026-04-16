<p align="center">
  <img src="engram-svgrepo-com.svg" width="120" height="120" alt="Engram"/>
</p>

<h1 align="center">Engram</h1>

<p align="center">
  Your API learns to defend itself.
</p>

<p align="center">
  <a href="https://github.com/srk0102/engram"><img src="https://img.shields.io/badge/version-v1.0.2-059669" alt="version"/></a>
  <a href="https://github.com/srk0102/engram"><img src="https://img.shields.io/badge/tests-17%20passing-059669" alt="tests"/></a>
  <a href="https://github.com/srk0102/SCP"><img src="https://img.shields.io/badge/built_on-scp--protocol-4F46E5" alt="scp"/></a>
  <a href="https://supabase.com"><img src="https://img.shields.io/badge/runs_on-supabase-3ECF8E" alt="supabase"/></a>
</p>

---

## The problem

You built an API. Users pay for it. Bots don't.

A bot scraping your parsed resumes costs you the same LLM call as a real user. A fraudster with a stolen card burns through your credits in minutes. A churning user silently walks away with unused credits.

Rate limiters don't help. They count requests, not behavior. A smart bot sends 29 requests per minute and passes your 30/min limit. A real user uploading 5 resumes during a job search gets blocked.

## The solution

Engram watches **behavior**, not requests.

A real user has an account age, a payment history, a browsing pattern. A bot has a 0-day account doing 15 uploads per hour with no user agent.

Engram classifies the behavior shape. Stores the decision. Next request with the same shape — decision served from cache. No classification needed.

**One brain call teaches. The pattern store remembers.**

| What | How long | Cost |
|------|----------|------|
| First request from a new behavior shape | ~100ms | ~$0 |
| Every request after that with same shape | <1ms | $0 |

## What happens to different users

| User | Engram sees | Decision | Your LLM called? |
|------|-------------|----------|-------------------|
| Real user, 30 days old, 2 uploads today | Normal behavior | **allow** | Yes |
| Bot, 0 days old, 15 uploads this hour | Burst velocity + no UA | **fraud** (403) | No |
| Scraper, fake Chrome UA, 8 uploads/hr | Young account + high velocity | **fraud** (403) | No |
| Paid user, inactive 20 days, has credits | Idle with unspent credits | **churn_risk** | Yes (+ team notified) |

Bots never reach your database. Fraudsters never call your LLM. Real users never notice Engram exists.

## Install (3 steps)

**Step 1.** Paste [`supabase/install.sql`](supabase/install.sql) into your Supabase SQL Editor. Run it.

**Step 2.** Go to Settings → API → Exposed schemas → add `engram`.

**Step 3.** Verify:

```sql
select engram.classify('{"account_age_days":0,"uploads_last_hour":15,"ua_class":"missing"}'::jsonb);
-- → {"decision":"fraud","confidence":0.95}
```

Done. No new infrastructure. No code changes. Uses your existing Postgres.

## Use it

```sql
-- Classify a request
select engram.classify('{"account_age_days":45,"ua_class":"browser"}'::jsonb);

-- Full flow: check cache → classify → learn → return
select engram.decide('{"account_age_days":45,"ua_class":"browser"}'::jsonb, 'my_app');

-- See everything Engram has learned
select engram.dashboard();

-- List all patterns, all visits, all flagged users
select engram.list_patterns();
select engram.list_visits(null, 'fraud', 20);
select engram.list_churn_queue();
```

## Use it in Node.js

```typescript
import { withEngram } from './lib/engram'

export const POST = withEngram(async (request) => {
  // Bots and fraudsters never reach this line.
  // Engram already returned 403/429 for them.
  const data = await callYourExpensiveLLM()
  return Response.json(data)
})
```

Fail-open by design. If Supabase is down, your handler runs anyway. Engram never blocks a real user because it crashed.

## How it learns

```
Request 1 (new shape):  classify → learn → return "fraud"
Request 2 (same shape): cache hit → return "fraud" instantly
Request 3 (same shape): cache hit → return "fraud" instantly
...
Request 1000:           still cached. Brain never called again.
```

Patterns get stronger with correct decisions. Wrong decisions weaken them. Below 20% confidence, patterns auto-evict and the brain re-classifies fresh.

## Documentation

**[Read the full docs →](docs.md)**

Covers: all 18 functions, schema reference, classification rules, Node.js integration, security model, retention policies, custom rule examples.

## Links

- **[SCP Protocol](https://github.com/srk0102/SCP)** — body-level pattern caching
- **[Plexa](https://github.com/srk0102/plexa)** — multi-body orchestration
- **[Supabase](https://supabase.com)** — the database Engram runs on

## License

MIT
