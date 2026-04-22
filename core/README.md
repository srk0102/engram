# @srk0102/engram

**Primitives for pattern-cached LLM decisions on Postgres.**

You bring the brain, the prompt, the schema, and the cache key.
Engram gives you storage, retrieval, and caching on any Postgres.

No opinions on what "allow" or "block" means. No hardcoded decision enum.
No middleware that sends 403s behind your back. Just four functions and
a migrator.

```
record()    feed any signal
retrieve()  pull context fast
decide()    cacheKey hit -> return; miss -> brain -> validate -> store
feedback()  raise or lower a cached decision's confidence
```

---

## Install

```bash
npm install @srk0102/engram pg
```

`pg` is a peer dependency so your app controls the driver version.

---

## 60-second example (Ollama)

```ts
import { Engram, OllamaAdapter } from "@srk0102/engram";

const engram = new Engram({
  connectionString: process.env.DATABASE_URL,
  namespace: "my_app",
});
await engram.connect(); // runs migrations idempotently

const brain = new OllamaAdapter({ model: "llama3.2" });

const schema = {
  parse(x: unknown) {
    const o = x as { action?: string };
    if (o?.action !== "allow" && o?.action !== "block") throw new Error("bad");
    return { action: o.action };
  },
};

const result = await engram.decide({
  input: { userId: "u_1", route: "/api/charge", amount: 9.99 },
  brain,
  prompt: (_ctx, i) =>
    `Classify this API call. Return JSON {"action":"allow"|"block"}.\n${JSON.stringify(i)}`,
  schema,
  cacheKey: (i) => `${i.route}:${i.amount < 100 ? "small" : "big"}`,
});

// result.source === "brain"  on first call (slow, calls Ollama)
// result.source === "cache"  on second call (fast, no LLM)
```

Two calls with the same `cacheKey` hit the same cache row in the same
namespace. That's the whole trick.

---

## The four primitives

### `record(input)`

Append an event. Cheap, append-only. Used later by `retrieve()`.

```ts
await engram.record({
  userId: "u_1",
  eventType: "api_call",
  metadata: { path: "/charge", status: 200 },
  sessionId: "sess_abc",      // optional
  ipRegion: "us-west",        // optional
  uaClass: "browser",         // optional
});
```

### `retrieve(input)`

Pull recent events for a user, optionally with a rolling summary.

```ts
const ctx = await engram.retrieve({
  userId: "u_1",
  lookback: "7d",             // or ms number
  eventTypes: ["api_call"],   // optional filter
  limit: 200,
  aggregate: true,            // include per-event-type summary
});
// ctx.events   -> raw rows
// ctx.summary  -> { api_call: { count, avg_per_day, first_seen, ... } }
```

### `decide(input)`

The full loop: lookup by `cacheKey` first; on a miss, call the brain,
validate with the schema, and store the result under the cacheKey.

```ts
const r = await engram.decide({
  input: { userId, route, amount },
  brain,                          // any Brain
  prompt: (ctx, input) => "...",  // returns string
  schema,                         // any { parse(unknown): T }
  cacheKey: (input, ctx) => "..." // returns string
  // optional:
  namespace: "other_app",         // override instance default
  cacheThreshold: 0.5,            // min confidence for a hit
  context: customCtx,             // skip auto-retrieve
  autoContext: false,             // disable auto-retrieve
  brainOptions: { maxTokens: 256, temperature: 0 },
});
// -> { decision, source: "cache" | "brain", cacheId, cacheKey,
//      confidence, hitCount, latencyMs }
```

Auto-context: when `input.userId` is a string and you don't pass
`context`, engram calls `retrieve({ userId, lookback: "30d" })` for you
and hands that to `prompt()`.

### `feedback(cacheId, wasCorrect)`

Raise or lower a cached decision's confidence. Decisions below 0.2 get
evicted. No external ML, just a confidence decay/reward scheme.

```ts
await engram.feedback(r.cacheId, true);   // worked as expected
await engram.feedback(r.cacheId, false);  // false positive/wrong
```

---

## Bring your own schema

Any object with `.parse(unknown) => T` is accepted. This means Zod,
Valibot, Yup, or a hand-rolled validator all work with no adapter.

```ts
// Zod
import { z } from "zod";
const schema = z.object({ action: z.enum(["allow", "block", "review"]) });

// Hand-rolled
const schema = {
  parse(x: unknown) {
    if (typeof (x as any)?.action !== "string") throw new Error("bad");
    return x as { action: string };
  },
};
```

The validated value is what gets cached, so next time it comes out of
cache already shaped correctly — no re-parsing cost on hits.

---

## Bring your own brain

A `Brain` is anything with `call(prompt, opts?) => Promise<string>`.
Three adapters ship in the package:

```ts
import { OllamaAdapter, AnthropicAdapter, OpenAIAdapter } from "@srk0102/engram";

const local  = new OllamaAdapter({ model: "llama3.2" });
const claude = new AnthropicAdapter({
  model: "claude-haiku-4-5",
  // apiKey: "...",  // or ANTHROPIC_API_KEY env
});
const gpt    = new OpenAIAdapter({
  model: "gpt-4o-mini",
  // apiKey: "...",  // or OPENAI_API_KEY env
  jsonMode: true,   // default, forces response_format json_object
});
```

Point `OpenAIAdapter.url` at any OpenAI-compatible server (vLLM, Groq,
LM Studio, OpenRouter, Azure) and it works.

Or just pass a function:

```ts
const brain = { async call(prompt: string) { return '{"action":"allow"}'; } };
```

---

## Express middleware

Unopinionated: it attaches the decision to `req.engram` and calls
`next()`. **It does not send 403 or 429 for you.** The route handler
or the `onDecision` hook owns the response.

```ts
import express from "express";
import { Engram, OllamaAdapter } from "@srk0102/engram";

const app = express();
const engram = new Engram({ connectionString: process.env.DATABASE_URL });
await engram.connect();

app.use(engram.express({
  buildInput: (req) => ({
    userId: req.headers["x-user-id"] as string,
    route: req.path,
    method: req.method,
  }),
  brain: new OllamaAdapter({ model: "llama3.2" }),
  prompt: (_ctx, i) => `Classify ${JSON.stringify(i)} as JSON {"action":"..."}`,
  schema: /* your schema */,
  cacheKey: (i) => `${i.route}:${i.method}`,
  recordAs: "api_call",       // optional: records an event first
  onDecision: (d, _req, res) => {
    if ((d.decision as any).action === "block") {
      res.status(403).json({ error: "blocked" });
    }
  },
  failOpen: true,             // default: on engram error, call next()
}));

app.get("/charge", (req, res) => {
  // req.engram is populated with the decision + metadata
  res.json({ ok: true, via: req.engram?.source });
});
```

Import from the subpath to skip bundling the Engram class if you
already have an instance:

```ts
import { engramExpress } from "@srk0102/engram/express";
app.use(engramExpress(engram, { /* options */ }));
```

---

## Fastify middleware

Same shape as the Express one. It's a `preHandler` that attaches
`req.engram` and returns. If your `onDecision` hook calls
`reply.code(...).send(...)`, the handler short-circuits.

```ts
import Fastify from "fastify";
import { Engram, OllamaAdapter } from "@srk0102/engram";
import { engramFastify } from "@srk0102/engram/fastify";

const app = Fastify();
const engram = new Engram({ connectionString: process.env.DATABASE_URL });
await engram.connect();

app.addHook("preHandler", engramFastify(engram, {
  buildInput: (req) => ({
    userId: req.headers["x-user-id"] as string,
    route: req.url,
    method: req.method,
  }),
  brain: new OllamaAdapter({ model: "llama3.2" }),
  prompt: (_ctx, i) => `Classify ${JSON.stringify(i)} as JSON {"action":"..."}`,
  schema: /* your schema */,
  cacheKey: (i) => `${i.route}:${i.method}`,
}));

app.get("/charge", (req, reply) => {
  reply.send({ ok: true, via: req.engram?.source });
});
```

---

## CacheKey helpers

`cacheKey` is the load-bearing function of the whole library. Get it wrong
and every request pays the LLM cost. These helpers turn continuous /
free-form signals into stable coarse labels that cluster similar inputs.

```ts
import { bucket, bucketEnum } from "@srk0102/engram";

const AMOUNT_EDGES  = [50, 500, 5000] as const;
const AMOUNT_LABELS = ["tiny", "small", "medium", "large"] as const;

const AGE_EDGES     = [1, 30, 365] as const;
const AGE_LABELS    = ["brand_new", "new", "established", "veteran"] as const;

const PAYMENT_METHODS = ["card", "paypal", "bank"] as const;

function checkoutKey(i: {
  amount: number; account_age_days: number;
  payment_method: string; device_type: string;
}) {
  return [
    "checkout",
    bucket(i.amount, AMOUNT_EDGES, AMOUNT_LABELS),
    bucket(i.account_age_days, AGE_EDGES, AGE_LABELS),
    bucketEnum(i.payment_method, PAYMENT_METHODS),  // unknown -> "other"
    i.device_type,
  ].join(":");
}

checkoutKey({ amount: 9.99,  account_age_days: 800, payment_method: "card",   device_type: "web" });
// -> "checkout:tiny:veteran:card:web"
checkoutKey({ amount: 8.50,  account_age_days: 820, payment_method: "card",   device_type: "web" });
// -> "checkout:tiny:veteran:card:web"   (same row -- shared LLM decision)
checkoutKey({ amount: 6500,  account_age_days: 0,   payment_method: "crypto", device_type: "mobile" });
// -> "checkout:large:brand_new:other:mobile"
```

`bucket()` is `(value, edges, labels) => label`. `labels.length` must be
`edges.length + 1`. `bucketEnum()` is `(value, allowed, fallback?) =>
label` — snaps unknown values to `"other"` (or any fallback you pass).

---

## Bound policies (skip the 5-arg call site)

Rebinding `brain + prompt + schema + cacheKey` on every `decide()` call
gets old. `engram.policy()` captures them once and returns a function
that takes only `input` (and an optional `context`).

```ts
const classifyCheckout = engram.policy({
  brain: new OllamaAdapter({ model: "llama3.2" }),
  prompt: (_ctx, i) => `... ${JSON.stringify(i)}`,
  schema: /* ... */,
  cacheKey: checkoutKey,
  namespace: "billing",     // all options from decide() are accepted here
});

// Everywhere else, the call site is just (input):
const r = await classifyCheckout({ userId, amount: 9.99, account_age_days: 800, ... });
// -> { decision, source: "cache" | "brain", cacheId, ... }

// Override context for a single call:
const r2 = await classifyCheckout(input, preBuiltContext);
```

---

## Debugging a wrong decision

Set `ENGRAM_DEBUG=true` before your process starts. Engram will log the
prompt it sent, the raw brain response, and the string `extractJson` is
parsing. Use this when the LLM emits junk you didn't expect or the schema
parser throws.

```bash
ENGRAM_DEBUG=true node server.js
```

```
[engram.debug] prompt sent to brain:
Classify this API call ...
[engram.debug] raw brain response:
<|channel>thought...<channel|>{"action":"allow"}
[engram.debug] extractJson cleaned input:
{"action":"allow"}
```

For a known-bad cache entry, evict it:

```ts
await engram.feedback(cacheId, false);   // decays confidence
await engram.feedback(cacheId, false);   // drops below 0.2 -> evicted

// or the hammer:
await pool.query("delete from engram.cache where id = $1", [cacheId]);
```

---

## Cold-start warning

The first LLM call after a model is loaded into memory is slow, because
the model loads before it runs. The numbers we saw for `gemma4:e4b` on an
RTX 5060 Ti 16GB with Docker GPU passthrough:

| situation | latency |
|---|---|
| First call, model not in VRAM | ~120 seconds |
| Second call, model warm | ~1.2 seconds |
| Cache hit after brain miss | ~4 ms |

The warm-call latency is what your users actually feel on a miss. The
cold-start hits only the very first request after a server boot or a
model swap. Three ways to avoid waking up the first user with a 2-minute
wait:

**1. Pre-load at Ollama start.** Tell Ollama which model to keep hot:

```yaml
# docker-compose.yml
ollama:
  image: ollama/ollama:latest
  environment:
    OLLAMA_PRELOAD_MODELS: gemma4:e4b
    OLLAMA_KEEP_ALIVE: "24h"   # keep model loaded between requests
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: all
            capabilities: [gpu]
```

**2. Warm-up health check.** Have your app hit the model once on startup
before accepting traffic, so the first real request is already warm:

```yaml
# docker-compose.yml
ollama:
  healthcheck:
    test: ["CMD-SHELL", "curl -fsS -X POST http://localhost:11434/api/generate -d '{\"model\":\"gemma4:e4b\",\"prompt\":\"ok\",\"stream\":false}' || exit 1"]
    interval: 10s
    timeout: 180s   # generous for the initial model load
    retries: 3
    start_period: 180s
```

**3. Skip the cold-start entirely.** For production, point the brain at a
hosted Anthropic / OpenAI endpoint — no model loading, consistent
per-request latency.

---

## Configuration

```ts
new Engram({
  connectionString: "postgresql://...",
  // OR:
  pool: existingPgPool,
  namespace: "my_app",    // default "default"
  autoMigrate: true,      // default true
  logger: (m, meta) => console.log(m, meta),
});
```

- If you pass a `pool`, engram borrows it and does **not** close it.
- If you pass a `connectionString`, engram creates the pool and will
  close it on `engram.close()`.
- Migrations live in the package's `migrations/` directory. Each file
  is hashed; drift between your DB and the shipped file throws
  `EngramMigrationDriftError` on `connect()`.

---

## Observability

```ts
await engram.stats();       // { total_cached, avg_confidence, total_hits }
await engram.listCache({ namespace: "my_app", limit: 50 });
await engram.dashboard();   // all-in-one snapshot
await engram.userBaseline("u_1");
await engram.detectAnomaly("u_1", { api_call: 80 });
```

---

## What Engram is not

- Not a bot-detection product. There is no `classify()`, no built-in
  fraud heuristics, no hardcoded decision types.
- Not an LLM framework. No chains, no agents, no tools.
- Not a rate-limiter. Decide returns whatever your brain returned;
  you decide what it means.

It is a durable, typed cache keyed on developer-supplied strings,
sitting in front of an LLM call, on Postgres.

---

## License

MIT
