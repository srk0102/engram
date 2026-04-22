# @srk0102/engram — Developer Experience (honest read)

This is a candid self-audit written after building three real demos against the packed tarball. It's here so you don't have to guess what's smooth and what's rough before you install.

---

## "I installed @srk0102/engram. Now what?"

You need three things before `decide()` works:

1. **A Postgres connection.** Any Postgres 14+. Local docker works. Engram runs its own migrations on `connect()` inside an `engram` schema — no manual SQL.
2. **A brain.** Any object with `async call(prompt, opts?) => string`. We ship `OllamaAdapter`, `AnthropicAdapter`, `OpenAIAdapter`. Ollama is free-and-local (`ollama pull llama3.2`).
3. **A decision schema.** Anything with `.parse(unknown) => T`. Zod works out of the box. So does `{ parse: (x) => /* ... */ }`.

A full bootstrap is ~10 lines:

```ts
const engram = new Engram({ connectionString: process.env.DATABASE_URL });
await engram.connect();
const brain = new OllamaAdapter({ model: "llama3.2" });
const schema = z.object({ action: z.enum(["allow","block","review"]) });
```

There is no free default for brain, prompt, schema, or cacheKey. You provide all four on every `decide()` call. This is the whole point — but it means "hello world" is not a one-liner.

## "What do I pass to decide()?"

Five required things:

| field | type | you provide |
|---|---|---|
| `input` | anything | the "thing being decided about" |
| `brain` | `Brain` | the LLM |
| `prompt` | `(ctx, input) => string` | how to ask |
| `schema` | `Schema<T>` | how to validate the reply |
| `cacheKey` | `(input, ctx) => string` | **the most important one** |

Plus optional: `context`, `namespace`, `cacheThreshold`, `autoContext`, `brainOptions`.

**`cacheKey` is load-bearing.** Get it wrong and either:
- Too narrow (e.g. raw amount) → every request is a cache miss, LLM is called every time. Engram degrades into an expensive proxy.
- Too wide (e.g. just `"/charge"`) → a decision for a $5 coffee gets served to a $50k wire transfer.

There is no helper for writing good cacheKeys today. The demos show the "bucket the numeric signals, leave categoricals raw" pattern. That's it. A `cacheKey` utility for bucketing is a known gap.

## "What does the output look like?"

```ts
{
  decision: { action: "allow", reason: "..." },   // the typed T from schema
  source: "cache" | "brain",
  cacheId: "md5ish",
  cacheKey: "ecom:tiny:veteran:card:web",
  confidence: 0.5,
  hitCount: 2,
  latencyMs: 4.1
}
```

`source` is the thing you actually watch. First call = `brain`, repeat = `cache`. That's the whole value proposition on one field.

## "How do I know it is working?"

Three signals:

1. Call the same `cacheKey` twice. First → `source: "brain"`, second → `source: "cache"`. If it isn't, your `cacheKey` is non-deterministic (common: using `Date.now()` or an unsorted object in the key).
2. `await engram.listCache({ namespace, limit: 50 })` — the rows are the truth.
3. `await engram.stats()` — total cached, avg confidence, total hits.

## "What happens when I redeploy?"

- Migrations run on every `connect()` via sha256 hashes. Already-applied files are skipped. **If the files in your installed package drift from the rows in `engram.migrations`, connect throws `EngramMigrationDriftError`.**
- Cache rows survive redeploys (they're Postgres rows).
- If you pass a `connectionString`, engram owns the pool and closes it on `engram.close()`.
- If you pass an existing `pool`, engram borrows it and does not close it.

**Rough edge:** the drift error tells you what mismatched, but not "what to do." In dev the fix is `DROP SCHEMA engram CASCADE`. We don't say this in the error message. It's an obvious TODO.

## "How do I debug a wrong decision?"

This is the roughest part today. Your tools:

- **Inspect:** `await engram.listCache({ namespace })` shows all cached decisions with their keys.
- **Correct via feedback:** `await engram.feedback(cacheId, false)` decays confidence. Two false feedbacks typically evict. Numbers live in SQL (`engram.feedback` function) and are not yet documented.
- **Nuke a row:** `delete from engram.cache where id = '...'`. No sugar for this yet.
- **Re-ask the brain:** there is no `decide({ skipCache: true })` option. You can drop the row then call again. Or change the cacheKey to force a new lookup.

What's missing, honestly:
- No "dry run" mode (call brain but don't store).
- No way to see what `prompt()` produced for a given cache row (the raw prompt isn't stored, only the decision).
- No structured log of brain attempts that failed `schema.parse()` (they just throw).

## "How do I fix a wrong cached pattern?"

Today, two paths:

```ts
await engram.feedback(cacheId, false);   // polite
await engram.feedback(cacheId, false);   // below 0.2 -> evicted

// or the hammer:
await pool.query("delete from engram.cache where id = $1", [cacheId]);
```

For bulk corrections (e.g. "every 'block' in the `free` plan bucket is wrong because policy changed"), you are writing raw SQL. A `engram.evictWhere({ predicate })` helper is not here yet.

---

## What's genuinely smooth

- **Install + connect is ~3 lines**, migrations are automatic, no hand-written SQL.
- **Bring-your-own-everything.** Any LLM (adapter or callback), any validator (Zod/Valibot/hand-rolled), any Postgres. No hard dependency beyond `pg`.
- **The middleware doesn't lie.** It attaches `req.engram = decision` and calls `next()`. It doesn't send 403 behind your back. You get a real cache-source receipt on every request and decide what it means in your handler.
- **Cache hits are fast.** ~4ms including SQL lookup + schema.parse. The network ride is often the bottleneck after that.
- **Namespaces work.** Two services sharing a DB can share (one namespace) or isolate (two namespaces) with a single config string.

## What's genuinely rough

1. **No cacheKey helpers.** Bucketing is the whole trick and you write it from scratch every time. A standard `bucket(value, edges)` export and a `keyOf({ a, b, c })` helper would cut demo code by 30%.
2. **Migration drift error lacks a fix hint.** In dev, the right answer is `DROP SCHEMA engram CASCADE`. Say so in the error.
3. **Brain/prompt/schema/cacheKey on every call is verbose.** A higher-level `engram.policy({ ... })` factory that binds the four once and returns `(input) => Promise<decision>` would kill a lot of repetition.
4. **No Fastify / Hono / Nest middleware yet.** Only Express.
5. **No CLI.** `engram migrate` / `engram reset` would help in CI.
6. **Feedback curve is opaque.** We claim confidence decay at 0.5 → 0.2 but that's inside SQL. It should be documented and ideally configurable.
7. **`extractJson()` swallows too much.** It tolerates code fences, prose, partial JSON. Good for robustness; bad because you cannot tell from the return value that the LLM emitted junk. A `debug: true` option that logs the raw brain response before parsing would help a lot.
8. **Auto-context trigger is a hidden rule** ("triggers when `input.userId` is a string and `context` is absent"). It's documented but easy to miss.
9. **No per-namespace or per-cacheKey expiry.** `cache.expires_at` exists in the schema but nothing writes to it yet.
10. **Observability is the four functions above (stats, listCache, dashboard, userBaseline) — no Prometheus metrics, no OTel spans.** Nothing stops you from wrapping manually, but nothing helps either.

## Should you use it today?

- **Yes** if: you have a Postgres already, you already use LLMs for per-request classification, and the cache-miss cost is what's hurting you.
- **Not yet** if: you need multi-framework support beyond Express, a CLI, or polished debugging tools today. Those are on the roadmap but not in `0.2.0`.

If the rough edges above feel like table stakes for your team — wait a release. If they feel like things you'd happily solve yourself in exchange for the unopinionated core — ship it.
