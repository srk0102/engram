<p align="center">
  <img src="engram-svgrepo-com.svg" width="120" height="120" alt="Engram"/>
</p>

<h1 align="center">Engram</h1>

<p align="center">
  Pattern-cached LLM decisions on Postgres.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@srk0102/engram"><img src="https://img.shields.io/npm/v/@srk0102/engram?color=059669&label=npm" alt="npm"/></a>
  <a href="https://github.com/srk0102/engram"><img src="https://img.shields.io/badge/tests-34%20passing-059669" alt="tests"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-059669" alt="license"/></a>
  <a href="https://github.com/srk0102/SCP"><img src="https://img.shields.io/badge/built_on-scp--protocol-4F46E5" alt="scp"/></a>
</p>

---

## What it is

You have an LLM judging per-request decisions (fraud, abuse, anomaly, routing, you name it). You don't want to pay for the LLM every single request forever. Engram is a Postgres-backed cache that sits in front of the call — first time it sees a shape of input, the LLM runs; every repeat reuses the decision in milliseconds.

- **Bring your own brain** — any LLM (Ollama, Anthropic, OpenAI) or a plain function
- **Bring your own schema** — Zod, Valibot, hand-rolled, anything with `.parse()`
- **Bring your own `cacheKey`** — coarsen signals however fits your domain
- Engram handles storage, retrieval, cache lookup, confidence decay, and cross-framework sharing

This repo ships **two products** from the same idea:

| Product | Path | Purpose |
|---|---|---|
| **npm package `@srk0102/engram`** | [`core/`](core) | Any Node.js backend (Express / Fastify / anything) on any Postgres. v0.2.0, published. |
| **Supabase SQL extension** | [`supabase/`](supabase) | Paste-into-SQL-Editor for Supabase users. v1.0.2. |

---

## Install the npm package

```bash
npm install @srk0102/engram pg
```

```ts
import { Engram, OllamaAdapter, bucket, bucketEnum } from "@srk0102/engram";
import { z } from "zod";

const engram = new Engram({
  connectionString: process.env.DATABASE_URL,
  namespace: "my_app",
});
await engram.connect(); // runs migrations idempotently

const classify = engram.policy({
  brain: new OllamaAdapter({ model: "llama3.2" }),
  prompt: (_ctx, i) =>
    `Classify ${JSON.stringify(i)} as JSON {"action":"allow"|"block"}`,
  schema: z.object({ action: z.enum(["allow", "block"]) }),
  cacheKey: (i) =>
    `charge:${bucket(i.amount, [50, 500, 5000], ["tiny","small","medium","large"])}`,
});

const r1 = await classify({ amount: 9.99 });   // source: "brain"  (~1s)
const r2 = await classify({ amount: 8.50 });   // source: "cache" (~4ms)  same bucket
```

Express and Fastify middleware ship as subpath exports:

```ts
import { engramExpress } from "@srk0102/engram/express";
import { engramFastify } from "@srk0102/engram/fastify";
```

**[Full docs for the npm package →](core/README.md)**
**[Honest developer-experience notes →](core/DEVELOPER_EXPERIENCE.md)**

---

## Install the Supabase SQL extension

```sql
-- Enable pg_tle (one time per project)
create extension if not exists pg_tle;

-- Register Engram (paste supabase/tle-register.sql in SQL Editor), then:
create extension engram;
```

Or paste [`supabase/install.sql`](supabase/install.sql) directly into your SQL Editor and run it.

**[Full docs for the Supabase extension →](docs.md)**

---

## How it learns

```
Request 1 (new shape):    brain runs  → learned decision stored under cacheKey
Request 2 (same shape):   cache hit   → ~4ms, no LLM call
Request 3 (same shape):   cache hit   → ~4ms
...
Request 10000:            still cached. Brain never called again for this shape.
```

`feedback(cacheId, wasCorrect)` raises or lowers the cached decision's confidence. Below 0.2, patterns auto-evict and the next request re-asks the brain.

---

## Links

- **npm:** https://www.npmjs.com/package/@srk0102/engram
- **[SCP Protocol](https://github.com/srk0102/SCP)** — body-level pattern caching
- **[Plexa](https://github.com/srk0102/plexa)** — multi-body orchestration

## Contributing

**[Read the contributing guide →](CONTRIBUTING.md)**

## License

[MIT](LICENSE)
