// Minimal Express demo using @srk0102/engram v0.2.0.
//
// 1. Start Postgres and export DATABASE_URL.
// 2. npm install @srk0102/engram express pg
// 3. Pull an Ollama model (e.g. `ollama pull llama3.2`) or swap in
//    AnthropicAdapter / OpenAIAdapter.
// 4. node server.js
// 5. curl -H 'x-user-id: alice' 'http://localhost:3000/api/charge?amount=9.99'
//    First call  -> source=brain  (~1s LLM round-trip)
//    Second call -> source=cache  (~4ms)

import express from "express";
import {
  Engram,
  OllamaAdapter,
  bucket,
  bucketEnum,
} from "@srk0102/engram";

const engram = new Engram({
  connectionString: process.env.DATABASE_URL,
  namespace: "express_demo",
});
await engram.connect();
console.log("[engram-demo] connected + migrations applied");

const brain = new OllamaAdapter({ model: "llama3.2" });

const schema = {
  parse(x) {
    const a = x?.action;
    if (a !== "allow" && a !== "review" && a !== "block") {
      throw new Error("bad action: " + JSON.stringify(a));
    }
    return { action: a, reason: typeof x?.reason === "string" ? x.reason : "" };
  },
};

const AMOUNT_EDGES  = [50, 500, 5000];
const AMOUNT_LABELS = ["tiny", "small", "medium", "large"];
const AGE_EDGES     = [1, 30, 365];
const AGE_LABELS    = ["brand_new", "new", "established", "veteran"];
const PAYMENT_METHODS = ["card", "paypal", "bank"];

const classifyCharge = engram.policy({
  brain,
  prompt: (_ctx, i) => `Classify this payment as allow/review/block.
Return ONLY JSON {"action":"allow"|"review"|"block","reason":"short"}.

Signal: ${JSON.stringify(i)}`,
  schema,
  cacheKey: (i) => `charge:${i.amount_b}:${i.age_b}:${i.payment}`,
});

const app = express();
app.use(express.json());

app.get("/api/charge", async (req, res, next) => {
  try {
    const userId = req.header("x-user-id") ?? "anon";
    const amount = Number(req.query.amount ?? 0);
    const account_age_days = Number(req.query.account_age_days ?? 30);
    const payment_method = String(req.query.payment_method ?? "card");

    const decision = await classifyCharge({
      userId,
      amount_b: bucket(amount, AMOUNT_EDGES, AMOUNT_LABELS),
      age_b:    bucket(account_age_days, AGE_EDGES, AGE_LABELS),
      payment:  bucketEnum(payment_method, PAYMENT_METHODS),
    });

    res.json({
      ok: true,
      source: decision.source,
      decision: decision.decision,
      latencyMs: decision.latencyMs,
      hitCount: decision.hitCount,
      cacheKey: decision.cacheKey,
    });
  } catch (err) { next(err); }
});

app.get("/engram/dashboard", async (_req, res) => {
  res.json(await engram.dashboard());
});

app.get("/engram/cache", async (_req, res) => {
  res.json(await engram.listCache({ namespace: "express_demo", limit: 50 }));
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`[engram-demo] http://localhost:${port}`);
  console.log("  try:");
  console.log(`    curl -H 'x-user-id: alice' 'http://localhost:${port}/api/charge?amount=9.99'`);
  console.log(`    curl 'http://localhost:${port}/engram/dashboard'`);
});
