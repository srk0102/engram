import { describe, test, expect } from "vitest";
import { engramExpress } from "../../src/middleware/express.js";
import type { Engram } from "../../src/engram.js";
import type { Brain, DecideInput, DecideResult, Schema } from "../../src/types.js";

/**
 * Fake Engram via duck-typing so these tests stay hermetic (no DB needed).
 * v0.2.0 middleware is a thin wrapper: it calls engram.decide() and attaches
 * the result to req.engram. It does NOT auto-block on any particular shape.
 */
function fakeEngram(override: {
  decide?: (input: DecideInput<any, any, any>) => Promise<DecideResult<any>>;
  record?: () => Promise<void>;
}): Engram {
  return {
    decide: override.decide ?? (async () => okDecision("allow")),
    record: override.record ?? (async () => {}),
  } as unknown as Engram;
}

function okDecision(action: string, source: "cache" | "brain" = "brain"): DecideResult<{ action: string }> {
  return {
    decision: { action },
    source,
    cacheId: "id1",
    cacheKey: "k1",
    confidence: 0.85,
    hitCount: 1,
    latencyMs: 1.2,
  };
}

interface FakeRes {
  statusCode?: number;
  body?: unknown;
  headersSent: boolean;
  status(n: number): FakeRes;
  json(b: unknown): FakeRes;
  setHeader(k: string, v: string): FakeRes;
}
function fakeRes(): FakeRes {
  const r: FakeRes = {
    headersSent: false,
    status(n) { r.statusCode = n; return r; },
    json(b)   { r.body = b; r.headersSent = true; return r; },
    setHeader(_k, _v) { return r; },
  };
  return r;
}
function fakeReq(userId: string | null = "u1") {
  return {
    path: "/api/test",
    method: "GET",
    headers: userId ? { "x-user-id": userId } : {},
  } as any;
}

const noopBrain: Brain = { call: async () => "{}" };
const passthroughSchema: Schema<{ action: string }> = {
  parse: (x) => x as { action: string },
};

describe("engramExpress v0.2.0 middleware", () => {
  test("on success, attaches req.engram and calls next()", async () => {
    const engram = fakeEngram({
      decide: async () => okDecision("allow", "cache"),
    });
    const mw = engramExpress(engram, {
      buildInput: () => ({ userId: "u1" }),
      brain: noopBrain,
      prompt: () => "ignored",
      schema: passthroughSchema,
      cacheKey: () => "k1",
    });

    const req = fakeReq();
    const res = fakeRes();
    let called = false;
    await mw(req, res as any, () => { called = true; });

    expect(called).toBe(true);
    expect(req.engram?.decision).toEqual({ action: "allow" });
    expect(req.engram?.source).toBe("cache");
  });

  test("does NOT auto-send 403/429 -- middleware is unopinionated", async () => {
    const engram = fakeEngram({
      decide: async () => okDecision("block"),
    });
    const mw = engramExpress(engram, {
      buildInput: () => ({ userId: "u1" }),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
    });

    const req = fakeReq();
    const res = fakeRes();
    let called = false;
    await mw(req, res as any, () => { called = true; });

    expect(called).toBe(true);                           // next() was called
    expect(res.statusCode).toBeUndefined();              // no auto response
    expect(req.engram?.decision).toEqual({ action: "block" }); // dev's route handler now sees this and decides what to do
  });

  test("onDecision hook can short-circuit the response", async () => {
    const engram = fakeEngram({
      decide: async () => okDecision("block"),
    });
    const mw = engramExpress(engram, {
      buildInput: () => ({ userId: "u1" }),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
      onDecision: (d, _req, res) => {
        if ((d.decision as { action: string }).action === "block") {
          res.status(403).json({ error: "blocked by onDecision hook" });
        }
      },
    });

    const req = fakeReq();
    const res = fakeRes();
    let called = false;
    await mw(req, res as any, () => { called = true; });

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ error: "blocked by onDecision hook" });
    expect(called).toBe(false);
  });

  test("records an event when recordAs is set and userId resolvable", async () => {
    let recorded: unknown = null;
    const engram = fakeEngram({
      decide: async () => okDecision("allow"),
      record: (async (input: unknown) => { recorded = input; }) as any,
    });
    const mw = engramExpress(engram, {
      buildInput: (req) => ({ userId: req.headers["x-user-id"] as string | undefined }),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
      recordAs: "api_call",
    });

    const req = fakeReq("user_123");
    const res = fakeRes();
    await mw(req, res as any, () => {});

    expect(recorded).toMatchObject({
      userId: "user_123",
      eventType: "api_call",
      metadata: { path: "/api/test", method: "GET" },
    });
  });

  test("failOpen default: engram throws -> next() with no error", async () => {
    const engram = fakeEngram({
      decide: async () => { throw new Error("db down"); },
    });
    const mw = engramExpress(engram, {
      buildInput: () => ({}),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
    });

    let calledWith: unknown = "not_called";
    await mw(fakeReq(), fakeRes() as any, (err?: unknown) => {
      calledWith = err ?? "ok";
    });
    expect(calledWith).toBe("ok");
  });

  test("failOpen: false forwards the error to next(err)", async () => {
    const boom = new Error("db down");
    const engram = fakeEngram({
      decide: async () => { throw boom; },
    });
    const mw = engramExpress(engram, {
      buildInput: () => ({}),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
      failOpen: false,
    });

    let calledWith: unknown = null;
    await mw(fakeReq(), fakeRes() as any, (err?: unknown) => {
      calledWith = err;
    });
    expect(calledWith).toBe(boom);
  });
});
