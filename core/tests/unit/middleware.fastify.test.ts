import { describe, test, expect } from "vitest";
import { engramFastify } from "../../src/middleware/fastify.js";
import type { Engram } from "../../src/engram.js";
import type { Brain, DecideInput, DecideResult, Schema } from "../../src/types.js";

function fakeEngram(override: {
  decide?: (input: DecideInput<any, any, any>) => Promise<DecideResult<any>>;
  record?: (input: any) => Promise<void>;
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

interface FakeReply {
  statusCode?: number;
  payload?: unknown;
  sent: boolean;
  code(n: number): FakeReply;
  send(b: unknown): FakeReply;
  header(k: string, v: string): FakeReply;
}
function fakeReply(): FakeReply {
  const r: FakeReply = {
    sent: false,
    code(n) { r.statusCode = n; return r; },
    send(b) { r.payload = b; r.sent = true; return r; },
    header(_k, _v) { return r; },
  };
  return r;
}
function fakeReq(userId: string | null = "u1") {
  return {
    url: "/api/test",
    method: "GET",
    headers: userId ? { "x-user-id": userId } : {},
  } as any;
}

const noopBrain: Brain = { call: async () => "{}" };
const passthroughSchema: Schema<{ action: string }> = { parse: (x) => x as { action: string } };

describe("engramFastify preHandler", () => {
  test("attaches req.engram and does NOT auto-block", async () => {
    const engram = fakeEngram({ decide: async () => okDecision("block") });
    const handler = engramFastify(engram, {
      buildInput: () => ({ userId: "u1" }),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
    });
    const req = fakeReq();
    const reply = fakeReply();
    await handler(req as any, reply as any);
    expect(req.engram?.decision).toEqual({ action: "block" });
    expect(reply.statusCode).toBeUndefined();
    expect(reply.sent).toBe(false);
  });

  test("onDecision hook can short-circuit via reply.code/send", async () => {
    const engram = fakeEngram({ decide: async () => okDecision("block") });
    const handler = engramFastify(engram, {
      buildInput: () => ({ userId: "u1" }),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
      onDecision: (d, _req, reply) => {
        if ((d.decision as { action: string }).action === "block") {
          reply.code(403).send({ error: "blocked" });
        }
      },
    });
    const req = fakeReq();
    const reply = fakeReply();
    await handler(req as any, reply as any);
    expect(reply.statusCode).toBe(403);
    expect(reply.sent).toBe(true);
    expect(reply.payload).toMatchObject({ error: "blocked" });
  });

  test("records an event when recordAs is set and userId resolvable", async () => {
    let recorded: unknown = null;
    const engram = fakeEngram({
      decide: async () => okDecision("allow"),
      record: async (input: unknown) => { recorded = input; },
    });
    const handler = engramFastify(engram, {
      buildInput: (req) => ({ userId: (req.headers as any)["x-user-id"] as string | undefined }),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
      recordAs: "api_call",
    });
    await handler(fakeReq("user_42") as any, fakeReply() as any);
    expect(recorded).toMatchObject({
      userId: "user_42",
      eventType: "api_call",
      metadata: { path: "/api/test", method: "GET" },
    });
  });

  test("failOpen default: engram throws -> swallow (no rethrow)", async () => {
    const engram = fakeEngram({ decide: async () => { throw new Error("db down"); } });
    const handler = engramFastify(engram, {
      buildInput: () => ({}),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
    });
    await expect(handler(fakeReq() as any, fakeReply() as any)).resolves.toBeUndefined();
  });

  test("failOpen:false rethrows the error", async () => {
    const boom = new Error("db down");
    const engram = fakeEngram({ decide: async () => { throw boom; } });
    const handler = engramFastify(engram, {
      buildInput: () => ({}),
      brain: noopBrain,
      prompt: () => "x",
      schema: passthroughSchema,
      cacheKey: () => "k1",
      failOpen: false,
    });
    await expect(handler(fakeReq() as any, fakeReply() as any)).rejects.toBe(boom);
  });
});
