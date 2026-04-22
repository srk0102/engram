import { describe, test, expect } from "vitest";
import type { Engram } from "../../src/engram.js";
import type { PolicyOptions } from "../../src/engram.js";

/**
 * The policy() factory is a tiny forwarder that captures opts and calls
 * engram.decide(). We test it by building a minimal fake Engram that
 * records what was passed into decide().
 */

interface Captured {
  args?: unknown;
}

function fakeEngram(captured: Captured): Engram {
  return {
    async decide(args: unknown) {
      captured.args = args;
      return {
        decision: { ok: true },
        source: "cache",
        cacheId: "x",
        cacheKey: "k",
        confidence: 1,
        hitCount: 1,
        latencyMs: 0,
      } as any;
    },
    // unused
    policy(this: any, opts: any) {
      return async (input: any, context?: any) => {
        const a: any = {
          input,
          brain: opts.brain,
          prompt: opts.prompt,
          schema: opts.schema,
          cacheKey: opts.cacheKey,
        };
        if (opts.namespace !== undefined) a.namespace = opts.namespace;
        if (opts.cacheThreshold !== undefined) a.cacheThreshold = opts.cacheThreshold;
        if (opts.autoContext !== undefined) a.autoContext = opts.autoContext;
        if (opts.brainOptions !== undefined) a.brainOptions = opts.brainOptions;
        if (context !== undefined) a.context = context;
        return this.decide(a);
      };
    },
  } as unknown as Engram;
}

describe("engram.policy()", () => {
  const baseOpts: PolicyOptions<{ x: number }, { ok: boolean }, unknown> = {
    brain: { async call() { return "{}"; } },
    prompt: () => "p",
    schema: { parse: () => ({ ok: true }) },
    cacheKey: (i) => `k:${i.x}`,
  };

  test("binds brain/prompt/schema/cacheKey; input-only call site", async () => {
    const captured: Captured = {};
    const engram = fakeEngram(captured);
    const fn = engram.policy(baseOpts);
    await fn({ x: 1 });
    expect(captured.args).toMatchObject({
      input: { x: 1 },
      brain: baseOpts.brain,
      prompt: baseOpts.prompt,
      schema: baseOpts.schema,
      cacheKey: baseOpts.cacheKey,
    });
    expect((captured.args as any).context).toBeUndefined();
  });

  test("forwards namespace / cacheThreshold / autoContext / brainOptions", async () => {
    const captured: Captured = {};
    const engram = fakeEngram(captured);
    const fn = engram.policy({
      ...baseOpts,
      namespace: "ns1",
      cacheThreshold: 0.7,
      autoContext: false,
      brainOptions: { temperature: 0.2 },
    });
    await fn({ x: 2 });
    expect(captured.args).toMatchObject({
      namespace: "ns1",
      cacheThreshold: 0.7,
      autoContext: false,
      brainOptions: { temperature: 0.2 },
    });
  });

  test("accepts an explicit context override", async () => {
    const captured: Captured = {};
    const engram = fakeEngram(captured);
    const fn = engram.policy(baseOpts);
    await fn({ x: 3 }, { extra: "ctx" });
    expect((captured.args as any).context).toEqual({ extra: "ctx" });
  });
});
