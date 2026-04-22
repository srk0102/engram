import type { FastifyReply, FastifyRequest } from "fastify";
import type { Engram } from "../engram.js";
import type { Brain, DecideInput, DecideResult, Schema } from "../types.js";

export interface FastifyEngramOptions<TInput, TOutput, TContext = unknown> {
  /** Build the input object from the request. */
  buildInput: (req: FastifyRequest) => TInput;

  /** Brain to use on cache miss. */
  brain: Brain;

  /** Prompt template. */
  prompt: (context: TContext | null, input: TInput) => string;

  /** Validator for the brain's response. */
  schema: Schema<TOutput>;

  /** Key builder: two inputs with the same key share a cache entry. */
  cacheKey: (input: TInput, context: TContext | null) => string;

  /** Optional context builder. Skip to let Engram auto-retrieve by userId. */
  buildContext?: (req: FastifyRequest) => TContext | null | Promise<TContext | null>;

  /** Optional namespace override. */
  namespace?: string;

  /** Optional eventType to record before deciding. Default: do not record. */
  recordAs?: string;

  /**
   * If set, runs after decide(). If this hook sends a reply (e.g.
   * `reply.code(403).send(...)`), the handler short-circuits.
   */
  onDecision?: (
    decision: DecideResult<TOutput>,
    req: FastifyRequest,
    reply: FastifyReply,
  ) => void | Promise<void>;

  /** If engram itself throws, swallow and continue. Default true. */
  failOpen?: boolean;
}

declare module "fastify" {
  interface FastifyRequest {
    engram?: DecideResult<unknown>;
  }
}

/**
 * Fastify preHandler. Attaches the decision to `req.engram` and returns.
 * Does NOT send 403/429 -- the developer's route (or the `onDecision`
 * hook) owns the response.
 *
 * @example
 *   fastify.addHook('preHandler', engramFastify(engram, { ... }));
 */
export function engramFastify<TInput, TOutput, TContext = unknown>(
  engram: Engram,
  opts: FastifyEngramOptions<TInput, TOutput, TContext>,
) {
  const { failOpen = true } = opts;

  return async function engramPreHandler(
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    try {
      const input = opts.buildInput(req);
      const ctx = opts.buildContext
        ? await opts.buildContext(req)
        : undefined;

      if (opts.recordAs) {
        const userId =
          (input as unknown as { userId?: string }).userId ??
          (req as unknown as { user?: { id?: string } }).user?.id;
        if (userId) {
          await engram.record({
            userId,
            eventType: opts.recordAs,
            metadata: { path: req.url, method: req.method },
          });
        }
      }

      const decideInput: DecideInput<TInput, TOutput, TContext> = {
        input,
        brain: opts.brain,
        prompt: opts.prompt,
        schema: opts.schema,
        cacheKey: opts.cacheKey,
      };
      if (opts.namespace !== undefined) decideInput.namespace = opts.namespace;
      if (ctx !== undefined) decideInput.context = ctx ?? undefined;

      const decision = await engram.decide(decideInput);
      req.engram = decision as DecideResult<unknown>;

      if (opts.onDecision) {
        await opts.onDecision(decision, req, reply);
        if (reply.sent) return;
      }
    } catch (err) {
      if (!failOpen) throw err;
    }
  };
}
