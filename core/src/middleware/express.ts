import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { Engram } from "../engram.js";
import type { Brain, DecideInput, DecideResult, Schema } from "../types.js";

export interface ExpressEngramOptions<TInput, TOutput, TContext = unknown> {
  /**
   * Build the input object from the request. This is what gets passed to
   * prompt() and cacheKey(). Typically contains userId, route, signals.
   */
  buildInput: (req: Request) => TInput;

  /** Brain to use on cache miss. */
  brain: Brain;

  /** Prompt template. */
  prompt: (context: TContext | null, input: TInput) => string;

  /** Schema to validate the brain's response (Zod / Valibot / hand-rolled). */
  schema: Schema<TOutput>;

  /** Key builder: two inputs with the same key share a cache entry. */
  cacheKey: (input: TInput, context: TContext | null) => string;

  /** Optional context builder. Skip to let Engram auto-retrieve by userId. */
  buildContext?: (req: Request) => TContext | null | Promise<TContext | null>;

  /** Optional namespace override. */
  namespace?: string;

  /** Optional eventType to record before deciding. Default: do not record. */
  recordAs?: string;

  /** If set, the hook runs after decide(). Return a Response here to short-circuit. */
  onDecision?: (
    decision: DecideResult<TOutput>,
    req: Request,
    res: Response,
  ) => void | Promise<void>;

  /** If engram itself throws, call next() instead of next(err). Default true. */
  failOpen?: boolean;
}

declare module "express-serve-static-core" {
  interface Request {
    engram?: DecideResult<unknown>;
  }
}

/**
 * Thin middleware. It records an event (optional), calls engram.decide(),
 * attaches the result to req.engram, and calls next(). It does NOT send
 * 403/429 -- the developer decides what each decision shape means.
 */
export function engramExpress<TInput, TOutput, TContext = unknown>(
  engram: Engram,
  opts: ExpressEngramOptions<TInput, TOutput, TContext>,
): RequestHandler {
  const { failOpen = true } = opts;

  return async function engramMiddleware(
    req: Request,
    _res: Response,
    next: NextFunction,
  ): Promise<void> {
    try {
      const input = opts.buildInput(req);
      const ctx = opts.buildContext
        ? await opts.buildContext(req)
        : undefined;

      // Optional event recording.
      if (opts.recordAs) {
        const userId =
          (input as unknown as { userId?: string }).userId ??
          (req as unknown as { user?: { id?: string } }).user?.id;
        if (userId) {
          await engram.record({
            userId,
            eventType: opts.recordAs,
            metadata: { path: req.path, method: req.method },
          });
        }
      }

      const decideInput: DecideInput<TInput, TOutput, TContext> = {
        input,
        brain: opts.brain,
        prompt: opts.prompt,
        schema: opts.schema,
        cacheKey: opts.cacheKey,
        namespace: opts.namespace,
      };
      if (ctx !== undefined) decideInput.context = ctx ?? undefined;

      const decision = await engram.decide(decideInput);
      req.engram = decision as DecideResult<unknown>;

      if (opts.onDecision) {
        await opts.onDecision(decision, req, _res);
        if (_res.headersSent) return;
      }
      next();
    } catch (err) {
      if (failOpen) next();
      else next(err as Error);
    }
  };
}
