import pg from "pg";
import { Migrator, type MigrationResult } from "./migrator.js";
import {
  EngramConfigError,
  EngramNotConnectedError,
} from "./errors.js";
import {
  engramExpress,
  type ExpressEngramOptions,
} from "./middleware/express.js";
import type { RequestHandler } from "express";
import type {
  Anomaly,
  Baseline,
  Brain,
  BrainCallOptions,
  CacheEntry,
  Dashboard,
  DecideInput,
  DecideResult,
  EngramConfig,
  Logger,
  RecordEventInput,
  RetrieveInput,
  RetrieveResult,
  Schema,
  StatsSnapshot,
} from "./types.js";

/**
 * Bound decision function returned by {@link Engram.policy}.
 * Takes only the input (and optional context) -- brain/prompt/schema/cacheKey
 * are captured at policy-creation time.
 */
export type PolicyFn<TInput, TOutput, TContext = RetrieveResult> = (
  input: TInput,
  context?: TContext,
) => Promise<DecideResult<TOutput>>;

export interface PolicyOptions<TInput, TOutput, TContext = RetrieveResult> {
  brain: Brain;
  prompt: (context: TContext | null, input: TInput) => string;
  schema: Schema<TOutput>;
  cacheKey: (input: TInput, context: TContext | null) => string;
  namespace?: string;
  cacheThreshold?: number;
  autoContext?: boolean;
  brainOptions?: BrainCallOptions;
}

const { Pool } = pg;

/**
 * Engram v0.2.0 -- a primitives library, not a pipeline.
 *
 * Four functions on the public surface:
 *   record()   -- feed any signal
 *   retrieve() -- get context fast
 *   decide()   -- dev-supplied brain + prompt + schema + cacheKey
 *   feedback() -- confidence decay + eviction
 */
export class Engram {
  private readonly cfg: Required<Pick<EngramConfig, "namespace" | "autoMigrate">> &
    Pick<EngramConfig, "connectionString" | "pool" | "logger">;
  private pool: pg.Pool | null = null;
  private ownsPool = false;
  private connected = false;
  private readonly log: Logger;

  constructor(config: EngramConfig) {
    if (!config.connectionString && !config.pool) {
      throw new EngramConfigError(
        "Engram: either `connectionString` or `pool` must be provided",
      );
    }
    this.cfg = {
      connectionString: config.connectionString,
      pool: config.pool,
      namespace: config.namespace ?? "default",
      autoMigrate: config.autoMigrate ?? true,
      logger: config.logger,
    };
    this.log = config.logger ?? (() => {});
  }

  async connect(): Promise<{ migrations: MigrationResult[] }> {
    if (this.cfg.pool) {
      this.pool = this.cfg.pool;
      this.ownsPool = false;
    } else {
      this.pool = new Pool({ connectionString: this.cfg.connectionString });
      this.ownsPool = true;
    }

    let migrations: MigrationResult[] = [];
    if (this.cfg.autoMigrate) {
      const migrator = new Migrator({ pool: this.pool, logger: this.log });
      migrations = await migrator.run();
    }

    this.connected = true;
    this.log("engram: connected", {
      namespace: this.cfg.namespace,
      migrationsApplied: migrations.filter((m) => m.status === "applied").length,
    });
    return { migrations };
  }

  async close(): Promise<void> {
    if (this.pool && this.ownsPool) await this.pool.end();
    this.pool = null;
    this.connected = false;
  }

  private requirePool(): pg.Pool {
    if (!this.connected || !this.pool) throw new EngramNotConnectedError();
    return this.pool;
  }

  // ------------------------------------------------------------------
  // record()
  // ------------------------------------------------------------------
  async record(input: RecordEventInput): Promise<void> {
    const pool = this.requirePool();
    const {
      userId,
      eventType,
      metadata = {},
      sessionId = null,
      ipRegion = null,
      uaClass = null,
    } = input;
    await pool.query(
      "select engram.record_event($1, $2, $3, $4, $5, $6)",
      [userId, eventType, metadata, sessionId, ipRegion, uaClass],
    );
  }

  /** @deprecated Use record(). Kept for backwards-compat in this repo. */
  recordEvent(input: RecordEventInput): Promise<void> {
    return this.record(input);
  }

  // ------------------------------------------------------------------
  // retrieve()
  // ------------------------------------------------------------------
  async retrieve(input: RetrieveInput): Promise<RetrieveResult> {
    const pool = this.requirePool();
    const lookbackMs = parseLookback(input.lookback);
    const eventTypes = input.eventTypes ?? null;
    const limit = input.limit ?? 200;
    const aggregate = input.aggregate ?? true;

    const { rows } = await pool.query<{ result: RetrieveResult }>(
      "select engram.retrieve($1, $2::text[], $3::bigint, $4::int, $5::bool) as result",
      [input.userId, eventTypes, lookbackMs, limit, aggregate],
    );
    const raw = rows[0]!.result;
    return {
      user_id: raw.user_id,
      window_ms: Number(raw.window_ms),
      events: raw.events ?? [],
      summary: aggregate ? (raw.summary ?? {}) : undefined,
    };
  }

  // ------------------------------------------------------------------
  // decide()
  // ------------------------------------------------------------------
  async decide<TInput, TOutput, TContext = RetrieveResult>(
    input: DecideInput<TInput, TOutput, TContext>,
  ): Promise<DecideResult<TOutput>> {
    const pool = this.requirePool();
    const t0 = performance.now();
    const ns = input.namespace ?? this.cfg.namespace;
    const threshold = input.cacheThreshold ?? 0.5;

    // Step 0: auto-context when dev didn't pass one.
    let ctx: TContext | null = input.context ?? null;
    const wantsAuto =
      input.autoContext ?? (ctx === null && hasUserId(input.input));
    if (wantsAuto && ctx === null) {
      const userId = (input.input as { userId?: string }).userId;
      if (userId) {
        const r = (await this.retrieve({
          userId,
          lookback: "30d",
          aggregate: true,
        })) as unknown as TContext;
        ctx = r;
      }
    }

    const cacheKey = input.cacheKey(input.input, ctx);

    // Step 1: cache lookup.
    const { rows: lookupRows } = await pool.query<{ result: CacheLookupRow }>(
      "select engram.cache_lookup($1, $2, $3) as result",
      [cacheKey, ns, threshold],
    );
    const lookup = lookupRows[0]!.result;

    if (lookup.hit) {
      const parsed = input.schema.parse(lookup.decision);
      return {
        decision: parsed,
        source: "cache",
        cacheId: lookup.id,
        cacheKey,
        confidence: Number(lookup.confidence),
        hitCount: Number(lookup.hit_count),
        latencyMs: +(performance.now() - t0).toFixed(3),
      };
    }

    // Step 2: brain call with dev-supplied prompt.
    const promptText = input.prompt(ctx, input.input);
    if (process.env.ENGRAM_DEBUG === "true") {
      // eslint-disable-next-line no-console
      console.error("[engram.debug] prompt sent to brain:\n" + promptText);
    }
    const rawResponse = await input.brain.call(promptText, input.brainOptions);
    if (process.env.ENGRAM_DEBUG === "true") {
      // eslint-disable-next-line no-console
      console.error("[engram.debug] raw brain response:\n" + rawResponse);
    }

    // Step 3: extract + validate JSON.
    const parsed = input.schema.parse(extractJson(rawResponse));

    // Step 4: store under dev-supplied cache_key.
    const { rows: storeRows } = await pool.query<{ id: string }>(
      "select engram.cache_store($1, $2, $3::jsonb, $4, $5::jsonb) as id",
      [cacheKey, ns, parsed as unknown, 0.5, {}],
    );
    const cacheId = storeRows[0]!.id;

    return {
      decision: parsed,
      source: "brain",
      cacheId,
      cacheKey,
      confidence: 0.5,
      hitCount: 1,
      latencyMs: +(performance.now() - t0).toFixed(3),
    };
  }

  // ------------------------------------------------------------------
  // feedback()
  // ------------------------------------------------------------------
  async feedback(
    cacheId: string,
    wasCorrect: boolean,
    namespace: string = this.cfg.namespace,
  ): Promise<void> {
    const pool = this.requirePool();
    await pool.query("select engram.feedback($1, $2, $3)", [
      cacheId,
      namespace,
      wasCorrect,
    ]);
  }

  // ------------------------------------------------------------------
  // Optional utilities (unchanged SQL names).
  // ------------------------------------------------------------------
  async userBaseline(userId: string): Promise<Baseline | null> {
    const pool = this.requirePool();
    const { rows } = await pool.query<{ result: Baseline | null }>(
      "select engram.user_baseline($1) as result",
      [userId],
    );
    return rows[0]?.result ?? null;
  }

  async detectAnomaly(
    userId: string,
    current: Record<string, number>,
  ): Promise<Anomaly> {
    const pool = this.requirePool();
    const { rows } = await pool.query<{ result: Anomaly }>(
      "select engram.detect_anomaly($1, $2) as result",
      [userId, current],
    );
    return rows[0]!.result;
  }

  async stats(namespace: string | null = null): Promise<StatsSnapshot> {
    const pool = this.requirePool();
    const { rows } = await pool.query<{ result: StatsSnapshot }>(
      "select engram.stats($1) as result",
      [namespace],
    );
    return rows[0]!.result;
  }

  async listCache(opts: { namespace?: string; limit?: number } = {}): Promise<
    CacheEntry[]
  > {
    const pool = this.requirePool();
    const { rows } = await pool.query<{ result: CacheEntry[] }>(
      "select engram.list_cache($1, $2) as result",
      [opts.namespace ?? null, opts.limit ?? 100],
    );
    return rows[0]!.result ?? [];
  }

  /** @deprecated Use listCache(). Kept so existing observability code works. */
  listPatterns(opts: { namespace?: string; limit?: number } = {}) {
    return this.listCache(opts);
  }

  async dashboard(): Promise<Dashboard> {
    const pool = this.requirePool();
    const { rows } = await pool.query<{ result: Dashboard }>(
      "select engram.dashboard() as result",
    );
    return rows[0]!.result;
  }

  /**
   * Express middleware factory bound to this Engram. Import
   * `@srk0102/engram/express` directly if you prefer tree-shakable usage.
   */
  express<TInput, TOutput, TContext = unknown>(
    opts: ExpressEngramOptions<TInput, TOutput, TContext>,
  ): RequestHandler {
    return engramExpress(this, opts);
  }

  /**
   * Bind brain/prompt/schema/cacheKey once and get back a function that
   * only needs `(input)` on each call. Useful when the same decision
   * shape is invoked from many call sites.
   *
   * @example
   *   const classify = engram.policy({ brain, prompt, schema, cacheKey });
   *   const r = await classify({ userId, amount });
   */
  policy<TInput, TOutput, TContext = RetrieveResult>(
    opts: PolicyOptions<TInput, TOutput, TContext>,
  ): PolicyFn<TInput, TOutput, TContext> {
    return async (input, context) => {
      const decideInput: DecideInput<TInput, TOutput, TContext> = {
        input,
        brain: opts.brain,
        prompt: opts.prompt,
        schema: opts.schema,
        cacheKey: opts.cacheKey,
      };
      if (opts.namespace !== undefined) decideInput.namespace = opts.namespace;
      if (opts.cacheThreshold !== undefined) decideInput.cacheThreshold = opts.cacheThreshold;
      if (opts.autoContext !== undefined) decideInput.autoContext = opts.autoContext;
      if (opts.brainOptions !== undefined) decideInput.brainOptions = opts.brainOptions;
      if (context !== undefined) decideInput.context = context;
      return this.decide(decideInput);
    };
  }
}

// ---------- helpers ----------

interface CacheLookupRow {
  hit: boolean;
  id: string;
  cache_key: string;
  decision: unknown;
  confidence: number;
  hit_count: number;
  meta?: Record<string, unknown>;
}

function hasUserId(x: unknown): x is { userId: string } {
  return (
    typeof x === "object" &&
    x !== null &&
    "userId" in x &&
    typeof (x as { userId: unknown }).userId === "string"
  );
}

function parseLookback(lookback: string | number | undefined): number {
  const MS_30D = 30 * 24 * 60 * 60 * 1000;
  if (lookback == null) return MS_30D;
  if (typeof lookback === "number") return lookback;
  const m = lookback.trim().match(/^(\d+)\s*(ms|s|m|h|d)$/i);
  if (!m) return MS_30D;
  const n = Number(m[1]);
  const unit = m[2]!.toLowerCase();
  const factor: Record<string, number> = {
    ms: 1,
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
  };
  return n * (factor[unit] ?? 86_400_000);
}

/**
 * Robustly pull a single JSON object out of an LLM response that may have
 * leading prose or code fences. Returns the raw string if no JSON found,
 * so the schema's .parse() can throw a clear error.
 */
function extractJson(raw: string): unknown {
  const cleaned = String(raw)
    .replace(/```(?:json)?/gi, "")
    .replace(/```/g, "")
    .trim();
  if (process.env.ENGRAM_DEBUG === "true") {
    // eslint-disable-next-line no-console
    console.error("[engram.debug] extractJson cleaned input:\n" + cleaned);
  }

  // Try the whole thing first (fast path for clean output).
  try {
    return JSON.parse(cleaned);
  } catch {
    /* fall through */
  }

  // Find the last {...} block at depth 0.
  let depth = 0;
  let start = -1;
  let bestStart = -1;
  let bestEnd = -1;
  for (let i = 0; i < cleaned.length; i++) {
    const c = cleaned[i];
    if (c === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        bestStart = start;
        bestEnd = i;
      }
    }
  }
  if (bestStart >= 0 && bestEnd > bestStart) {
    return JSON.parse(cleaned.slice(bestStart, bestEnd + 1));
  }
  // Return the raw string; schema.parse() will throw with a helpful error.
  return cleaned;
}
