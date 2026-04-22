import type { Pool } from "pg";

/**
 * Anything with a .parse() method that throws on invalid or returns the
 * parsed value on valid works as a schema. This matches Zod, Valibot,
 * Yup (async mode aside), and hand-rolled validators. No hard dep on any.
 */
export interface Schema<T> {
  parse(input: unknown): T;
}

/**
 * A brain is any async function that takes a prompt string and returns
 * a string response. Adapters (Ollama, Anthropic, OpenAI) implement this
 * by wrapping their provider's HTTP API.
 *
 * Callers can also supply a plain function: `async (p) => "...llm output..."`.
 */
export interface Brain {
  call(prompt: string, opts?: BrainCallOptions): Promise<string>;
}

export interface BrainCallOptions {
  /** Approximate upper bound on response tokens. Advisory -- brains may ignore. */
  maxTokens?: number;
  /** Sampling temperature. 0 = deterministic. */
  temperature?: number;
  /** Per-call timeout override, in ms. */
  timeoutMs?: number;
}

export interface Logger {
  (message: string, meta?: Record<string, unknown>): void;
}

/* ---------------------------------------------------------------------------
 * record() -- universal signal ingestion
 * ------------------------------------------------------------------------ */

export interface RecordEventInput {
  userId: string;
  eventType: string;
  metadata?: Record<string, unknown>;
  sessionId?: string | null;
  ipRegion?: string | null;
  uaClass?: string | null;
}

/* ---------------------------------------------------------------------------
 * retrieve() -- context assembly for the LLM
 * ------------------------------------------------------------------------ */

export interface RetrieveInput {
  userId: string;
  eventTypes?: string[];
  /**
   * Lookback window. Accepts either a ms number or a duration string like
   * "7d", "24h", "15m". Default: "30d".
   */
  lookback?: string | number;
  limit?: number;
  /**
   * When true, the result includes a per-event-type summary (count,
   * first_seen, last_seen, avg_per_day, most recent metadata sample).
   */
  aggregate?: boolean;
}

export interface RetrieveEvent {
  id: number;
  user_id: string;
  event_type: string;
  metadata: Record<string, unknown>;
  session_id: string | null;
  ip_region: string | null;
  ua_class: string | null;
  created_at: number;
}

export interface RetrieveEventTypeSummary {
  count: number;
  first_seen: number;
  last_seen: number;
  avg_per_day: number;
  days_seen: number;
  sample_metadata: Record<string, unknown> | null;
}

export interface RetrieveResult {
  events: RetrieveEvent[];
  summary?: Record<string, RetrieveEventTypeSummary>;
  user_id: string;
  window_ms: number;
}

/* ---------------------------------------------------------------------------
 * decide() -- the full flow: cache -> brain -> store
 * ------------------------------------------------------------------------ */

export interface DecideInput<TInput, TOutput, TContext = RetrieveResult> {
  /** The thing you are deciding about. Passed to prompt/cacheKey unchanged. */
  input: TInput;

  /**
   * Optional pre-assembled context. If omitted and userId is present on
   * input, engram will call retrieve() for you. Pass your own context if
   * you want full control over what the LLM sees.
   */
  context?: TContext;

  /** Any function that returns a string response to a prompt. */
  brain: Brain;

  /** Build the LLM prompt from context + input. */
  prompt: (context: TContext | null, input: TInput) => string;

  /**
   * Any object with a .parse(unknown) => TOutput method. Zod, Valibot,
   * hand-rolled -- doesn't matter. Validated LLM output goes into cache.
   */
  schema: Schema<TOutput>;

  /**
   * Returns a string key that uniquely identifies "the same situation."
   * Two calls with the same key on the same namespace hit the cache.
   */
  cacheKey: (input: TInput, context: TContext | null) => string;

  /** Override the instance default namespace for this call. */
  namespace?: string;

  /** Minimum confidence for a cache hit. Default 0.5. */
  cacheThreshold?: number;

  /**
   * Whether to auto-call retrieve() when context is missing.
   * Default: true if input has a `userId` field, false otherwise.
   */
  autoContext?: boolean;

  /**
   * Per-call options passed through to the brain adapter.
   */
  brainOptions?: BrainCallOptions;
}

export type DecisionSource = "cache" | "brain";

export interface DecideResult<TOutput> {
  decision: TOutput;
  source: DecisionSource;
  cacheId: string;
  cacheKey: string;
  confidence: number;
  hitCount: number;
  latencyMs: number;
}

/* ---------------------------------------------------------------------------
 * Low-level cache entry (the row stored in engram.cache)
 * ------------------------------------------------------------------------ */

export interface CacheEntry {
  id: string;
  namespace: string;
  cache_key: string;
  decision: unknown;
  confidence: number;
  hit_count: number;
  success_count: number;
  failure_count: number;
  meta: Record<string, unknown>;
  created_at: number;
  updated_at: number;
  expires_at: number | null;
}

/* ---------------------------------------------------------------------------
 * Utility result shapes (baseline + anomaly kept as optional tools)
 * ------------------------------------------------------------------------ */

export interface BaselineEventTypeStats {
  count: number;
  days_seen: number;
  avg_per_day: number;
  first_seen: number;
  last_seen: number;
  sample_metadata: Record<string, unknown> | null;
}

export interface Baseline {
  user_id: string;
  window_days: number;
  distinct_days: number;
  computed_at: number;
  event_types: Record<string, BaselineEventTypeStats>;
}

export interface AnomalyEntry {
  event_type: string;
  kind: "burst" | "silence" | "new_event_type" | "zero_baseline_nonzero_current";
  current: number | null;
  baseline_avg: number | null;
  ratio: number | null;
}

export interface Anomaly {
  anomaly_score: number;
  anomalies: AnomalyEntry[];
  baseline: Baseline | null;
  current: Record<string, number>;
  should_ask_brain: boolean;
  reason?: string;
}

export interface StatsSnapshot {
  total_cached: number;
  avg_confidence: number;
  total_hits: number;
}

export interface Dashboard {
  cache: {
    total: number;
    total_hits: number;
    avg_confidence: number;
    by_namespace: Record<string, number>;
  };
  events: {
    total: number;
    by_event_type: Record<string, number>;
  };
  version: string;
}

/* ---------------------------------------------------------------------------
 * Engram config
 * ------------------------------------------------------------------------ */

export interface EngramConfig {
  connectionString?: string;
  pool?: Pool;
  /** Default namespace if not overridden on decide(). Default "default". */
  namespace?: string;
  /** Run migrations on connect(). Default true. */
  autoMigrate?: boolean;
  /** Logger. Default: no-op. */
  logger?: Logger;
}
