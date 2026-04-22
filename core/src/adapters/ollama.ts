import type { Brain, BrainCallOptions } from "../types.js";

export interface OllamaAdapterConfig {
  /**
   * Model to use, e.g. "gemma4:e4b", "llama3.2", "qwen2.5:3b".
   * Optional. Defaults to "gemma4:e4b".
   */
  model?: string;
  /** Base URL of the Ollama daemon. Default http://localhost:11434. */
  url?: string;
  /** Default max tokens per call. */
  maxTokens?: number;
  /** Default temperature. Set 0 for deterministic JSON output. */
  temperature?: number;
  /** Default per-call timeout in ms. */
  timeoutMs?: number;
  /** Optional system prompt prepended to every call. */
  systemPrompt?: string;
  /**
   * Strip model "thinking" channel blocks from the response before
   * returning. Needed for Gemma 4 and other models that emit internal
   * reasoning in a <|channel>thought ... <channel|> block before the
   * final answer. Default true.
   */
  stripThinking?: boolean;
}

/**
 * Ollama brain adapter. Talks to /api/generate. Works with any model
 * the daemon has pulled. Default model is "gemma4:e4b".
 */
export class OllamaAdapter implements Brain {
  private readonly model: string;
  private readonly url: string;
  private readonly maxTokens: number;
  private readonly temperature: number;
  private readonly timeoutMs: number;
  private readonly systemPrompt?: string;
  private readonly stripThinking: boolean;

  constructor(config: OllamaAdapterConfig = {}) {
    this.model = config.model ?? "gemma4:e4b";
    this.url = (config.url ?? "http://localhost:11434").replace(/\/+$/, "");
    this.maxTokens = config.maxTokens ?? 512;
    this.temperature = config.temperature ?? 0.0;
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.systemPrompt = config.systemPrompt;
    this.stripThinking = config.stripThinking ?? true;
  }

  async call(prompt: string, opts?: BrainCallOptions): Promise<string> {
    const body = {
      model: this.model,
      prompt,
      stream: false,
      system: this.systemPrompt,
      options: {
        temperature: opts?.temperature ?? this.temperature,
        num_predict: opts?.maxTokens ?? this.maxTokens,
      },
      format: "json",
    };

    const controller = new AbortController();
    const deadline = setTimeout(
      () => controller.abort(),
      opts?.timeoutMs ?? this.timeoutMs,
    );

    try {
      const res = await fetch(`${this.url}/api/generate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        throw new Error(
          `OllamaAdapter: HTTP ${res.status} from ${this.url}/api/generate: ${detail.slice(0, 300)}`,
        );
      }
      const payload = (await res.json()) as { response?: string };
      const raw = String(payload.response ?? "");
      if (process.env.ENGRAM_DEBUG === "true") {
        // eslint-disable-next-line no-console
        console.error("[engram.debug] OllamaAdapter raw response:\n" + raw);
      }
      return this.stripThinking ? stripThinkingBlocks(raw) : raw;
    } finally {
      clearTimeout(deadline);
    }
  }
}

/**
 * Remove model "thinking" / "reasoning" channel blocks so the downstream
 * JSON parser sees only the final answer. Covers the formats Gemma 4,
 * gpt-oss harmony, DeepSeek R1, and Qwen thinking models use.
 *
 * Patterns removed:
 *   <|channel>thought ... <channel|>       (Gemma 4 / harmony-lite)
 *   <|channel|>analysis ... <|message|>    (gpt-oss harmony)
 *   <think> ... </think>                   (DeepSeek R1, Qwen QwQ)
 *   <thinking> ... </thinking>             (generic)
 */
function stripThinkingBlocks(text: string): string {
  let out = text;
  const patterns: RegExp[] = [
    /<\|channel\|?>\s*thought[\s\S]*?<\|?channel\|>/gi,
    /<\|channel\|?>\s*analysis[\s\S]*?<\|message\|?>/gi,
    /<think>[\s\S]*?<\/think>/gi,
    /<thinking>[\s\S]*?<\/thinking>/gi,
  ];
  for (const p of patterns) out = out.replace(p, "");
  return out.trim();
}
