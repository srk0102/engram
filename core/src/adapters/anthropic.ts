import type { Brain, BrainCallOptions } from "../types.js";

export interface AnthropicAdapterConfig {
  /** Model id, e.g. "claude-haiku-4-5". Required. */
  model: string;
  /** API key. Defaults to process.env.ANTHROPIC_API_KEY. */
  apiKey?: string;
  /** Base URL. Default https://api.anthropic.com. */
  url?: string;
  /** API version header. Default "2023-06-01". */
  apiVersion?: string;
  /** Default max tokens per call. */
  maxTokens?: number;
  /** Default temperature. 0 for deterministic JSON. */
  temperature?: number;
  /** Default per-call timeout in ms. */
  timeoutMs?: number;
  /** Optional system prompt prepended to every call. */
  systemPrompt?: string;
}

interface AnthropicContentBlock {
  type?: string;
  text?: string;
}
interface AnthropicMessageResponse {
  content?: AnthropicContentBlock[];
}

/**
 * Anthropic Messages API adapter. Concatenates all text blocks in the
 * response into a single string so the engram schema parser can read it.
 */
export class AnthropicAdapter implements Brain {
  private readonly model: string;
  private readonly apiKey: string;
  private readonly url: string;
  private readonly apiVersion: string;
  private readonly maxTokens: number;
  private readonly temperature: number;
  private readonly timeoutMs: number;
  private readonly systemPrompt?: string;

  constructor(config: AnthropicAdapterConfig) {
    if (!config.model) throw new Error("AnthropicAdapter: `model` is required");
    const key = config.apiKey ?? process.env.ANTHROPIC_API_KEY;
    if (!key) {
      throw new Error(
        "AnthropicAdapter: `apiKey` missing (and ANTHROPIC_API_KEY not set)",
      );
    }
    this.model = config.model;
    this.apiKey = key;
    this.url = (config.url ?? "https://api.anthropic.com").replace(/\/+$/, "");
    this.apiVersion = config.apiVersion ?? "2023-06-01";
    this.maxTokens = config.maxTokens ?? 1024;
    this.temperature = config.temperature ?? 0.0;
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.systemPrompt = config.systemPrompt;
  }

  async call(prompt: string, opts?: BrainCallOptions): Promise<string> {
    const body: Record<string, unknown> = {
      model: this.model,
      max_tokens: opts?.maxTokens ?? this.maxTokens,
      temperature: opts?.temperature ?? this.temperature,
      messages: [{ role: "user", content: prompt }],
    };
    if (this.systemPrompt) body.system = this.systemPrompt;

    const controller = new AbortController();
    const deadline = setTimeout(
      () => controller.abort(),
      opts?.timeoutMs ?? this.timeoutMs,
    );

    try {
      const res = await fetch(`${this.url}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": this.apiKey,
          "anthropic-version": this.apiVersion,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        throw new Error(
          `AnthropicAdapter: HTTP ${res.status} from ${this.url}/v1/messages: ${detail.slice(0, 300)}`,
        );
      }
      const payload = (await res.json()) as AnthropicMessageResponse;
      const text = (payload.content ?? [])
        .filter((b) => b?.type === "text" && typeof b.text === "string")
        .map((b) => b.text as string)
        .join("");
      return text;
    } finally {
      clearTimeout(deadline);
    }
  }
}
