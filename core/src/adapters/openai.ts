import type { Brain, BrainCallOptions } from "../types.js";

export interface OpenAIAdapterConfig {
  /** Model id, e.g. "gpt-4o-mini". Required. */
  model: string;
  /** API key. Defaults to process.env.OPENAI_API_KEY. */
  apiKey?: string;
  /** Base URL. Default https://api.openai.com. Override for Azure / proxies. */
  url?: string;
  /** Default max tokens per call. */
  maxTokens?: number;
  /** Default temperature. 0 for deterministic JSON. */
  temperature?: number;
  /** Default per-call timeout in ms. */
  timeoutMs?: number;
  /** Optional system prompt prepended to every call. */
  systemPrompt?: string;
  /**
   * If true, request `response_format: { type: "json_object" }` so the
   * model is forced to emit a JSON object. Default true.
   */
  jsonMode?: boolean;
}

interface OpenAIChatResponse {
  choices?: Array<{ message?: { content?: string } }>;
}

/**
 * OpenAI Chat Completions adapter. Works with OpenAI, Azure OpenAI, and
 * any OpenAI-compatible server (vLLM, LM Studio, Groq, OpenRouter) by
 * overriding `url`.
 */
export class OpenAIAdapter implements Brain {
  private readonly model: string;
  private readonly apiKey: string;
  private readonly url: string;
  private readonly maxTokens: number;
  private readonly temperature: number;
  private readonly timeoutMs: number;
  private readonly systemPrompt?: string;
  private readonly jsonMode: boolean;

  constructor(config: OpenAIAdapterConfig) {
    if (!config.model) throw new Error("OpenAIAdapter: `model` is required");
    const key = config.apiKey ?? process.env.OPENAI_API_KEY;
    if (!key) {
      throw new Error(
        "OpenAIAdapter: `apiKey` missing (and OPENAI_API_KEY not set)",
      );
    }
    this.model = config.model;
    this.apiKey = key;
    this.url = (config.url ?? "https://api.openai.com").replace(/\/+$/, "");
    this.maxTokens = config.maxTokens ?? 1024;
    this.temperature = config.temperature ?? 0.0;
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.systemPrompt = config.systemPrompt;
    this.jsonMode = config.jsonMode ?? true;
  }

  async call(prompt: string, opts?: BrainCallOptions): Promise<string> {
    const messages: Array<{ role: string; content: string }> = [];
    if (this.systemPrompt) messages.push({ role: "system", content: this.systemPrompt });
    messages.push({ role: "user", content: prompt });

    const body: Record<string, unknown> = {
      model: this.model,
      messages,
      max_tokens: opts?.maxTokens ?? this.maxTokens,
      temperature: opts?.temperature ?? this.temperature,
    };
    if (this.jsonMode) body.response_format = { type: "json_object" };

    const controller = new AbortController();
    const deadline = setTimeout(
      () => controller.abort(),
      opts?.timeoutMs ?? this.timeoutMs,
    );

    try {
      const res = await fetch(`${this.url}/v1/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        throw new Error(
          `OpenAIAdapter: HTTP ${res.status} from ${this.url}/v1/chat/completions: ${detail.slice(0, 300)}`,
        );
      }
      const payload = (await res.json()) as OpenAIChatResponse;
      return String(payload.choices?.[0]?.message?.content ?? "");
    } finally {
      clearTimeout(deadline);
    }
  }
}
