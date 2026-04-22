import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { AnthropicAdapter } from "../../src/adapters/anthropic.js";
import { OpenAIAdapter } from "../../src/adapters/openai.js";
import { OllamaAdapter } from "../../src/adapters/ollama.js";

/**
 * These tests stub global.fetch so we can assert the wire format each
 * adapter uses without hitting real APIs or spending tokens.
 */

type FetchCall = { url: string; init: RequestInit };
let calls: FetchCall[] = [];
let respond: () => Response;

beforeEach(() => {
  calls = [];
  respond = () => new Response("{}", { status: 200 });
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return respond();
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OllamaAdapter", () => {
  test("posts to /api/generate with format=json and returns response field", async () => {
    respond = () =>
      new Response(JSON.stringify({ response: "{\"action\":\"allow\"}" }), {
        status: 200,
      });
    const a = new OllamaAdapter({ model: "llama3.2", url: "http://h:1234" });
    const out = await a.call("hi");
    expect(out).toBe("{\"action\":\"allow\"}");
    expect(calls[0]?.url).toBe("http://h:1234/api/generate");
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body).toMatchObject({ model: "llama3.2", prompt: "hi", format: "json" });
  });

  test("defaults model to gemma4:e4b when none provided", async () => {
    respond = () => new Response(JSON.stringify({ response: "{}" }), { status: 200 });
    const a = new OllamaAdapter();
    await a.call("hi");
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.model).toBe("gemma4:e4b");
  });

  test("strips Gemma 4 thinking block before returning JSON", async () => {
    const raw = `<|channel>thought\nLet me analyze this carefully. The amount is small.\n<channel|>\n{"action":"allow"}`;
    respond = () => new Response(JSON.stringify({ response: raw }), { status: 200 });
    const a = new OllamaAdapter({ model: "gemma4:e4b" });
    const out = await a.call("hi");
    expect(out).toBe("{\"action\":\"allow\"}");
  });

  test("strips gpt-oss harmony analysis channel", async () => {
    const raw = `<|channel|>analysis\nreasoning here\n<|message|>{"action":"block"}`;
    respond = () => new Response(JSON.stringify({ response: raw }), { status: 200 });
    const a = new OllamaAdapter();
    const out = await a.call("hi");
    expect(out).toBe("{\"action\":\"block\"}");
  });

  test("strips <think> blocks (DeepSeek R1 / QwQ style)", async () => {
    const raw = `<think>The user wants an allow decision.</think>{"action":"allow"}`;
    respond = () => new Response(JSON.stringify({ response: raw }), { status: 200 });
    const a = new OllamaAdapter();
    const out = await a.call("hi");
    expect(out).toBe("{\"action\":\"allow\"}");
  });

  test("stripThinking=false leaves response untouched", async () => {
    const raw = `<think>x</think>{"action":"allow"}`;
    respond = () => new Response(JSON.stringify({ response: raw }), { status: 200 });
    const a = new OllamaAdapter({ stripThinking: false });
    const out = await a.call("hi");
    expect(out).toBe(raw);
  });
});

describe("AnthropicAdapter", () => {
  test("throws without apiKey or env", () => {
    const prev = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    expect(() => new AnthropicAdapter({ model: "claude-haiku-4-5" })).toThrow(/apiKey/);
    if (prev !== undefined) process.env.ANTHROPIC_API_KEY = prev;
  });

  test("posts to /v1/messages with x-api-key + anthropic-version, concats text blocks", async () => {
    respond = () =>
      new Response(
        JSON.stringify({
          content: [
            { type: "text", text: "{\"action\":" },
            { type: "text", text: "\"allow\"}" },
            { type: "tool_use" },
          ],
        }),
        { status: 200 },
      );
    const a = new AnthropicAdapter({
      model: "claude-haiku-4-5",
      apiKey: "sk-test",
    });
    const out = await a.call("hi");
    expect(out).toBe("{\"action\":\"allow\"}");
    expect(calls[0]?.url).toBe("https://api.anthropic.com/v1/messages");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("sk-test");
    expect(headers["anthropic-version"]).toBe("2023-06-01");
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.messages).toEqual([{ role: "user", content: "hi" }]);
  });

  test("propagates HTTP errors with status and body preview", async () => {
    respond = () => new Response("rate limited", { status: 429 });
    const a = new AnthropicAdapter({ model: "claude-haiku-4-5", apiKey: "x" });
    await expect(a.call("hi")).rejects.toThrow(/429/);
  });
});

describe("OpenAIAdapter", () => {
  test("throws without apiKey or env", () => {
    const prev = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    expect(() => new OpenAIAdapter({ model: "gpt-4o-mini" })).toThrow(/apiKey/);
    if (prev !== undefined) process.env.OPENAI_API_KEY = prev;
  });

  test("posts to /v1/chat/completions with Bearer auth and json response_format", async () => {
    respond = () =>
      new Response(
        JSON.stringify({
          choices: [{ message: { content: "{\"action\":\"allow\"}" } }],
        }),
        { status: 200 },
      );
    const a = new OpenAIAdapter({
      model: "gpt-4o-mini",
      apiKey: "sk-openai-test",
      systemPrompt: "be strict",
    });
    const out = await a.call("hi");
    expect(out).toBe("{\"action\":\"allow\"}");
    expect(calls[0]?.url).toBe("https://api.openai.com/v1/chat/completions");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer sk-openai-test");
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.response_format).toEqual({ type: "json_object" });
    expect(body.messages).toEqual([
      { role: "system", content: "be strict" },
      { role: "user", content: "hi" },
    ]);
  });

  test("honors custom url for Azure / openrouter-style proxies", async () => {
    respond = () =>
      new Response(
        JSON.stringify({ choices: [{ message: { content: "{}" } }] }),
        { status: 200 },
      );
    const a = new OpenAIAdapter({
      model: "gpt-4o-mini",
      apiKey: "x",
      url: "https://openrouter.ai/api",
    });
    await a.call("hi");
    expect(calls[0]?.url).toBe("https://openrouter.ai/api/v1/chat/completions");
  });
});
