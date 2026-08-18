import { config } from "../config";
import { type ChatMessage, type GenerationOptions } from "../types";

export type LLMOptions = GenerationOptions;

interface LiteLLMChoice {
  message?: {
    content?: unknown;
  };
}

interface LiteLLMResponse extends Record<string, unknown> {
  choices?: LiteLLMChoice[];
}

export interface LiteLLMCompletion {
  content: string;
  response: LiteLLMResponse;
}

const DEFAULT_TEMPERATURE = 0.7;
const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_BACKOFF_MS = [500, 1000] as const;

const sleep = async (durationMs: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, durationMs);
  });

const normalizeContent = (value: unknown): string | null => {
  if (typeof value === "string") {
    return value;
  }

  if (Array.isArray(value)) {
    const textParts = value
      .map((item) => {
        if (item && typeof item === "object" && "text" in item && typeof item.text === "string") {
          return item.text;
        }
        return "";
      })
      .filter((part) => part.length > 0);

    if (textParts.length > 0) {
      return textParts.join("");
    }
  }

  return null;
};

export class LiteLLMError extends Error {
  public readonly statusCode: number;
  public readonly llmReason: string;

  public constructor(message: string, statusCode: number, llmReason: string) {
    super(message);
    this.name = "LiteLLMError";
    this.statusCode = statusCode;
    this.llmReason = llmReason;
  }
}

export class LiteLLMClient {
  public async chat(messages: ChatMessage[], options?: LLMOptions): Promise<string> {
    return (await this.chatCompletion(messages, options)).content;
  }

  public async chatCompletion(messages: ChatMessage[], options?: LLMOptions): Promise<LiteLLMCompletion> {
    const url = `${config.LITELLM_BASE_URL.replace(/\/$/, "")}/chat/completions`;
    const body = {
      model: options?.model ?? config.LITELLM_MODEL,
      messages: messages.map((message) => ({
        role: message.role,
        content: message.content
      })),
      stream: false,
      temperature: options?.temperature ?? DEFAULT_TEMPERATURE,
      ...(options?.maxTokens !== undefined ? { max_tokens: options.maxTokens } : {}),
      ...(options?.topP !== undefined ? { top_p: options.topP } : {}),
      ...(options?.stop !== undefined ? { stop: options.stop } : {}),
      ...(options?.tools !== undefined ? { tools: options.tools } : {}),
      ...(options?.toolChoice !== undefined ? { tool_choice: options.toolChoice } : {}),
      ...(options?.responseFormat !== undefined ? { response_format: options.responseFormat } : {})
    };

    for (let attempt = 0; attempt <= RETRY_BACKOFF_MS.length; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${options?.apiKey ?? config.LITELLM_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body),
          signal: controller.signal
        });

        if (response.status >= 400 && response.status < 500) {
          throw new LiteLLMError(
            `LiteLLM client error: ${response.status}`,
            response.status,
            response.status === 401 || response.status === 403
              ? "upstream_authentication_failed"
              : response.status === 429 ? "upstream_rate_limited" : "upstream_client_error"
          );
        }

        if (response.status >= 500) {
          throw new LiteLLMError(
            `LiteLLM server error: ${response.status}`,
            response.status,
            "upstream_server_error"
          );
        }

        const parsed = (await response.json()) as LiteLLMResponse;
        const content = normalizeContent(parsed.choices?.[0]?.message?.content);
        if (!content) {
          throw new LiteLLMError("LiteLLM malformed response", 502, "malformed_response");
        }

        return { content, response: parsed };
      } catch (error) {
        const isLastAttempt = attempt === RETRY_BACKOFF_MS.length;

        if (error instanceof LiteLLMError) {
          if (error.statusCode >= 500 && !isLastAttempt) {
            await sleep(RETRY_BACKOFF_MS[attempt]);
            continue;
          }
          throw error;
        }

        if (!isLastAttempt) {
          await sleep(RETRY_BACKOFF_MS[attempt]);
          continue;
        }

        const reason =
          error instanceof Error && error.name === "AbortError" ? "request_timeout" : "request_failed";
        throw new LiteLLMError("LiteLLM request failed", 0, reason);
      } finally {
        clearTimeout(timeout);
      }
    }

    throw new LiteLLMError("LiteLLM request failed", 0, "request_failed");
  }
}
