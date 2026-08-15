import { config } from "../config";
import { type ChatMessage } from "../types";

export interface LLMOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
}

interface LiteLLMChoice {
  message?: {
    content?: unknown;
  };
}

interface LiteLLMResponse {
  choices?: LiteLLMChoice[];
}

const DEFAULT_MODEL = "gpt-4o-mini";
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
    const url = `${config.LITELLM_BASE_URL.replace(/\/$/, "")}/chat/completions`;
    const body = {
      model: options?.model ?? DEFAULT_MODEL,
      messages: messages.map((message) => ({
        role: message.role,
        content: message.content
      })),
      stream: false,
      temperature: options?.temperature ?? DEFAULT_TEMPERATURE,
      ...(options?.maxTokens ? { max_tokens: options.maxTokens } : {})
    };

    for (let attempt = 0; attempt <= RETRY_BACKOFF_MS.length; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${config.LITELLM_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body),
          signal: controller.signal
        });

        if (response.status >= 400 && response.status < 500) {
          const errorText = await response.text();
          throw new LiteLLMError(
            `LiteLLM client error: ${response.status}`,
            response.status,
            errorText || "client_error"
          );
        }

        if (response.status >= 500) {
          const errorText = await response.text();
          throw new LiteLLMError(
            `LiteLLM server error: ${response.status}`,
            response.status,
            errorText || "server_error"
          );
        }

        const parsed = (await response.json()) as LiteLLMResponse;
        const content = normalizeContent(parsed.choices?.[0]?.message?.content);
        if (!content) {
          throw new LiteLLMError("LiteLLM malformed response", 502, "malformed_response");
        }

        return content;
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
