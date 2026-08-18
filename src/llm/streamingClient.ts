import { config } from "../config";
import { type ChatMessage } from "../types";
import { LiteLLMError, type LLMOptions } from "./litellmClient";

interface StreamDelta {
  content?: unknown;
}

interface StreamChoice {
  delta?: StreamDelta;
  finish_reason?: unknown;
}

export interface StreamPayload extends Record<string, unknown> {
  choices?: StreamChoice[];
}

const DEFAULT_TEMPERATURE = 0.7;
const REQUEST_TIMEOUT_MS = 30_000;

const extractContent = (value: unknown): string => {
  if (typeof value === "string") {
    return value;
  }

  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (item && typeof item === "object" && "text" in item && typeof item.text === "string") {
          return item.text;
        }
        return "";
      })
      .join("");
  }

  return "";
};

export class StreamingClient {
  private readonly abortControllersByStreamId = new Map<string, AbortController>();

  public abortStream(streamId: string): void {
    const abortController = this.abortControllersByStreamId.get(streamId);
    if (abortController) {
      abortController.abort();
      this.abortControllersByStreamId.delete(streamId);
    }
  }

  public async streamChat(
    streamId: string,
    messages: ChatMessage[],
    options: LLMOptions,
    onChunk: (chunk: string) => void,
    onEnd: () => void,
    onError: (err: Error) => void,
    onEvent?: (payload: StreamPayload, content: string) => void
  ): Promise<void> {
    const url = `${config.LITELLM_BASE_URL.replace(/\/$/, "")}/chat/completions`;
    const abortController = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      abortController.abort();
    }, REQUEST_TIMEOUT_MS);
    this.abortControllersByStreamId.set(streamId, abortController);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${options.apiKey ?? config.LITELLM_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: options.model ?? config.LITELLM_MODEL,
          messages: messages.map((message) => ({
            role: message.role,
            content: message.content
          })),
          stream: true,
          ...(options.streamOptions !== undefined ? {
            stream_options: { include_usage: options.streamOptions.includeUsage }
          } : {}),
          temperature: options.temperature ?? DEFAULT_TEMPERATURE,
          ...(options.maxTokens !== undefined ? { max_tokens: options.maxTokens } : {}),
          ...(options.topP !== undefined ? { top_p: options.topP } : {}),
          ...(options.stop !== undefined ? { stop: options.stop } : {}),
          ...(options.tools !== undefined ? { tools: options.tools } : {}),
          ...(options.toolChoice !== undefined ? { tool_choice: options.toolChoice } : {}),
          ...(options.responseFormat !== undefined ? { response_format: options.responseFormat } : {})
        }),
        signal: abortController.signal
      });

      if (!response.ok) {
        throw new LiteLLMError(
          `LiteLLM streaming request failed: ${response.status}`,
          response.status,
          "stream_request_failed"
        );
      }

      if (!response.body) {
        throw new LiteLLMError("LiteLLM streaming body missing", 502, "missing_stream_body");
      }

      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      for await (const chunk of response.body) {
        buffer += decoder.decode(chunk, { stream: true });

        let newlineIndex = buffer.indexOf("\n");
        while (newlineIndex !== -1) {
          const line = buffer.slice(0, newlineIndex).trim();
          buffer = buffer.slice(newlineIndex + 1);

          if (!line || !line.startsWith("data:")) {
            newlineIndex = buffer.indexOf("\n");
            continue;
          }

          const payload = line.slice(5).trim();
          if (payload === "[DONE]") {
            onEnd();
            return;
          }

          const parsed = JSON.parse(payload) as StreamPayload;
          const content = extractContent(parsed.choices?.[0]?.delta?.content);
          if (onEvent) {
            onEvent(parsed, content);
          } else if (content.length > 0) {
            onChunk(content);
          }

          newlineIndex = buffer.indexOf("\n");
        }
      }

      if (buffer.trim().startsWith("data:")) {
        const payload = buffer.trim().slice(5).trim();
        if (payload === "[DONE]") {
          onEnd();
          return;
        }
        const parsed = JSON.parse(payload) as StreamPayload;
        const content = extractContent(parsed.choices?.[0]?.delta?.content);
        if (onEvent) {
          onEvent(parsed, content);
        } else if (content.length > 0) {
          onChunk(content);
        }
      }

      onEnd();
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        if (timedOut) onError(new LiteLLMError("LiteLLM streaming request timed out", 504, "request_timeout"));
        return;
      }
      const normalizedError = error instanceof Error ? error : new Error("streaming_failed");
      onError(normalizedError);
    } finally {
      clearTimeout(timeout);
      this.abortControllersByStreamId.delete(streamId);
    }
  }
}
