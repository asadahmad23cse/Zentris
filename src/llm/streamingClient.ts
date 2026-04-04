import { config } from "../config";
import { type ChatMessage } from "../types";
import { LiteLLMError, type LLMOptions } from "./litellmClient";

interface StreamDelta {
  content?: unknown;
}

interface StreamChoice {
  delta?: StreamDelta;
}

interface StreamPayload {
  choices?: StreamChoice[];
}

const DEFAULT_MODEL = "gpt-4o";
const DEFAULT_TEMPERATURE = 0.7;

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
  public async streamChat(
    messages: ChatMessage[],
    options: LLMOptions,
    onChunk: (chunk: string) => void,
    onEnd: () => void,
    onError: (err: Error) => void
  ): Promise<void> {
    const url = `${config.LITELLM_BASE_URL.replace(/\/$/, "")}/chat/completions`;

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.LITELLM_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: options.model ?? DEFAULT_MODEL,
          messages: messages.map((message) => ({
            role: message.role,
            content: message.content
          })),
          stream: true,
          temperature: options.temperature ?? DEFAULT_TEMPERATURE,
          ...(options.maxTokens ? { max_tokens: options.maxTokens } : {})
        })
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
          if (content.length > 0) {
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
        if (content.length > 0) {
          onChunk(content);
        }
      }

      onEnd();
    } catch (error) {
      const normalizedError = error instanceof Error ? error : new Error("streaming_failed");
      onError(normalizedError);
    }
  }
}
