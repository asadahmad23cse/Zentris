import fp from "fastify-plugin";
import { type FastifyPluginAsync } from "fastify";
import { RagSecurityGuard } from "../guards/ragSecurityGuard";
import { wrapUntrustedData } from "../guards/ragWrapper";
import { type LLMChat, ZentrisPipeline } from "../middleware/pipeline";
import { config } from "../config";
import { createAccessToken } from "../auth/jwt";
import { LiteLLMClient, LiteLLMError } from "../llm/litellmClient";
import { type AuthenticatedIdentity, type ChatMessage, type ToolInvocation } from "../types";

interface PublicChatBody {
  sessionId?: string;
  message: string;
  history?: Array<{
    role: "user" | "assistant";
    content: string;
    timestamp?: number;
  }>;
  ragContext?: string;
  toolInvocation?: ToolInvocation;
}

export interface PublicRouteOptions {
  litellmChat?: LLMChat;
}

const PUBLIC_IDENTITY: AuthenticatedIdentity = {
  userId: "public-web-user",
  userRole: "viewer",
  tenantId: null,
  orgId: null
};

// Upstream is Groq (LITELLM_BASE_URL=https://api.groq.com/openai/v1). Model IDs
// must be real Groq model names so they can be forwarded verbatim.
const PUBLIC_MODELS = [
  {
    model_group: "openai/gpt-oss-120b",
    providers: ["groq"],
    mode: "chat",
    max_input_tokens: 131072,
    max_output_tokens: 65536,
    input_cost_per_token: 0.00000015,
    output_cost_per_token: 0.0000006,
    supports_function_calling: true,
    supports_parallel_function_calling: true,
    supports_vision: false,
    health_status: "available"
  },
  {
    model_group: "openai/gpt-oss-20b",
    providers: ["groq"],
    mode: "chat",
    max_input_tokens: 131072,
    max_output_tokens: 65536,
    input_cost_per_token: 0.00000005,
    output_cost_per_token: 0.0000002,
    supports_function_calling: true,
    supports_parallel_function_calling: true,
    supports_vision: false,
    health_status: "available"
  },
  {
    model_group: "qwen/qwen3.6-27b",
    providers: ["groq"],
    mode: "chat",
    max_input_tokens: 131072,
    max_output_tokens: 16384,
    input_cost_per_token: 0.0000006,
    output_cost_per_token: 0.000003,
    supports_function_calling: true,
    supports_parallel_function_calling: false,
    supports_vision: true,
    health_status: "available"
  },
  {
    model_group: "groq/compound",
    providers: ["groq"],
    mode: "chat",
    max_input_tokens: 131072,
    max_output_tokens: 8192,
    input_cost_per_token: 0.0000002,
    output_cost_per_token: 0.0000006,
    supports_function_calling: true,
    supports_parallel_function_calling: true,
    supports_vision: false,
    health_status: "available"
  }
] as const;

const publicChatBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["message"],
  properties: {
    sessionId: { type: "string", maxLength: 64, pattern: "^[A-Za-z0-9-]{1,64}$" },
    message: { type: "string", minLength: 1, maxLength: 4000 },
    ragContext: { type: "string", maxLength: 8000 },
    history: {
      type: "array",
      maxItems: 20,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["role", "content"],
        properties: {
          role: { type: "string", enum: ["user", "assistant"] },
          content: { type: "string", maxLength: 4000 },
          timestamp: { type: "number" }
        }
      }
    },
    toolInvocation: {
      type: "object",
      additionalProperties: true
    }
  }
} as const;

const normalizeHistory = (history: PublicChatBody["history"]): ChatMessage[] =>
  (history ?? []).slice(-config.MAX_SESSION_MESSAGES).map((message) => ({
    role: message.role,
    content: message.content,
    timestamp: message.timestamp ?? Date.now()
  }));

const redactSensitiveText = (value: string): string =>
  value
    .replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, "[REDACTED_KEY]")
    .replace(/\bBearer\s+[A-Za-z0-9._-]+/gi, "Bearer [REDACTED]")
    .slice(0, 240);

const summarizeLLMError = (error: unknown): { statusCode: number; reason: string } => {
  if (error instanceof LiteLLMError) {
    let reason = error.llmReason;

    try {
      const parsed = JSON.parse(error.llmReason) as {
        error?: { message?: unknown; type?: unknown; code?: unknown };
      };
      const providerError = parsed.error;
      const parts = [providerError?.code, providerError?.type, providerError?.message]
        .filter((part): part is string => typeof part === "string" && part.length > 0);
      if (parts.length > 0) {
        reason = parts.join(": ");
      }
    } catch {
      // Provider error payload was plain text; redact and return the bounded value below.
    }

    return {
      statusCode: error.statusCode,
      reason: redactSensitiveText(reason)
    };
  }

  return {
    statusCode: 0,
    reason: error instanceof Error ? redactSensitiveText(error.message) : "unknown_error"
  };
};

const publicRoutes: FastifyPluginAsync<PublicRouteOptions> = async (app, options) => {
  const ragSecurityGuard = new RagSecurityGuard();
  const pipeline = new ZentrisPipeline({ litellmChat: options.litellmChat });
  const llmStatusChat = options.litellmChat ?? ((messages, llmOptions) => new LiteLLMClient().chat(messages, llmOptions));

  app.get("/.well-known/litellm-ui-config", async () => {
    return {
      server_root_path: "/",
      proxy_base_url: null,
      auto_redirect_to_sso: false,
      admin_ui_disabled: false,
      sso_configured: false,
      is_control_plane: false,
      workers: []
    };
  });

  app.get("/public/model_hub/info", async () => ({
    docs_title: "Zentris Gateway",
    custom_docs_description: "Public model catalog for the Zentris AI security runtime.",
    Zentris_version: "1.0.0"
  }));

  app.get("/public/model_hub", async () => PUBLIC_MODELS);
  app.get("/public/agent_hub", async () => []);
  app.get("/public/mcp_hub", async () => []);

  app.get("/public/dashboard-token", async () => {
    const exp = Math.floor(Date.now() / 1000) + 86400;
    const token = createAccessToken(
      {
        sub: "public-admin",
        role: "admin",
        exp,
        user_id: "public-admin",
        user_email: "admin@zentris.ai",
        user_role: "proxy_admin",
        login_method: "public_access",
        premium_user: false,
        disabled_non_admin_personal_key_creation: false,
        key: "public-admin"
      },
      config.JWT_SECRET
    );
    return { token, user_role: "proxy_admin", login_method: "public_access" };
  });

  // Provider-backed public probes/chat exist only in the explicit demo runtime
  // or when a test injects a bounded fake model. Production inference always
  // requires a LiteLLM virtual key through /v1/chat or /v1/chat/completions.
  if (!config.ZENTRIS_DEMO_ENABLED && !options.litellmChat) return;

  app.get(
    "/public/llm-status",
    {
      config: {
        rateLimit: {
          max: 3,
          timeWindow: "1 minute"
        }
      }
    },
    async () => {
      const keyConfigured = config.LITELLM_API_KEY.trim().length >= 16;

      if (!keyConfigured) {
        return {
          status: "not_configured",
          model: config.LITELLM_MODEL,
          keyConfigured: false,
          error: "LITELLM_API_KEY is missing or too short"
        };
      }

      try {
        const response = await llmStatusChat(
          [
            {
              role: "system",
              content: "Reply with exactly: OK",
              timestamp: Date.now()
            },
            {
              role: "user",
              content: "Health check",
              timestamp: Date.now()
            }
          ],
          { model: config.LITELLM_MODEL, temperature: 0, maxTokens: 8 }
        );

        const sample = typeof response === "string" ? response : response.content;
        return {
          status: "ok",
          model: config.LITELLM_MODEL,
          keyConfigured: true,
          sample: sample.slice(0, 40)
        };
      } catch (error) {
        return {
          status: "upstream_error",
          model: config.LITELLM_MODEL,
          keyConfigured: true,
          error: summarizeLLMError(error)
        };
      }
    }
  );

  app.post<{ Body: PublicChatBody }>(
    "/v1/public/chat",
    {
      config: {
        rateLimit: {
          max: Math.max(3, Math.floor(config.RATE_LIMIT_MAX / 2)),
          timeWindow: config.RATE_LIMIT_WINDOW
        }
      },
      schema: { body: publicChatBodySchema }
    },
    async (request, reply) => {
      const history = normalizeHistory(request.body.history);

      if (request.body.ragContext && request.body.ragContext.trim().length > 0) {
        const sanitized = await ragSecurityGuard.sanitizeChunks([
          { content: request.body.ragContext, source: "public_rag_context" }
        ]);
        for (const chunk of sanitized.accepted) {
          history.push({
            role: "user",
            content: wrapUntrustedData(chunk.content, {
              source: chunk.source,
              trustLevel: chunk.trustLevel,
              chunkId: chunk.chunkId
            }),
            timestamp: Date.now()
          });
        }
      }

      const result = await pipeline.run({
        sessionId: request.body.sessionId ?? request.id,
        identity: PUBLIC_IDENTITY,
        rawInput: request.body.message,
        messages: history.slice(-config.MAX_SESSION_MESSAGES),
        toolInvocation: request.body.toolInvocation
      });

      if (result.action === "block") {
        return reply.code(400).send({
          error: "Request blocked",
          reason: result.guardResult.reason,
          requestId: request.id,
          riskLevel: result.riskLevel
        });
      }

      if (result.action === "require_confirmation") {
        return reply.code(202).send({
          requiresConfirmation: true,
          message: "High risk action requires confirmation",
          confirmationToken: result.confirmationToken ?? null,
          requestId: request.id,
          riskLevel: result.riskLevel
        });
      }

      return {
        response: result.response ?? "",
        requestId: request.id,
        riskLevel: result.riskLevel
      };
    }
  );
};

export default fp(publicRoutes, {
  name: "public-routes"
});
