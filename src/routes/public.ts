import fp from "fastify-plugin";
import { type FastifyPluginAsync } from "fastify";
import { RagSecurityGuard } from "../guards/ragSecurityGuard";
import { wrapUntrustedData } from "../guards/ragWrapper";
import { type LLMChat, ZentrisPipeline } from "../middleware/pipeline";
import { config } from "../config";
import { createAccessToken } from "../auth/jwt";
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

const PUBLIC_MODELS = [
  {
    model_group: "gpt-4o-mini",
    providers: ["openai"],
    mode: "chat",
    max_input_tokens: 128000,
    max_output_tokens: 16384,
    input_cost_per_token: 0.00000015,
    output_cost_per_token: 0.0000006,
    supports_function_calling: true,
    supports_parallel_function_calling: true,
    supports_vision: true,
    health_status: "available"
  },
  {
    model_group: "gpt-4o",
    providers: ["openai"],
    mode: "chat",
    max_input_tokens: 128000,
    max_output_tokens: 16384,
    input_cost_per_token: 0.0000025,
    output_cost_per_token: 0.00001,
    supports_function_calling: true,
    supports_parallel_function_calling: true,
    supports_vision: true,
    health_status: "available"
  },
  {
    model_group: "claude-3-5-sonnet",
    providers: ["anthropic"],
    mode: "chat",
    max_input_tokens: 200000,
    max_output_tokens: 8192,
    input_cost_per_token: 0.000003,
    output_cost_per_token: 0.000015,
    supports_function_calling: true,
    supports_parallel_function_calling: false,
    supports_vision: true,
    health_status: "available"
  },
  {
    model_group: "gemini-1.5-flash",
    providers: ["gemini"],
    mode: "chat",
    max_input_tokens: 1000000,
    max_output_tokens: 8192,
    input_cost_per_token: 0.000000075,
    output_cost_per_token: 0.0000003,
    supports_function_calling: true,
    supports_parallel_function_calling: true,
    supports_vision: true,
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

const publicRoutes: FastifyPluginAsync<PublicRouteOptions> = async (app, options) => {
  const ragSecurityGuard = new RagSecurityGuard();
  const pipeline = new ZentrisPipeline({ litellmChat: options.litellmChat });

  app.get("/.well-known/litellm-ui-config", async (request) => {
    const host = request.headers.host;
    const protocol = host?.includes("localhost") ? "http" : "https";

    return {
      server_root_path: "/",
      proxy_base_url: host ? `${protocol}://${host}` : null,
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
    Zentris_version: "1.0.0",
    useful_links: {
      "Backend health": { url: "/health/readiness", index: 1 },
      "Chat API": { url: "/v1/public/chat", index: 2 }
    }
  }));

  app.get("/public/model_hub", async () => PUBLIC_MODELS);
  app.get("/public/agent_hub", async () => []);
  app.get("/public/mcp_hub", async () => []);

  app.get("/public/dashboard-token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = createAccessToken(
      {
        sub: "public-admin",
        role: "admin",
        key: "public-admin",
        user_id: "public-admin",
        user_email: "admin@zentris.local",
        user_role: "proxy_admin",
        login_method: "public_access",
        premium_user: false,
        exp: now + 7 * 24 * 60 * 60
      },
      config.JWT_SECRET
    );

    return {
      token,
      expires_in: 7 * 24 * 60 * 60
    };
  });

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
