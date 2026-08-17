import fp from "fastify-plugin";
import { type FastifyPluginAsync, type FastifyRequest, type FastifyReply } from "fastify";
import { ZentrisPipeline } from "../middleware/pipeline";
import { config } from "../config";
import { type ChatMessage, type ZentrisRequest } from "../types";

interface OpenAIMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface ChatCompletionsBody {
  model?: string;
  messages: OpenAIMessage[];
  stream?: boolean;
  stream_options?: { include_usage?: boolean };
  temperature?: number;
  max_tokens?: number;
}

const gatewayRoutes: FastifyPluginAsync = async (app) => {
  const pipeline = new ZentrisPipeline();

  const handler = async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as ChatCompletionsBody;
    const messages = body.messages ?? [];
    const lastUserMessage = [...messages].reverse().find((m) => m.role === "user");

    if (!lastUserMessage) {
      return reply.code(400).header("X-Request-ID", request.id).send({
        error: { message: "No user message found", type: "invalid_request_error" }
      });
    }

    const identity = (request as any).identity ?? {
      userId: "anonymous",
      userRole: "anonymous",
      tenantId: null,
      orgId: null
    };

    const history: ChatMessage[] = messages.slice(0, -1).map((m) => ({
      role: m.role,
      content: m.content,
      timestamp: Date.now()
    }));

    const zentrisRequest: ZentrisRequest = {
      sessionId: request.id,
      identity: {
        userId: identity.userId,
        userRole: identity.userRole as "admin" | "operator" | "viewer" | "anonymous",
        tenantId: identity.tenantId,
        orgId: identity.orgId
      },
      rawInput: lastUserMessage.content,
      messages: history.slice(-config.MAX_SESSION_MESSAGES)
    };

    const result = await pipeline.run(zentrisRequest);

    if (result.action === "block") {
      return reply.code(400).header("X-Request-ID", request.id).send({
        error: {
          message: `Request blocked by Zentris security: ${result.guardResult.reason}`,
          type: "security_error",
          code: "content_blocked"
        },
        zentris: {
          action: "block",
          riskLevel: result.riskLevel,
          reason: result.guardResult.reason
        }
      });
    }

    if (result.action === "require_confirmation") {
      return reply.code(202).header("X-Request-ID", request.id).send({
        error: {
          message: "High risk action requires confirmation",
          type: "security_error",
          code: "confirmation_required"
        },
        zentris: {
          action: "require_confirmation",
          riskLevel: result.riskLevel,
          confirmationToken: result.confirmationToken ?? null
        }
      });
    }

    const responseText = result.response ?? "";
    const completionId = `chatcmpl-${request.id}`;
    const created = Math.floor(Date.now() / 1000);
    const model = body.model ?? config.LITELLM_MODEL;

    reply.header("X-Request-ID", request.id);
    reply.header("X-Risk-Level", result.riskLevel);
    reply.header("X-Zentris-Action", result.action);

    if (body.stream) {
      const origin = request.headers.origin;
      reply.raw.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Request-ID": request.id,
        "X-Risk-Level": result.riskLevel,
        "X-Zentris-Action": result.action,
        ...(origin ? {
          "Access-Control-Allow-Origin": origin,
          "Vary": "Origin",
          "Access-Control-Allow-Headers": "authorization,content-type,x-zentris-tags,x-stainless-lang,x-stainless-package-version,x-stainless-os,x-stainless-arch,x-stainless-runtime,x-stainless-runtime-version,x-stainless-retry-count,x-stainless-timeout",
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        } : {})
      });

      const roleChunk = {
        id: completionId,
        object: "chat.completion.chunk",
        created,
        model,
        choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }]
      };
      reply.raw.write(`data: ${JSON.stringify(roleChunk)}\n\n`);

      const contentChunk = {
        id: completionId,
        object: "chat.completion.chunk",
        created,
        model,
        choices: [{ index: 0, delta: { content: responseText }, finish_reason: null }]
      };
      reply.raw.write(`data: ${JSON.stringify(contentChunk)}\n\n`);

      const stopChunk: any = {
        id: completionId,
        object: "chat.completion.chunk",
        created,
        model,
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }]
      };
      if (body.stream_options?.include_usage) {
        stopChunk.usage = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
      }
      reply.raw.write(`data: ${JSON.stringify(stopChunk)}\n\n`);
      reply.raw.write("data: [DONE]\n\n");
      reply.raw.end();
      return;
    }

    return {
      id: completionId,
      object: "chat.completion",
      created,
      model,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: responseText
          },
          finish_reason: "stop"
        }
      ],
      usage: {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0
      },
      zentris: {
        action: result.action,
        riskLevel: result.riskLevel
      }
    };
  };

  app.post("/v1/chat/completions", handler);
  app.post("/chat/completions", handler);

  app.get("/v1/models", async () => ({
    object: "list",
    data: [
      { id: "gpt-4o-mini", object: "model", owned_by: "openai" },
      { id: "gpt-4o", object: "model", owned_by: "openai" },
      { id: "claude-3-5-sonnet", object: "model", owned_by: "anthropic" },
      { id: "gemini-1.5-flash", object: "model", owned_by: "google" }
    ]
  }));

  app.get("/models", async () => ({
    object: "list",
    data: [
      { id: "gpt-4o-mini", object: "model", owned_by: "openai" },
      { id: "gpt-4o", object: "model", owned_by: "openai" },
      { id: "claude-3-5-sonnet", object: "model", owned_by: "anthropic" },
      { id: "gemini-1.5-flash", object: "model", owned_by: "google" }
    ]
  }));

  app.get("/model/info", async () => ({
    data: [
      {
        model_name: "gpt-4o-mini",
        litellm_params: { model: "gpt-4o-mini" },
        model_info: {
          id: "gpt-4o-mini",
          mode: "chat",
          input_cost_per_token: 0.00000015,
          output_cost_per_token: 0.0000006,
          max_input_tokens: 128000,
          max_output_tokens: 16384,
          supports_function_calling: true,
          supports_vision: true
        }
      },
      {
        model_name: "gpt-4o",
        litellm_params: { model: "gpt-4o" },
        model_info: {
          id: "gpt-4o",
          mode: "chat",
          input_cost_per_token: 0.0000025,
          output_cost_per_token: 0.00001,
          max_input_tokens: 128000,
          max_output_tokens: 16384,
          supports_function_calling: true,
          supports_vision: true
        }
      }
    ]
  }));

  app.get("/key/info", async () => ({
    info: {
      token: "sk-zentris-public",
      key_name: "Public Demo Key",
      spend: 0,
      max_budget: null,
      expires: null,
      models: ["gpt-4o-mini", "gpt-4o"],
      user_id: "public-admin"
    }
  }));

  app.get("/global/spend/logs", async () => []);
  app.get("/global/spend/report", async () => ({ data: [] }));
  app.get("/user/info", async () => ({
    user_id: "public-admin",
    user_role: "proxy_admin",
    spend: 0,
    max_budget: null
  }));

  app.get("/guardrails/list", async () => ({ guardrails: [] }));

  app.get("/team/list", async () => []);
  app.post("/team/list", async () => []);

  app.get("/global/spend", async () => ({ spend: 0, max_budget: null }));
  app.get("/global/spend/all_tag_names", async () => []);
  app.get("/global/all_end_users", async () => []);

  app.get("/v1/model/info", async () => ({
    data: [
      {
        model_name: "gpt-4o-mini",
        litellm_params: { model: "gpt-4o-mini" },
        model_info: { id: "gpt-4o-mini", mode: "chat" }
      },
      {
        model_name: "gpt-4o",
        litellm_params: { model: "gpt-4o" },
        model_info: { id: "gpt-4o", mode: "chat" }
      }
    ]
  }));

  app.get("/get/config/callbacks", async () => ({
    status: "success",
    callbacks: [],
    alerting: []
  }));

  app.get("/sso/get/ui_settings", async () => ({ status: "success" }));
  app.get("/get/allowed_ips", async () => ({ allowed_ips: [] }));
  app.get("/budget/list", async () => []);
  app.get("/organization/list", async () => []);

  const modelInfoData = [
    {
      model_name: "gpt-4o-mini",
      litellm_params: { model: "gpt-4o-mini" },
      model_info: {
        id: "gpt-4o-mini",
        mode: "chat",
        input_cost_per_token: 0.00000015,
        output_cost_per_token: 0.0000006,
        max_input_tokens: 128000,
        max_output_tokens: 16384,
        supports_function_calling: true,
        supports_vision: true
      }
    },
    {
      model_name: "gpt-4o",
      litellm_params: { model: "gpt-4o" },
      model_info: {
        id: "gpt-4o",
        mode: "chat",
        input_cost_per_token: 0.0000025,
        output_cost_per_token: 0.00001,
        max_input_tokens: 128000,
        max_output_tokens: 16384,
        supports_function_calling: true,
        supports_vision: true
      }
    }
  ];

  app.get("/v2/model/info", async () => ({ data: modelInfoData }));

  app.post("/key/generate", { config: { rawBody: false } }, async () => ({
    key: "sk-zentris-demo",
    key_name: "Demo Key",
    expires: null,
    user_id: "public-admin",
    models: ["gpt-4o-mini", "gpt-4o"],
    spend: 0,
    max_budget: null
  }));

  app.get("/mcp_server/list", async () => []);
  app.get("/policy/list", async () => []);
  app.get("/in-product-nudges", async () => ({ nudges: [] }));

  app.get("/config/list", async () => ({
    PROXY_BASE_URL: "",
    Zentris_UI_API_DOC_BASE_URL: null
  }));
  app.get("/global/spend/provider", async () => []);
  app.get("/global/activity", async () => ({ data: [] }));
  app.get("/vector_store/list", async () => []);

  app.get("/openai/deployments", async () => ({ data: [] }));
  app.get("/access_group/list", async () => []);
};

export default fp(gatewayRoutes, { name: "gateway-routes" });
