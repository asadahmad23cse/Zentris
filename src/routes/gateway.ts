import fp from "fastify-plugin";
import { type FastifyPluginAsync, type FastifyReply, type FastifyRequest } from "fastify";
import { config } from "../config";
import { StreamingGuard } from "../guards/streamingGuard";
import { scanAndRedactSensitiveData } from "../guards/dlpGuard";
import { LiteLLMError } from "../llm/litellmClient";
import { StreamingClient } from "../llm/streamingClient";
import { ZentrisPipeline } from "../middleware/pipeline";
import { CircuitOpenError } from "../services/circuitBreaker";
import { TelemetryService } from "../services/telemetryService";
import { type ChatMessage, type GenerationOptions, type SecurityMetadata, type ZentrisRequest } from "../types";

interface OpenAIMessage { role: "system" | "user" | "assistant"; content: string; }
interface ChatCompletionsBody {
  model?: string;
  messages: OpenAIMessage[];
  stream?: boolean;
  stream_options?: { include_usage?: boolean };
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  stop?: string | string[];
  tools?: unknown[];
  tool_choice?: unknown;
  response_format?: unknown;
  user?: string;
}

const messageSchema = {
  type: "object", additionalProperties: false, required: ["role", "content"],
  properties: {
    role: { type: "string", enum: ["system", "user", "assistant"] },
    content: { type: "string", minLength: 1, maxLength: 262144 }
  }
} as const;

const bodySchema = {
  type: "object", additionalProperties: true, required: ["messages"],
  properties: {
    model: { type: "string", minLength: 1, maxLength: 256 },
    messages: { type: "array", minItems: 1, maxItems: 100, items: messageSchema },
    stream: { type: "boolean" },
    stream_options: { type: "object", additionalProperties: false, properties: { include_usage: { type: "boolean" } } },
    temperature: { type: "number", minimum: 0, maximum: 2 },
    max_tokens: { type: "integer", minimum: 1, maximum: 131072 },
    top_p: { type: "number", minimum: 0, maximum: 1 },
    stop: { anyOf: [{ type: "string", maxLength: 256 }, { type: "array", maxItems: 8, items: { type: "string", maxLength: 256 } }] },
    tools: { type: "array", maxItems: 128 },
    user: { type: "string", maxLength: 256 }
  }
} as const;

const bearerToken = (request: FastifyRequest): string | undefined => {
  const value = request.headers.authorization;
  return value?.startsWith("Bearer ") ? value.slice(7).trim() || undefined : undefined;
};

const generationOptions = (body: ChatCompletionsBody, request: FastifyRequest): GenerationOptions => ({
  model: body.model ?? config.LITELLM_MODEL,
  temperature: body.temperature,
  maxTokens: body.max_tokens,
  topP: body.top_p,
  stop: body.stop,
  tools: body.tools,
  toolChoice: body.tool_choice,
  responseFormat: body.response_format,
  apiKey: bearerToken(request)
});

const telemetryModelParameters = (body: ChatCompletionsBody): Record<string, unknown> => ({
  ...(body.temperature !== undefined ? { temperature: body.temperature } : {}),
  ...(body.max_tokens !== undefined ? { max_tokens: body.max_tokens } : {}),
  ...(body.top_p !== undefined ? { top_p: body.top_p } : {}),
  ...(body.stop !== undefined ? { stop: body.stop } : {}),
  ...(body.tools !== undefined ? { tools: body.tools } : {}),
  ...(body.tool_choice !== undefined ? { tool_choice: body.tool_choice } : {}),
  ...(body.response_format !== undefined ? { response_format: body.response_format } : {}),
  stream: Boolean(body.stream)
});

const setSecurityHeaders = (reply: FastifyReply, security: SecurityMetadata): void => {
  const action = security.injectionDetected && security.dlpDetected ? "warn_and_redact"
    : security.injectionDetected ? "warn" : security.dlpDetected ? "redact" : "allow";
  reply.header("X-Zentris-Request-Id", security.requestId);
  reply.header("X-Request-ID", security.requestId);
  reply.header("X-Zentris-Injection-Detected", String(security.injectionDetected));
  reply.header("X-Zentris-Security-Action", action);
  reply.header("X-Zentris-Risk", security.risk);
};

const safePublicSecurity = (security: SecurityMetadata): SecurityMetadata => ({
  ...security,
  findings: security.findings.map(({ start: _start, end: _end, ...finding }) => finding)
});

const upstreamStatus = (error: unknown): number => {
  if (error instanceof CircuitOpenError) return 503;
  if (error instanceof LiteLLMError) {
    if (error.llmReason === "request_timeout") return 504;
    if ([401, 403, 429].includes(error.statusCode)) return error.statusCode;
    return error.statusCode === 503 ? 503 : 502;
  }
  return 502;
};

const gatewayRoutes: FastifyPluginAsync = async (app) => {
  const pipeline = new ZentrisPipeline();
  const streamingClient = new StreamingClient();
  const streamingGuard = new StreamingGuard(config.STREAMING_ROLLING_BUFFER_CHARS, Number.MAX_SAFE_INTEGER);
  const telemetry = new TelemetryService();

  const handler = async (request: FastifyRequest, reply: FastifyReply) => {
    const startedAt = Date.now();
    const body = request.body as ChatCompletionsBody;
    const lastUserIndex = body.messages.map((message) => message.role).lastIndexOf("user");
    if (lastUserIndex < 0) {
      return reply.code(400).header("X-Zentris-Request-Id", request.id).send({
        error: { message: "No user message found", type: "invalid_request_error", code: "missing_user_message" }
      });
    }

    const history: ChatMessage[] = body.messages.slice(0, lastUserIndex).map((message, index) => ({
      role: message.role, content: message.content, timestamp: Date.now() + index
    }));
    const zentrisRequest: ZentrisRequest = {
      sessionId: typeof body.user === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(body.user) ? body.user : request.id,
      requestId: request.id,
      identity: request.identity,
      rawInput: body.messages[lastUserIndex].content,
      messages: history.slice(-config.MAX_SESSION_MESSAGES),
      generation: generationOptions(body, request)
    };

    if (body.stream) return handleStreaming(request, reply, zentrisRequest, body, startedAt);

    try {
      const result = await pipeline.run(zentrisRequest);
      await telemetry.enqueue({
        requestId: request.id,
        sessionId: zentrisRequest.sessionId,
        identity: request.identity,
        route: "/v1/chat/completions",
        model: body.model ?? config.LITELLM_MODEL,
        modelParameters: telemetryModelParameters(body),
        rawMessages: body.messages,
        sanitizedMessages: result.modelMessages ?? [],
        rawResult: result.rawResponse === undefined ? undefined : { role: "assistant", content: result.rawResponse },
        sanitizedResult: result.response === undefined ? undefined : { role: "assistant", content: result.response },
        status: result.action === "block" || result.action === "require_confirmation" ? "rejected" : "success",
        httpStatus: result.action === "block" ? 400 : result.action === "require_confirmation" ? 202 : 200,
        failureCode: result.action === "block" || result.action === "require_confirmation" ? result.guardResult.reason : undefined,
        latencyMs: Date.now() - startedAt,
        security: result.security
      });
      setSecurityHeaders(reply, result.security);
      if (result.action === "block") {
        return reply.code(result.guardResult.reason.startsWith("unauthorized") ? 403 : 400).send({
          error: { message: "Request rejected by an independent security policy", type: "security_error", code: result.guardResult.reason },
          zentris_security: safePublicSecurity(result.security)
        });
      }
      if (result.action === "require_confirmation") {
        return reply.code(202).send({
          error: { message: "High risk action requires confirmation", type: "security_error", code: "confirmation_required" },
          confirmation_token: result.confirmationToken ?? null,
          zentris_security: safePublicSecurity(result.security)
        });
      }
      return reply.send({
        id: `chatcmpl-${request.id}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: body.model ?? config.LITELLM_MODEL,
        modelParameters: telemetryModelParameters(body),
        choices: [{ index: 0, message: { role: "assistant", content: result.response ?? "" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
        zentris_security: safePublicSecurity(result.security)
      });
    } catch (error) {
      const failureSecurity: SecurityMetadata = {
        requestId: request.id, injectionDetected: false, warningApplied: false, dlpDetected: false,
        risk: "none", score: 0, matchedRules: [], findings: []
      };
      await telemetry.enqueue({
        requestId: request.id,
        sessionId: zentrisRequest.sessionId,
        identity: request.identity,
        route: "/v1/chat/completions",
        model: body.model ?? config.LITELLM_MODEL,
        rawMessages: body.messages,
        sanitizedMessages: [],
        status: "failed",
        httpStatus: upstreamStatus(error),
        failureCode: error instanceof LiteLLMError ? error.llmReason : error instanceof CircuitOpenError ? "circuit_open" : "upstream_unavailable",
        failureMessage: "Upstream model request failed",
        latencyMs: Date.now() - startedAt,
        security: failureSecurity
      });
      request.log.warn({ errorType: error instanceof Error ? error.name : "unknown" }, "upstream_completion_failed");
      return reply.code(upstreamStatus(error)).send({
        error: { message: "Upstream model request failed", type: "upstream_error", code: error instanceof LiteLLMError ? error.llmReason : "upstream_unavailable" }
      });
    }
  };

  const handleStreaming = async (
    request: FastifyRequest,
    reply: FastifyReply,
    zentrisRequest: ZentrisRequest,
    body: ChatCompletionsBody,
    startedAt: number
  ): Promise<unknown> => {
    let guards;
    try {
      guards = await pipeline.runGuards(zentrisRequest);
    } catch {
      return reply.code(500).send({ error: { message: "Security pipeline failed", type: "security_error" } });
    }
    setSecurityHeaders(reply, guards.security);
    if (guards.action === "block") {
      await telemetry.enqueue({
        requestId: request.id, sessionId: zentrisRequest.sessionId, identity: request.identity,
        route: "/v1/chat/completions", model: body.model ?? config.LITELLM_MODEL,
        modelParameters: telemetryModelParameters(body),
        rawMessages: body.messages, sanitizedMessages: guards.llmMessages, status: "rejected", httpStatus: 400,
        failureCode: guards.guardResult.reason, latencyMs: Date.now() - startedAt, security: guards.security
      });
      return reply.code(guards.guardResult.reason.startsWith("unauthorized") ? 403 : 400).send({
        error: { message: "Request rejected by an independent security policy", type: "security_error", code: guards.guardResult.reason },
        zentris_security: safePublicSecurity(guards.security)
      });
    }
    if (guards.action === "require_confirmation") {
      await telemetry.enqueue({
        requestId: request.id, sessionId: zentrisRequest.sessionId, identity: request.identity,
        route: "/v1/chat/completions", model: body.model ?? config.LITELLM_MODEL,
        modelParameters: telemetryModelParameters(body),
        rawMessages: body.messages, sanitizedMessages: guards.llmMessages, status: "rejected", httpStatus: 202,
        failureCode: guards.guardResult.reason, latencyMs: Date.now() - startedAt, security: guards.security
      });
      return reply.code(202).send({ error: { message: "Confirmation required", type: "security_error" }, confirmation_token: guards.confirmationToken ?? null });
    }

    reply.hijack();
    const response = reply.raw;
    response.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive",
      "X-Zentris-Request-Id": request.id, "X-Zentris-Injection-Detected": String(guards.security.injectionDetected),
      "X-Zentris-Security-Action": guards.security.injectionDetected ? "warn" : guards.security.dlpDetected ? "redact" : "allow",
      "X-Zentris-Risk": guards.security.risk
    });
    const completionId = `chatcmpl-${request.id}`;
    const created = Math.floor(Date.now() / 1000);
    const model = body.model ?? config.LITELLM_MODEL;
    const state = streamingGuard.createState();
    let rawOutput = "";
    let sanitizedOutput = "";
    let telemetryWrite: Promise<void> = Promise.resolve();
    let closed = false;
    const emit = (payload: Record<string, unknown>): void => {
      if (!closed && !response.writableEnded) response.write(`data: ${JSON.stringify(payload)}\n\n`);
    };
    const emitContent = (content: string, first = false): void => emit({
      id: completionId, object: "chat.completion.chunk", created, model,
      choices: [{ index: 0, delta: { ...(first ? { role: "assistant" } : {}), content }, finish_reason: null }],
      ...(first ? { zentris_security: safePublicSecurity(guards.security) } : {})
    });
    emitContent("", true);

    await streamingClient.streamChat(
      completionId,
      guards.llmMessages,
      generationOptions(body, request),
      (chunk) => {
        rawOutput += chunk;
        const inspection = streamingGuard.inspectChunk(chunk, state);
        for (const safeChunk of inspection.redactedChunks) {
          sanitizedOutput += safeChunk;
          emitContent(safeChunk);
        }
      },
      () => {
        const final = streamingGuard.flush(state);
        for (const safeChunk of final.redactedChunks) {
          sanitizedOutput += safeChunk;
          emitContent(safeChunk);
        }
        const finalScan = scanAndRedactSensitiveData(rawOutput, "output");
        guards.security.findings.push(...finalScan.findings);
        guards.security.dlpDetected ||= finalScan.findings.length > 0;
        guards.security.matchedRules = Array.from(new Set(guards.security.findings.map((finding) => finding.ruleId)));
        guards.security.score = Math.max(guards.security.score, ...finalScan.findings.map((finding) => finding.score), 0);
        if (guards.security.score >= 70) guards.security.risk = "high";
        else if (guards.security.score >= 40) guards.security.risk = "medium";
        telemetryWrite = telemetry.enqueue({
          requestId: request.id, sessionId: zentrisRequest.sessionId, identity: request.identity,
          route: "/v1/chat/completions", model, rawMessages: body.messages, sanitizedMessages: guards.llmMessages,
          modelParameters: telemetryModelParameters(body),
          rawResult: { role: "assistant", content: rawOutput },
          sanitizedResult: { role: "assistant", content: sanitizedOutput || finalScan.redacted },
          status: "success", httpStatus: 200, latencyMs: Date.now() - startedAt, security: guards.security
        });
        const stopChunk: Record<string, unknown> = {
          id: completionId, object: "chat.completion.chunk", created, model,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }]
        };
        if (body.stream_options?.include_usage) stopChunk.usage = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
        emit(stopChunk);
        if (!response.writableEnded) response.write("data: [DONE]\n\n");
        closed = true;
        response.end();
      },
      (error) => {
        request.log.warn({ errorType: error.name }, "upstream_stream_failed");
        telemetryWrite = telemetry.enqueue({
          requestId: request.id, sessionId: zentrisRequest.sessionId, identity: request.identity,
          route: "/v1/chat/completions", model, rawMessages: body.messages, sanitizedMessages: guards.llmMessages,
          modelParameters: telemetryModelParameters(body),
          rawResult: rawOutput ? { role: "assistant", content: rawOutput } : undefined,
          sanitizedResult: sanitizedOutput ? { role: "assistant", content: sanitizedOutput } : undefined,
          status: "failed", httpStatus: upstreamStatus(error),
          failureCode: error instanceof LiteLLMError ? error.llmReason : "upstream_unavailable",
          failureMessage: "Upstream model stream failed", latencyMs: Date.now() - startedAt, security: guards.security
        });
        emit({ error: { message: "Upstream model stream failed", type: "upstream_error" } });
        closed = true;
        response.end();
      }
    );
    await telemetryWrite;
    return undefined;
  };

  app.post("/v1/chat/completions", { schema: { body: bodySchema } }, handler);
  app.post("/chat/completions", { schema: { body: bodySchema } }, handler);

  // ── Dashboard compatibility stubs ─────────────────────────────────────────

  const modelList = {
    object: "list",
    data: [
      { id: "gpt-4o-mini", object: "model", owned_by: "openai" },
      { id: "gpt-4o",      object: "model", owned_by: "openai" },
      { id: "claude-3-5-sonnet", object: "model", owned_by: "anthropic" },
      { id: "gemini-1.5-flash",  object: "model", owned_by: "google"    }
    ]
  };
  const modelInfoData = [
    { model_name: "gpt-4o-mini", litellm_params: { model: "gpt-4o-mini" }, model_info: { id: "gpt-4o-mini", mode: "chat", input_cost_per_token: 0.00000015, output_cost_per_token: 0.0000006, max_input_tokens: 128000, max_output_tokens: 16384, supports_function_calling: true, supports_vision: true } },
    { model_name: "gpt-4o",      litellm_params: { model: "gpt-4o"      }, model_info: { id: "gpt-4o",      mode: "chat", input_cost_per_token: 0.0000025,  output_cost_per_token: 0.00001,   max_input_tokens: 128000, max_output_tokens: 16384, supports_function_calling: true, supports_vision: true } }
  ];
  const demoKey = {
    token: "sk-zentris-demo-xxxxxxxx", key_alias: "Zentris Demo Key", key_name: "sk-...xxxx",
    spend: 0, max_budget: null, expires: null, models: ["gpt-4o-mini", "gpt-4o"],
    user_id: "public-admin", team_id: null, permissions: {},
    created_at: new Date().toISOString(), updated_at: new Date().toISOString()
  };

  // Models
  app.get("/v1/models",    async () => modelList);
  app.get("/models",       async () => modelList);
  app.get("/model/info",   async () => ({ data: modelInfoData }));
  app.get("/v1/model/info",async () => ({ data: modelInfoData }));
  app.get("/v2/model/info",async () => ({ data: modelInfoData }));
  app.get("/model_group/info", async () => ({ data: [] }));

  // Keys
  app.get("/key/info",     async () => ({ info: { token: "sk-zentris-public", key_name: "Public Demo Key", spend: 0, max_budget: null, expires: null, models: ["gpt-4o-mini", "gpt-4o"], user_id: "public-admin" } }));
  app.get("/key/list",     async () => ({ keys: [demoKey], total: 1 }));
  app.get("/v2/key/info",  async () => demoKey);
  app.get("/key/aliases",  async () => []);
  app.post("/key/generate",async () => ({ key: "sk-zentris-demo", key_name: "Demo Key", expires: null, user_id: "public-admin", models: ["gpt-4o-mini", "gpt-4o"], spend: 0, max_budget: null }));
  app.post("/key/delete",  async () => ({ deleted: true }));
  app.post("/key/update",  async () => demoKey);

  // Users
  app.get("/user/info",    async () => ({ user_id: "public-admin", user_role: "proxy_admin", spend: 0, max_budget: null }));
  app.get("/user/list",    async () => [{ user_id: "public-admin", user_role: "proxy_admin", spend: 0, max_budget: null }]);
  app.get("/v2/user/info", async () => ({ user_id: "public-admin", user_role: "proxy_admin", spend: 0, max_budget: null, teams: [], keys: [] }));
  app.get("/user/filter/ui", async () => ({ users: [], total: 0 }));
  app.get("/user/available_roles", async () => ["proxy_admin", "proxy_user", "app_user", "app_owner", "team_admin"]);
  app.get("/user/daily/activity", async () => ({ data: [] }));
  app.get("/user/daily/activity/aggregated", async () => ({ data: [] }));

  // Teams
  app.get("/team/list",      async () => []);
  app.post("/team/list",     async () => []);
  app.get("/v2/team/list",   async () => ({ teams: [], total: 0 }));
  app.get("/team/available", async () => []);
  app.get("/team/info",      async () => ({ team_id: null, team_alias: null, members_with_roles: [] }));
  app.get("/team/daily/activity", async () => ({ data: [] }));

  // Organizations & budgets
  app.get("/organization/list",   async () => []);
  app.get("/organization/info",   async () => null);
  app.get("/organization/daily/activity", async () => ({ data: [] }));
  app.get("/budget/list",         async () => []);
  app.get("/access_group/list",   async () => []);
  app.get("/customer/list",       async () => []);
  app.get("/customer/daily/activity", async () => ({ data: [] }));

  // Spend / usage
  app.get("/global/spend",         async () => ({ spend: 0, max_budget: null }));
  app.get("/global/spend/logs",    async () => []);
  app.get("/global/spend/report",  async () => ({ data: [] }));
  app.get("/global/spend/all_tag_names", async () => []);
  app.get("/global/all_end_users", async () => []);
  app.get("/global/spend/keys",    async () => []);
  app.get("/global/spend/tags",    async () => []);
  app.get("/global/spend/provider",async () => []);
  app.get("/global/spend/teams",   async () => []);
  app.get("/global/spend/end_users", async () => []);
  app.get("/global/spend/models",  async () => []);
  app.get("/global/predict/spend/logs", async () => ({ data: [] }));
  app.get("/global/activity",      async () => ({ data: [] }));
  app.get("/global/activity/cache_hits", async () => ({ data: [] }));
  app.get("/global/activity/model", async () => ({ data: [] }));

  // Logs / audit
  app.get("/spend/logs/ui",        async () => ({ data: [], total: 0, page: 0, page_size: 50 }));
  app.get("/spend/logs/ui/:logId", async () => ({ data: null }));
  app.get("/spend/logs/session/ui",async () => ({ data: [] }));
  app.get("/audit",                async () => ({ data: [] }));

  // Tags
  app.get("/tag/list",    async () => []);
  app.get("/tag/dau",     async () => ({ data: [] }));
  app.get("/tag/wau",     async () => ({ data: [] }));
  app.get("/tag/mau",     async () => ({ data: [] }));
  app.get("/tag/daily/activity", async () => ({ data: [] }));
  app.get("/agent/daily/activity", async () => ({ data: [] }));

  // Guardrails
  app.get("/guardrails/list",   async () => ({ guardrails: [] }));
  app.get("/v2/guardrails/list",async () => ({ guardrails: [] }));
  app.post("/guardrails",       async () => ({ guardrail_id: "demo", guardrail_name: "demo" }));
  app.delete("/guardrails/:guardrailId", async () => ({ deleted: true }));
  app.patch("/guardrails/:guardrailId",  async () => ({}));
  app.post("/guardrails/apply_guardrail", async () => ({ safe: true }));
  app.get("/guardrails/ui/add_guardrail_settings", async () => ({}));
  app.get("/guardrails/submissions", async () => ({ data: [] }));

  // Policies
  app.get("/policy/list",             async () => []);
  app.get("/policies/list",           async () => ({ policies: [], total: 0 }));
  app.get("/policies/attachments/list", async () => ({ attachments: [] }));
  app.get("/policies/:policyId",      async () => null);
  app.get("/policy/info/:policyName", async () => null);
  app.post("/policies/test",          async () => ({ results: [] }));

  // Settings / config
  app.get("/sso/get/ui_settings",     async () => ({ status: "success" }));
  app.get("/get/ui_settings",         async () => ({ status: "success" }));
  app.get("/get/internal_user_settings", async () => ({}));
  app.get("/get/allowed_ips",         async () => ({ allowed_ips: [] }));
  app.get("/get/config/callbacks",    async () => ({ status: "success", callbacks: [], alerting: [] }));
  app.get("/callbacks/configs",       async () => ({ callbacks: [] }));
  app.get("/alerting/settings",       async () => ({ alerting: [] }));
  app.get("/router/settings",         async () => ({ routing_strategy: "simple-shuffle", model_group_alias: {} }));
  app.get("/cache/settings",          async () => ({ cache: "none" }));
  app.get("/config/list",             async () => ({ PROXY_BASE_URL: "https://zentris-api.onrender.com", Zentris_UI_API_DOC_BASE_URL: null }));
  app.get("/config/pass_through_endpoint", async () => ({ endpoints: [] }));
  app.get("/config/field/info",       async () => ({}));
  app.get("/credentials",             async () => ({ credentials: [] }));

  // Misc / other
  app.get("/in-product-nudges",       async () => ({ nudges: [] }));
  app.get("/in_product_nudges",       async () => ({ nudges: [] }));
  app.get("/vector_store/list",       async () => []);
  app.get("/openai/deployments",      async () => ({ data: [] }));
  app.get("/openai.json",             async () => ({ openapi: "3.0.0", info: { title: "Zentris AI Gateway", version: "1.0.0" }, paths: {} }));
  app.get("/openapi/deployments",     async () => ({ data: [] }));
  app.get("/mcp_server/list",         async () => []);
  app.get("/v1/mcp/server",          async () => ({ data: [] }));
  app.get("/v1/agents",              async () => ({ data: [] }));
  app.get("/health/test_connection",  async () => ({ status: "ok" }));
  app.get("/health/latest",          async () => ({ status: "ok" }));
  app.get("/public/providers/fields", async () => []);
  app.get("/public/agents/fields",   async () => []);
};

export default fp(gatewayRoutes, { name: "gateway-routes" });
