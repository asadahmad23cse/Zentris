import fp from "fastify-plugin";
import { type FastifyPluginAsync, type FastifyReply, type FastifyRequest } from "fastify";
import { config } from "../config";
import { createAccessToken } from "../auth/jwt";
import { StreamingGuard } from "../guards/streamingGuard";
import { scanAndRedactSensitiveData } from "../guards/dlpGuard";
import { LiteLLMError } from "../llm/litellmClient";
import { StreamingClient, type StreamPayload } from "../llm/streamingClient";
import { ZentrisPipeline } from "../middleware/pipeline";
import { CircuitOpenError } from "../services/circuitBreaker";
import { TelemetryService } from "../services/telemetryService";
import { listAgents, createAgent, deleteAgent, setAgentsPublic } from "../services/agentStore";
import { listMCPServers, createMCPServer, updateMCPServer, deleteMCPServer } from "../services/mcpServerStore";
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

// Only real upstream provider keys (sk-.../gsk_...) may be forwarded to the LLM.
// The dashboard's "Current UI Session" sends a Zentris JWT (login_method=
// public_access), which is not a provider credential — forwarding it makes the
// upstream reject with 401. A non-provider token falls back to LITELLM_API_KEY.
const PROVIDER_KEY_PREFIX = /^(sk-|sk_|gsk_)/;
const upstreamApiKey = (request: FastifyRequest): string | undefined => {
  const token = bearerToken(request);
  return token && PROVIDER_KEY_PREFIX.test(token) ? token : undefined;
};

const generationOptions = (body: ChatCompletionsBody, request: FastifyRequest): GenerationOptions => ({
  model: body.model ?? config.LITELLM_MODEL,
  streamOptions: body.stream_options === undefined
    ? undefined
    : { includeUsage: body.stream_options.include_usage },
  temperature: body.temperature,
  maxTokens: body.max_tokens,
  topP: body.top_p,
  stop: body.stop,
  tools: body.tools,
  toolChoice: body.tool_choice,
  responseFormat: body.response_format,
  apiKey: upstreamApiKey(request)
});

const telemetryModelParameters = (body: ChatCompletionsBody): Record<string, unknown> => ({
  ...(body.temperature !== undefined ? { temperature: body.temperature } : {}),
  ...(body.max_tokens !== undefined ? { max_tokens: body.max_tokens } : {}),
  ...(body.top_p !== undefined ? { top_p: body.top_p } : {}),
  ...(body.stop !== undefined ? { stop: body.stop } : {}),
  ...(body.tools !== undefined ? { tools: body.tools } : {}),
  ...(body.tool_choice !== undefined ? { tool_choice: body.tool_choice } : {}),
  ...(body.response_format !== undefined ? { response_format: body.response_format } : {}),
  ...(body.stream_options !== undefined ? { stream_options: body.stream_options } : {}),
  stream: Boolean(body.stream)
});

const securityAction = (security: SecurityMetadata): string =>
  security.injectionDetected && security.dlpDetected ? "warn_and_redact"
    : security.injectionDetected ? "warn" : security.dlpDetected ? "redact" : "allow";

const setSecurityHeaders = (reply: FastifyReply, security: SecurityMetadata): void => {
  const action = securityAction(security);
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

const makeSecurityState = (requestId: string): SecurityMetadata => ({
  requestId,
  injectionDetected: false,
  warningApplied: false,
  dlpDetected: false,
  risk: "none",
  score: 0,
  matchedRules: [],
  findings: []
});

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
    const hasStableSession = typeof body.user === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(body.user);
    const zentrisRequest: ZentrisRequest = {
      sessionId: hasStableSession ? body.user as string : request.id,
      persistContext: hasStableSession,
      requestId: request.id,
      identity: request.identity,
      rawInput: body.messages[lastUserIndex].content,
      messages: history.slice(-config.MAX_SESSION_MESSAGES),
      generation: generationOptions(body, request)
    };

    if (body.stream) return handleStreaming(request, reply, zentrisRequest, body, startedAt);

    let security = makeSecurityState(request.id);
    try {
      const result = await pipeline.run(zentrisRequest);
      security = result.security;
      void telemetry.enqueue({
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
        security
      });
      setSecurityHeaders(reply, security);
      if (result.action === "block") {
        return reply.code(result.guardResult.reason.startsWith("unauthorized") ? 403 : 400).send({
          error: { message: "Request rejected by an independent security policy", type: "security_error", code: result.guardResult.reason },
          zentris_security: safePublicSecurity(security)
        });
      }
      if (result.action === "require_confirmation") {
        return reply.code(202).send({
          error: { message: "High risk action requires confirmation", type: "security_error", code: "confirmation_required" },
          confirmation_token: result.confirmationToken ?? null,
          zentris_security: safePublicSecurity(security)
        });
      }
      if (!result.upstreamResponse) {
        throw new LiteLLMError("LiteLLM response body was unavailable", 502, "malformed_response");
      }
      const responseBody = structuredClone(result.upstreamResponse) as Record<string, unknown>;
      const choices = responseBody.choices;
      if (!Array.isArray(choices) || !choices[0] || typeof choices[0] !== "object") {
        throw new LiteLLMError("LiteLLM choices were unavailable", 502, "malformed_response");
      }
      const firstChoice = choices[0] as Record<string, unknown>;
      if (!firstChoice.message || typeof firstChoice.message !== "object") {
        throw new LiteLLMError("LiteLLM message was unavailable", 502, "malformed_response");
      }
      (firstChoice.message as Record<string, unknown>).content = result.response ?? "";
      responseBody.zentris_security = safePublicSecurity(security);
      return reply.send(responseBody);
    } catch (error) {
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
        security
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
    const security = guards.security;
    setSecurityHeaders(reply, security);
    if (guards.action === "block") {
      await telemetry.enqueue({
        requestId: request.id, sessionId: zentrisRequest.sessionId, identity: request.identity,
        route: "/v1/chat/completions", model: body.model ?? config.LITELLM_MODEL,
        modelParameters: telemetryModelParameters(body),
        rawMessages: body.messages, sanitizedMessages: guards.llmMessages, status: "rejected", httpStatus: 400,
        failureCode: guards.guardResult.reason, latencyMs: Date.now() - startedAt, security
      });
      return reply.code(guards.guardResult.reason.startsWith("unauthorized") ? 403 : 400).send({
        error: { message: "Request rejected by an independent security policy", type: "security_error", code: guards.guardResult.reason },
        zentris_security: safePublicSecurity(security)
      });
    }
    if (guards.action === "require_confirmation") {
      await telemetry.enqueue({
        requestId: request.id, sessionId: zentrisRequest.sessionId, identity: request.identity,
        route: "/v1/chat/completions", model: body.model ?? config.LITELLM_MODEL,
        modelParameters: telemetryModelParameters(body),
        rawMessages: body.messages, sanitizedMessages: guards.llmMessages, status: "rejected", httpStatus: 202,
        failureCode: guards.guardResult.reason, latencyMs: Date.now() - startedAt, security
      });
      return reply.code(202).send({ error: { message: "Confirmation required", type: "security_error" }, confirmation_token: guards.confirmationToken ?? null });
    }

    reply.hijack();
    const response = reply.raw;
    response.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive",
      "X-Zentris-Request-Id": request.id, "X-Zentris-Injection-Detected": String(security.injectionDetected),
      "X-Zentris-Security-Action": securityAction(security), "X-Zentris-Risk": security.risk
    });
    const completionId = `chatcmpl-${request.id}`;
    const model = body.model ?? config.LITELLM_MODEL;
    const state = streamingGuard.createState();
    let rawOutput = "";
    let sanitizedOutput = "";
    let telemetryWrite: Promise<void> = Promise.resolve();
    let closed = false;
    let securitySent = false;
    let lastContentTemplate: StreamPayload | undefined;
    const pendingTerminalEvents: StreamPayload[] = [];
    const emit = (payload: Record<string, unknown>, finalSecurity = false): void => {
      const decorated = structuredClone(payload);
      if (!securitySent || finalSecurity) {
        decorated.zentris_security = safePublicSecurity(security);
        securitySent = true;
      }
      if (!closed && !response.writableEnded) response.write(`data: ${JSON.stringify(decorated)}\n\n`);
    };
    const emitContent = (content: string): void => {
      const payload = structuredClone(lastContentTemplate ?? {
        id: completionId,
        object: "chat.completion.chunk",
        model,
        choices: [{ index: 0, delta: {}, finish_reason: null }]
      }) as StreamPayload;
      const choices = payload.choices;
      if (Array.isArray(choices) && choices[0]) {
        choices[0].delta = { ...(choices[0].delta ?? {}), content };
      }
      emit(payload);
    };
    const recordOutputFindings = (findings: ReturnType<typeof scanAndRedactSensitiveData>["findings"]): void => {
      security.findings.push(...findings);
      security.dlpDetected ||= findings.length > 0;
    };
    const sanitizeToolArguments = (payload: StreamPayload): StreamPayload => {
      const copy = structuredClone(payload);
      const visit = (value: unknown, key?: string): unknown => {
        if (typeof value === "string" && key === "arguments") {
          const scan = scanAndRedactSensitiveData(value, "output");
          recordOutputFindings(scan.findings);
          return scan.redacted;
        }
        if (Array.isArray(value)) return value.map((entry) => visit(entry));
        if (value && typeof value === "object") {
          for (const [childKey, child] of Object.entries(value)) {
            (value as Record<string, unknown>)[childKey] = visit(child, childKey);
          }
        }
        return value;
      };
      return visit(copy) as StreamPayload;
    };
    const isTerminalEvent = (payload: StreamPayload): boolean => {
      const choices = payload.choices;
      return (Array.isArray(choices) && choices.some((choice) => choice.finish_reason != null)) || "usage" in payload;
    };

    await streamingClient.streamChat(
      completionId,
      guards.llmMessages,
      guards.generation ?? {},
      () => {},
      () => {
        const final = streamingGuard.flush(state);
        for (const safeChunk of final.redactedChunks) {
          sanitizedOutput += safeChunk;
          emitContent(safeChunk);
        }
        const finalScan = scanAndRedactSensitiveData(rawOutput, "output");
        security.findings.push(...finalScan.findings);
        security.dlpDetected ||= finalScan.findings.length > 0;
        security.matchedRules = Array.from(new Set(security.findings.map((finding) => finding.ruleId)));
        security.score = Math.max(security.score, ...finalScan.findings.map((finding) => finding.score), 0);
        if (security.score >= 70) security.risk = "high";
        else if (security.score >= 40) security.risk = "medium";
        else if (security.score > 0) security.risk = "low";
        telemetryWrite = telemetry.enqueue({
          requestId: request.id, sessionId: zentrisRequest.sessionId, identity: request.identity,
          route: "/v1/chat/completions", model, rawMessages: body.messages, sanitizedMessages: guards.llmMessages,
          modelParameters: telemetryModelParameters(body),
          rawResult: { role: "assistant", content: rawOutput },
          sanitizedResult: { role: "assistant", content: sanitizedOutput || finalScan.redacted },
          status: "success", httpStatus: 200, latencyMs: Date.now() - startedAt, security
        });
        if (pendingTerminalEvents.length > 0) {
          for (const terminalEvent of pendingTerminalEvents) emit(terminalEvent, true);
        } else if (lastContentTemplate) {
          const metadataEvent = structuredClone(lastContentTemplate);
          if (Array.isArray(metadataEvent.choices)) {
            for (const choice of metadataEvent.choices) choice.delta = {};
          }
          emit(metadataEvent, true);
        }
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
          failureMessage: "Upstream model stream failed", latencyMs: Date.now() - startedAt, security
        });
        emit({ error: { message: "Upstream model stream failed", type: "upstream_error" } });
        closed = true;
        response.end();
      },
      (payload, content) => {
        const safePayload = sanitizeToolArguments(payload);
        if (content.length > 0) {
          rawOutput += content;
          lastContentTemplate = safePayload;
          const inspection = streamingGuard.inspectChunk(content, state);
          for (const safeChunk of inspection.redactedChunks) {
            sanitizedOutput += safeChunk;
            emitContent(safeChunk);
          }
        } else if (isTerminalEvent(safePayload)) {
          pendingTerminalEvents.push(safePayload);
        } else {
          emit(safePayload);
        }
      }
    );
    await telemetryWrite;
    return undefined;
  };

  app.post("/v1/chat/completions", { schema: { body: bodySchema } }, handler);
  app.post("/chat/completions", { schema: { body: bodySchema } }, handler);

  // Deterministic dashboard fixtures are available only in explicitly enabled demo deployments.
  // In production these paths must reach the authenticated LiteLLM management proxy.
  if (!config.ZENTRIS_DEMO_ENABLED) return;

  // ── Demo-only dashboard compatibility fixtures ─────────────────────────────

  // Upstream is Groq (LITELLM_BASE_URL=https://api.groq.com/openai/v1). These IDs
  // are forwarded verbatim to Groq, so they must be real Groq model names.
  const modelList = {
    object: "list",
    data: [
      { id: "openai/gpt-oss-120b", object: "model", owned_by: "groq" },
      { id: "openai/gpt-oss-20b",  object: "model", owned_by: "groq" },
      { id: "qwen/qwen3.6-27b",    object: "model", owned_by: "groq" },
      { id: "groq/compound",       object: "model", owned_by: "groq" }
    ]
  };
  // The Models + Endpoints table/tabs read many fields per row. Provide the full
  // shape (Zentris_params mirror of litellm_params, max_tokens, db_model,
  // access_groups, timestamps, team_id) so row rendering never hits undefined.
  const nowIso = new Date().toISOString();
  const mkModelInfo = (id: string, opts: { input: number; output: number; maxOut: number; vision: boolean }) => ({
    model_name: id,
    litellm_params: { model: id },
    Zentris_params: { model: id },
    model_info: {
      id, mode: "chat",
      input_cost_per_token: opts.input, output_cost_per_token: opts.output,
      max_tokens: opts.maxOut, max_input_tokens: 131072, max_output_tokens: opts.maxOut,
      supports_function_calling: true, supports_vision: opts.vision,
      db_model: false, access_groups: [] as string[], team_id: null as string | null,
      created_by: "system", created_at: nowIso, updated_at: nowIso
    }
  });
  const modelInfoData = [
    mkModelInfo("openai/gpt-oss-120b", { input: 0.00000015, output: 0.0000006, maxOut: 65536, vision: false }),
    mkModelInfo("openai/gpt-oss-20b",  { input: 0.00000005, output: 0.0000002, maxOut: 65536, vision: false }),
    mkModelInfo("qwen/qwen3.6-27b",    { input: 0.0000006,  output: 0.000003,  maxOut: 16384, vision: true })
  ];
  // Drives the Playground model dropdown (fetchAvailableModels -> /model_group/info).
  // model_group must equal the ID forwarded to Groq so completions succeed.
  const modelGroupInfo = [
    { model_group: "openai/gpt-oss-120b", providers: ["groq"], mode: "chat", max_input_tokens: 131072, max_output_tokens: 65536, input_cost_per_token: 0.00000015, output_cost_per_token: 0.0000006, supports_function_calling: true, supports_vision: false },
    { model_group: "openai/gpt-oss-20b",  providers: ["groq"], mode: "chat", max_input_tokens: 131072, max_output_tokens: 65536, input_cost_per_token: 0.00000005, output_cost_per_token: 0.0000002, supports_function_calling: true, supports_vision: false },
    { model_group: "qwen/qwen3.6-27b",    providers: ["groq"], mode: "chat", max_input_tokens: 131072, max_output_tokens: 16384, input_cost_per_token: 0.0000006, output_cost_per_token: 0.000003, supports_function_calling: true, supports_vision: true },
    { model_group: "groq/compound",       providers: ["groq"], mode: "chat", max_input_tokens: 131072, max_output_tokens: 8192, input_cost_per_token: 0.0000002, output_cost_per_token: 0.0000006, supports_function_calling: true, supports_vision: false }
  ];
  const demoKey = {
    token: "sk-zentris-demo-xxxxxxxx", key_alias: "Zentris Demo Key", key_name: "sk-...xxxx",
    spend: 0, max_budget: null, expires: null, models: ["openai/gpt-oss-120b", "openai/gpt-oss-20b"],
    user_id: "public-admin", team_id: null, permissions: {},
    created_at: new Date().toISOString(), updated_at: new Date().toISOString()
  };

  // Models
  app.get("/v1/models",    async () => modelList);
  app.get("/models",       async () => modelList);
  app.get("/model/info",   async () => ({ data: modelInfoData }));
  app.get("/v1/model/info",async () => ({ data: modelInfoData }));
  app.get("/v2/model/info",async () => ({ data: modelInfoData }));
  app.get("/model_group/info", async () => ({ data: modelGroupInfo }));

  // Model cost map — the dashboard reads provider/mode/costs from here. Fetched
  // WITHOUT a bearer token, so /public/Zentris_model_cost_map is also listed in
  // OWNED_PUBLIC_PATHS. Must be a plain object keyed by model id (not an array).
  const modelCostMap: Record<string, Record<string, unknown>> = {
    "openai/gpt-oss-120b": { max_tokens: 65536, max_input_tokens: 131072, max_output_tokens: 65536, input_cost_per_token: 0.00000015, output_cost_per_token: 0.0000006, Zentris_provider: "groq", litellm_provider: "groq", mode: "chat", supports_function_calling: true },
    "openai/gpt-oss-20b":  { max_tokens: 65536, max_input_tokens: 131072, max_output_tokens: 65536, input_cost_per_token: 0.00000005, output_cost_per_token: 0.0000002, Zentris_provider: "groq", litellm_provider: "groq", mode: "chat", supports_function_calling: true },
    "qwen/qwen3.6-27b":    { max_tokens: 16384, max_input_tokens: 131072, max_output_tokens: 16384, input_cost_per_token: 0.0000006, output_cost_per_token: 0.000003, Zentris_provider: "groq", litellm_provider: "groq", mode: "chat", supports_function_calling: true },
    "groq/compound":       { max_tokens: 8192,  max_input_tokens: 131072, max_output_tokens: 8192,  input_cost_per_token: 0.0000002, output_cost_per_token: 0.0000006, Zentris_provider: "groq", litellm_provider: "groq", mode: "chat", supports_function_calling: true }
  };
  app.get("/public/Zentris_model_cost_map", async () => modelCostMap);
  // Price Data Management tab reads source.model_count.toLocaleString() (must be a
  // number) plus source/url; and reload status reads scheduled/last_run/next_run.
  app.get("/model/cost_map/source", async () => ({ source: "local", model_count: Object.keys(modelCostMap).length, url: null, is_env_forced: false, fallback_reason: null }));
  app.get("/schedule/model_cost_map_reload/status", async () => ({ scheduled: false, last_run: null, next_run: null, interval_hours: null }));
  app.get("/user/available_users", async () => ({ available_users: [], total: 0 }));
  app.get("/health/license", async () => ({ valid: false, license: null }));

  // Keys
  app.get("/key/info",     async () => ({ info: { token: "sk-zentris-public", key_name: "Public Demo Key", spend: 0, max_budget: null, expires: null, models: ["openai/gpt-oss-120b", "openai/gpt-oss-20b"], user_id: "public-admin" } }));
  app.get("/key/list",     async () => ({ keys: [demoKey], total: 1 }));
  app.get("/v2/key/info",  async () => demoKey);
  app.get("/key/aliases",  async () => []);
  app.post("/key/generate",async () => ({ key: "sk-zentris-demo", key_name: "Demo Key", expires: null, user_id: "public-admin", models: ["openai/gpt-oss-120b", "openai/gpt-oss-20b"], spend: 0, max_budget: null }));
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
  // /config/list has two shapes: with ?config_type=... the UI expects an ARRAY
  // of ConfigListItem and calls .find() over it (Model/SpendLogs settings modals);
  // without it, the dashboard reads PROXY_BASE_URL. Returning the object for the
  // config_type call caused "proxyConfigData.find is not a function".
  app.get("/config/list", async (request) => {
    const configType = (request.query as { config_type?: string } | undefined)?.config_type;
    if (configType) {
      return [
        { field_name: "store_model_in_db", field_type: "Boolean", field_description: "Store model settings in the database.", field_value: false, stored_in_db: null, field_default_value: false },
        { field_name: "store_prompts_in_spend_logs", field_type: "Boolean", field_description: "Store prompts in spend logs.", field_value: false, stored_in_db: null, field_default_value: false },
        { field_name: "maximum_spend_logs_retention_period", field_type: "String", field_description: "Maximum retention period for spend logs.", field_value: null, stored_in_db: null, field_default_value: null }
      ];
    }
    return { PROXY_BASE_URL: process.env["PROXY_BASE_URL"] || null, Zentris_UI_API_DOC_BASE_URL: null };
  });
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
  // fetchMCPServers/fetchAvailableAgents consume the raw body as an array
  // (mcpServers.map(...), agents.sort(...)), so these MUST return a bare array.
  // MCP server registry — persisted in Redis (see services/mcpServerStore.ts).
  // GET returns a bare array (the page does mcpServers.map(...)); create/update/
  // delete power the "Add New MCP Server" flow.
  app.get("/v1/mcp/server",          async () => await listMCPServers());
  app.post("/v1/mcp/server",         async (request) => await createMCPServer((request.body ?? {}) as Record<string, unknown>));
  app.put("/v1/mcp/server",          async (request) => (await updateMCPServer((request.body ?? {}) as Record<string, unknown>)) ?? {});
  app.delete("/v1/mcp/server/:serverId", async (request) => {
    const { serverId } = request.params as { serverId: string };
    const deleted = await deleteMCPServer(serverId);
    return { deleted, server_id: serverId };
  });
  app.get("/v1/mcp/server/health",   async () => []);

  // A2A agent registry — persisted in Redis (see services/agentStore.ts). The
  // dashboard Agents page reads GET (bare array) and writes via POST/DELETE.
  app.get("/v1/agents", async () => await listAgents());
  app.post("/v1/agents", async (request) => await createAgent((request.body ?? {}) as Record<string, unknown>));
  app.post("/v1/agents/make_public", async (request) => {
    const body = (request.body ?? {}) as { agent_ids?: string[]; agent_id?: string };
    const ids = body.agent_ids ?? (body.agent_id ? [body.agent_id] : []);
    await setAgentsPublic(ids);
    return { success: true, agent_ids: ids };
  });
  app.delete("/v1/agents/:agentId", async (request) => {
    const { agentId } = request.params as { agentId: string };
    const deleted = await deleteAgent(agentId);
    return { deleted, agent_id: agentId };
  });
  app.get("/health/test_connection",  async () => ({ status: "ok" }));
  app.get("/health/latest",          async () => ({ status: "ok" }));
  app.get("/public/providers/fields", async () => []);
  app.get("/public/agents/fields",   async () => []);

  const loginHandler = async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as { username?: string; password?: string } | undefined;
    const username = body?.username ?? "";
    const password = body?.password ?? "";

    const validPassword =
      (config.UI_PASSWORD.length > 0 && password === config.UI_PASSWORD) ||
      (config.LITELLM_API_KEY.length >= 16 && password === config.LITELLM_API_KEY);
    const validUsername = username === "admin" || username === "admin@zentris.ai";
    if (!validUsername || !validPassword) {
      return reply.code(401).send({ error: "invalid_credentials" });
    }

    const exp = Math.floor(Date.now() / 1000) + 86400;
    const token = createAccessToken(
      {
        sub: "admin",
        role: "admin",
        exp,
        user_id: "admin",
        user_email: "admin@zentris.ai",
        user_role: "proxy_admin",
        login_method: "public_access",
        premium_user: true,
        disabled_non_admin_personal_key_creation: false,
        key: "admin"
      },
      config.JWT_SECRET
    );

    return { token, redirect_url: "/ui/" };
  };

  app.post("/v2/login", loginHandler);
  app.post("/v3/login", loginHandler);
};

export default fp(gatewayRoutes, { name: "gateway-routes" });
