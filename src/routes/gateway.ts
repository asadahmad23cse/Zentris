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
};

export default fp(gatewayRoutes, { name: "gateway-routes" });
