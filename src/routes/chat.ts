import fp from "fastify-plugin";
import { type FastifyPluginAsync, type FastifyReply } from "fastify";
import { RagSecurityGuard, type RagChunkInput } from "../guards/ragSecurityGuard";
import { StreamingGuard } from "../guards/streamingGuard";
import { scanAndRedactSensitiveData } from "../guards/dlpGuard";
import { wrapUntrustedData } from "../guards/ragWrapper";
import { StreamingClient } from "../llm/streamingClient";
import { LiteLLMError } from "../llm/litellmClient";
import { type LLMChat, ZentrisPipeline } from "../middleware/pipeline";
import { config } from "../config";
import { StreamAbuseGuard } from "../services/streamAbuseGuard";
import { CircuitOpenError } from "../services/circuitBreaker";
import { TelemetryService } from "../services/telemetryService";
import { type AuthenticatedIdentity, type ChatMessage, type ToolInvocation, type ZentrisRequest } from "../types";

interface ClientMessage {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp: number;
}

interface ChatRouteBody {
  sessionId: string;
  message: string;
  history?: ClientMessage[];
  ragContext?: string;
  ragChunks?: RagChunkInput[];
  toolInvocation?: ToolInvocation;
  model?: string;
  temperature?: number;
  maxTokens?: number;
}

export type StreamChat = StreamingClient["streamChat"];

export interface ChatRouteOptions {
  litellmChat?: LLMChat;
  streamChat?: StreamChat;
}

const SESSION_ID_REGEX = /^[A-Za-z0-9-]{1,64}$/;

const upstreamStatus = (error: unknown): number => {
  if (error instanceof CircuitOpenError) return 503;
  if (error instanceof LiteLLMError && error.llmReason === "request_timeout") return 504;
  if (error instanceof LiteLLMError && [401, 403, 429].includes(error.statusCode)) return error.statusCode;
  return 502;
};

const bodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["sessionId", "message"],
  properties: {
    sessionId: { type: "string", maxLength: 64, pattern: "^[A-Za-z0-9-]{1,64}$" },
    message: { type: "string", minLength: 1, maxLength: 8000 },
    model: { type: "string", minLength: 1, maxLength: 256 },
    temperature: { type: "number", minimum: 0, maximum: 2 },
    maxTokens: { type: "integer", minimum: 1, maximum: 131072 },
    ragContext: { type: "string" },
    ragChunks: {
      type: "array",
      maxItems: 50,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["content"],
        properties: {
          content: { type: "string", minLength: 1, maxLength: 8000 },
          source: { type: "string", maxLength: 128 }
        }
      }
    },
    toolInvocation: {
      type: "object",
      additionalProperties: false,
      required: ["toolName", "arguments", "resourceScope"],
      properties: {
        toolName: { type: "string", minLength: 1, maxLength: 128 },
        arguments: { type: "object", additionalProperties: true },
        resourceScope: { type: "object", additionalProperties: true },
        confirmationToken: { type: "string", minLength: 1, maxLength: 4096 }
      }
    },
    history: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["role", "content", "timestamp"],
        properties: {
          role: { type: "string", enum: ["system", "user", "assistant"] },
          content: { type: "string" },
          timestamp: { type: "number" }
        }
      }
    }
  }
} as const;

const hasForbiddenIdentityFields = (value: unknown): boolean =>
  Boolean(
    value &&
      typeof value === "object" &&
      ("userId" in value || "userRole" in value || "role" in value || "isAdmin" in value)
  );

const hasClientSystemRole = (history: ClientMessage[] | undefined): boolean =>
  Boolean(history?.some((message) => message.role === "system"));

const normalizeClientHistory = (history: ClientMessage[] | undefined): ChatMessage[] =>
  (history ?? []).slice(-config.MAX_SESSION_MESSAGES).map((message) => ({
    role: message.role,
    content: message.content,
    timestamp: message.timestamp
  }));

const buildRagInputs = (body: ChatRouteBody): RagChunkInput[] => {
  const chunks = [...(body.ragChunks ?? [])];

  if (body.ragContext && body.ragContext.trim().length > 0) {
    chunks.push({
      content: body.ragContext,
      source: "rag_context"
    });
  }

  return chunks;
};

const telemetryModelParameters = (body: ChatRouteBody, stream: boolean): Record<string, unknown> => ({
  ...(body.temperature !== undefined ? { temperature: body.temperature } : {}),
  ...(body.maxTokens !== undefined ? { max_tokens: body.maxTokens } : {}),
  stream
});

const toZentrisRequest = async (
  body: ChatRouteBody,
  identity: AuthenticatedIdentity,
  ragSecurityGuard: RagSecurityGuard
): Promise<ZentrisRequest> => {
  const history = normalizeClientHistory(body.history);
  const ragInputs = buildRagInputs(body);
  const sanitizedRag = await ragSecurityGuard.sanitizeChunks(ragInputs);

  for (const chunk of sanitizedRag.accepted) {
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

  const boundedHistory = history.slice(-config.MAX_SESSION_MESSAGES);

  return {
    sessionId: body.sessionId,
    identity,
    rawInput: body.message,
    messages: boundedHistory,
    toolInvocation: body.toolInvocation,
    generation: {
      model: body.model,
      temperature: body.temperature,
      maxTokens: body.maxTokens
    }
  };
};

const sendJsonError = (
  reply: FastifyReply,
  statusCode: number,
  requestId: string,
  riskLevel: "low" | "medium" | "high",
  payload: Record<string, unknown>
) =>
  reply
    .code(statusCode)
    .header("X-Request-ID", requestId)
    .header("X-Risk-Level", riskLevel)
    .send(payload);

const chatRoutes: FastifyPluginAsync<ChatRouteOptions> = async (app, options) => {
  const ragSecurityGuard = new RagSecurityGuard();
  const pipeline = new ZentrisPipeline({ litellmChat: options.litellmChat });
  const streamingClient = new StreamingClient();
  const streamChat: StreamChat = options.streamChat ?? ((...args) => streamingClient.streamChat(...args));
  const streamAbuseGuard = new StreamAbuseGuard();
  const streamingGuard = new StreamingGuard(
    config.STREAMING_ROLLING_BUFFER_CHARS,
    config.STREAMING_SUSPICIOUS_EVENT_LIMIT
  );
  const telemetry = new TelemetryService();

  app.post<{ Body: ChatRouteBody }>(
    "/v1/chat",
    {
      preValidation: async (request, reply) => {
        if (hasForbiddenIdentityFields(request.body)) {
          return sendJsonError(reply, 403, request.id, "high", {
            error: "Forbidden identity fields in request body",
            reason: "client_identity_override_attempt"
          });
        }
        const body = request.body as ChatRouteBody;
        if (hasClientSystemRole(body.history)) {
          return sendJsonError(reply, 400, request.id, "high", {
            error: "System role is not allowed in client history",
            reason: "client_system_role_forbidden"
          });
        }
      },
      schema: { body: bodySchema }
    },
    async (request, reply) => {
      const requestId = request.id;
      const body = request.body;
      const startedAt = Date.now();
      const rawMessages = [...(body.history ?? []), { role: "user", content: body.message, timestamp: Date.now() }];

      if (!SESSION_ID_REGEX.test(body.sessionId)) {
        return sendJsonError(reply, 400, requestId, "high", {
          error: "Invalid sessionId"
        });
      }

      if (body.message.length > 8000) {
        return sendJsonError(reply, 400, requestId, "high", {
          error: "Message exceeds maximum length"
        });
      }

      let pipelineResult;
      try {
        pipelineResult = await pipeline.run({
          ...(await toZentrisRequest(body, request.identity, ragSecurityGuard)),
          requestId,
          generation: {
            model: body.model,
            temperature: body.temperature,
            maxTokens: body.maxTokens,
            apiKey: request.headers.authorization?.startsWith("Bearer ") ? request.headers.authorization.slice(7).trim() : undefined
          }
        });
      } catch (error) {
        await telemetry.enqueue({
          requestId, sessionId: body.sessionId, identity: request.identity, route: "/v1/chat",
          model: body.model ?? config.LITELLM_MODEL, rawMessages, sanitizedMessages: [], status: "failed",
          modelParameters: telemetryModelParameters(body, false),
          httpStatus: upstreamStatus(error),
          failureCode: error instanceof CircuitOpenError ? "circuit_open" : error instanceof LiteLLMError ? error.llmReason : "upstream_unavailable",
          failureMessage: "Upstream model request failed", latencyMs: Date.now() - startedAt,
          security: { requestId, injectionDetected: false, warningApplied: false, dlpDetected: false, risk: "none", score: 0, matchedRules: [], findings: [] }
        });
        return sendJsonError(reply, upstreamStatus(error), requestId, "low", {
          error: "Upstream model request failed",
          reason: error instanceof CircuitOpenError ? "circuit_open" : error instanceof LiteLLMError ? error.llmReason : "upstream_unavailable",
          requestId
        });
      }

      reply
        .header("X-Zentris-Request-Id", requestId)
        .header("X-Zentris-Injection-Detected", String(pipelineResult.security.injectionDetected))
        .header("X-Zentris-Security-Action", pipelineResult.security.injectionDetected ? "warn" : pipelineResult.security.dlpDetected ? "redact" : "allow")
        .header("X-Zentris-Risk", pipelineResult.security.risk);

      const rejected = pipelineResult.action === "block" || pipelineResult.action === "require_confirmation";
      void telemetry.enqueue({
        requestId, sessionId: body.sessionId, identity: request.identity, route: "/v1/chat",
        model: body.model ?? config.LITELLM_MODEL, rawMessages,
        modelParameters: telemetryModelParameters(body, false),
        sanitizedMessages: pipelineResult.modelMessages ?? [],
        rawResult: pipelineResult.rawResponse === undefined ? undefined : { role: "assistant", content: pipelineResult.rawResponse },
        sanitizedResult: pipelineResult.response === undefined ? undefined : { role: "assistant", content: pipelineResult.response },
        status: rejected ? "rejected" : "success",
        httpStatus: pipelineResult.action === "block" ? 400 : pipelineResult.action === "require_confirmation" ? 202 : 200,
        failureCode: rejected ? pipelineResult.guardResult.reason : undefined,
        latencyMs: Date.now() - startedAt, security: pipelineResult.security
      });

      if (pipelineResult.action === "block") {
        return sendJsonError(reply, 400, requestId, pipelineResult.riskLevel, {
          error: "Request blocked",
          reason: pipelineResult.guardResult.reason,
          requestId,
          security: pipelineResult.security
        });
      }

      if (pipelineResult.action === "require_confirmation") {
        return reply
          .code(202)
          .header("X-Request-ID", requestId)
          .header("X-Risk-Level", pipelineResult.riskLevel)
          .send({
            requiresConfirmation: true,
            message: "High risk action requires confirmation",
            confirmationToken: pipelineResult.confirmationToken ?? null,
            security: pipelineResult.security
          });
      }

      return reply
        .code(200)
        .header("X-Request-ID", requestId)
        .header("X-Risk-Level", pipelineResult.riskLevel)
        .send({
          response: pipelineResult.response ?? "",
          requestId,
          riskLevel: pipelineResult.riskLevel,
          security: pipelineResult.security
        });
    }
  );

  app.post<{ Body: ChatRouteBody }>(
    "/v1/chat/stream",
    {
      config: {
        rateLimit: {
          max: Math.max(1, Math.floor(config.RATE_LIMIT_MAX / 2)),
          timeWindow: config.RATE_LIMIT_WINDOW
        }
      },
      preValidation: async (request, reply) => {
        if (hasForbiddenIdentityFields(request.body)) {
          return sendJsonError(reply, 403, request.id, "high", {
            error: "Forbidden identity fields in request body",
            reason: "client_identity_override_attempt"
          });
        }
        const body = request.body as ChatRouteBody;
        if (hasClientSystemRole(body.history)) {
          return sendJsonError(reply, 400, request.id, "high", {
            error: "System role is not allowed in client history",
            reason: "client_system_role_forbidden"
          });
        }
      },
      schema: { body: bodySchema }
    },
    async (request, reply) => {
      const requestId = request.id;
      const body = request.body;
      const startedAt = Date.now();
      const rawMessages = [...(body.history ?? []), { role: "user", content: body.message, timestamp: Date.now() }];

      if (!SESSION_ID_REGEX.test(body.sessionId)) {
        return sendJsonError(reply, 400, requestId, "high", {
          error: "Invalid sessionId"
        });
      }

      if (body.message.length > 8000) {
        return sendJsonError(reply, 400, requestId, "high", {
          error: "Message exceeds maximum length"
        });
      }

      const guardOutcome = await pipeline.runGuards(
        {
          ...(await toZentrisRequest(body, request.identity, ragSecurityGuard)),
          requestId,
          generation: {
            model: body.model,
            temperature: body.temperature,
            maxTokens: body.maxTokens,
            apiKey: request.headers.authorization?.startsWith("Bearer ") ? request.headers.authorization.slice(7).trim() : undefined
          }
        }
      );

      if (guardOutcome.action === "block") {
        await telemetry.enqueue({
          requestId, sessionId: body.sessionId, identity: request.identity, route: "/v1/chat/stream",
          model: body.model ?? config.LITELLM_MODEL, rawMessages, sanitizedMessages: guardOutcome.llmMessages,
          modelParameters: telemetryModelParameters(body, true),
          status: "rejected", httpStatus: 400, failureCode: guardOutcome.guardResult.reason,
          latencyMs: Date.now() - startedAt, security: guardOutcome.security
        });
        return sendJsonError(reply, 400, requestId, guardOutcome.riskLevel, {
          error: "Request blocked",
          reason: guardOutcome.guardResult.reason,
          requestId
        });
      }

      if (guardOutcome.action === "require_confirmation") {
        await telemetry.enqueue({
          requestId, sessionId: body.sessionId, identity: request.identity, route: "/v1/chat/stream",
          model: body.model ?? config.LITELLM_MODEL, rawMessages, sanitizedMessages: guardOutcome.llmMessages,
          modelParameters: telemetryModelParameters(body, true),
          status: "rejected", httpStatus: 202, failureCode: guardOutcome.guardResult.reason,
          latencyMs: Date.now() - startedAt, security: guardOutcome.security
        });
        return reply
          .code(202)
          .header("X-Request-ID", requestId)
          .header("X-Risk-Level", guardOutcome.riskLevel)
          .send({
            requiresConfirmation: true,
            message: "High risk action requires confirmation",
            confirmationToken: guardOutcome.confirmationToken ?? null
          });
      }

      const streamId = `${requestId}:${Date.now().toString(36)}`;
      const slotResult = await streamAbuseGuard.acquireSlot(request.identity.userId, body.sessionId, streamId);
      if (!slotResult.allowed) {
        await telemetry.enqueue({
          requestId, sessionId: body.sessionId, identity: request.identity, route: "/v1/chat/stream",
          model: body.model ?? config.LITELLM_MODEL, rawMessages, sanitizedMessages: guardOutcome.llmMessages,
          modelParameters: telemetryModelParameters(body, true),
          status: "rejected", httpStatus: 429, failureCode: slotResult.reason ?? "concurrent_stream_limit_exceeded",
          latencyMs: Date.now() - startedAt, security: guardOutcome.security
        });
        return sendJsonError(reply, 429, requestId, "high", {
          error: "Request blocked",
          reason: slotResult.reason ?? "concurrent_stream_limit_exceeded",
          requestId
        });
      }

      reply.hijack();

      const response = reply.raw;
      const streamState = streamingGuard.createState();
      response.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
        "X-Request-ID": requestId,
        "X-Risk-Level": guardOutcome.riskLevel,
        "X-Zentris-Request-Id": requestId,
        "X-Zentris-Injection-Detected": String(guardOutcome.security.injectionDetected),
        "X-Zentris-Security-Action": guardOutcome.security.injectionDetected ? "warn" : guardOutcome.security.dlpDetected ? "redact" : "allow",
        "X-Zentris-Risk": guardOutcome.security.risk
      });

      let streamClosed = false;
      let slotReleased = false;
      let rawOutput = "";
      let sanitizedOutput = "";
      let telemetryWrite: Promise<void> = Promise.resolve();

      const sendSse = (payload: Record<string, unknown>): void => {
        if (streamClosed || response.writableEnded) {
          return;
        }
        response.write(`data: ${JSON.stringify(payload)}\n\n`);
      };

      const closeStream = (): void => {
        if (streamClosed || response.writableEnded) {
          return;
        }
        streamClosed = true;
        response.end();
      };

      const releaseSlot = async (): Promise<void> => {
        if (slotReleased) {
          return;
        }
        slotReleased = true;
        await streamAbuseGuard.releaseSlot(request.identity.userId, body.sessionId, streamId);
      };

      const disconnectHandler = (): void => {
        streamClosed = true;
        streamingClient.abortStream(streamId);
        void releaseSlot();
      };

      request.raw.socket.on("close", disconnectHandler);

      sendSse({ security: guardOutcome.security });

      await streamChat(
        streamId,
        guardOutcome.llmMessages,
        guardOutcome.generation ?? {},
        (chunk) => {
          rawOutput += chunk;
          const inspection = streamingGuard.inspectChunk(chunk, streamState);
          if (inspection.detectedTypes.length > 0) {
            request.log.warn({ detectedTypes: inspection.detectedTypes }, "stream_output_redacted");
          }

          for (const safeChunk of inspection.redactedChunks) {
            sanitizedOutput += safeChunk;
            sendSse({ chunk: safeChunk });
          }
        },
        () => {
          const flushInspection = streamingGuard.flush(streamState);
          for (const safeChunk of flushInspection.redactedChunks) {
            sanitizedOutput += safeChunk;
            sendSse({ chunk: safeChunk });
          }
          const finalScan = scanAndRedactSensitiveData(rawOutput, "output");
          guardOutcome.security.findings.push(...finalScan.findings);
          guardOutcome.security.dlpDetected ||= finalScan.findings.length > 0;
          guardOutcome.security.matchedRules = Array.from(new Set(guardOutcome.security.findings.map((finding) => finding.ruleId)));
          guardOutcome.security.score = Math.max(guardOutcome.security.score, ...finalScan.findings.map((finding) => finding.score), 0);
          if (guardOutcome.security.score >= 70) guardOutcome.security.risk = "high";
          else if (guardOutcome.security.score >= 40) guardOutcome.security.risk = "medium";
          telemetryWrite = telemetry.enqueue({
            requestId, sessionId: body.sessionId, identity: request.identity, route: "/v1/chat/stream",
            model: body.model ?? config.LITELLM_MODEL, rawMessages, sanitizedMessages: guardOutcome.llmMessages,
            modelParameters: telemetryModelParameters(body, true),
            rawResult: { role: "assistant", content: rawOutput },
            sanitizedResult: { role: "assistant", content: sanitizedOutput || finalScan.redacted },
            status: "success", httpStatus: 200, latencyMs: Date.now() - startedAt, security: guardOutcome.security
          });
          sendSse({ security: guardOutcome.security, done: true });
          closeStream();
        },
        (error) => {
          telemetryWrite = telemetry.enqueue({
            requestId, sessionId: body.sessionId, identity: request.identity, route: "/v1/chat/stream",
            model: body.model ?? config.LITELLM_MODEL, rawMessages, sanitizedMessages: guardOutcome.llmMessages,
            modelParameters: telemetryModelParameters(body, true),
            rawResult: rawOutput ? { role: "assistant", content: rawOutput } : undefined,
            sanitizedResult: sanitizedOutput ? { role: "assistant", content: sanitizedOutput } : undefined,
            status: "failed", httpStatus: upstreamStatus(error),
            failureCode: error instanceof LiteLLMError ? error.llmReason : "upstream_unavailable",
            failureMessage: "Upstream model stream failed", latencyMs: Date.now() - startedAt, security: guardOutcome.security
          });
          if (!streamClosed) {
            sendSse({ error: "stream_error" });
            closeStream();
          }
        }
      );

      await telemetryWrite;

      request.raw.socket.off("close", disconnectHandler);
      await releaseSlot();
    }
  );
};

export default fp(chatRoutes, {
  name: "chat-routes"
});
