import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import Redis from "ioredis";
import { config } from "./config";
import {
  type AuditLogEntry,
  type ChatMessage,
  type GuardResult,
  type IntentType,
  type PipelineContext,
  type UserRole,
  type ZentrisRequest
} from "./types";
import { logger } from "./utils/logger";

interface ChatBody {
  sessionId: string;
  userId: string;
  userRole: UserRole;
  message: string;
  history?: ChatMessage[];
}

interface ChatResponse {
  requestId: string;
  safe: boolean;
  action: GuardResult["action"];
  risk: GuardResult["risk"];
  output: string;
  intent: IntentType;
}

const redis = new Redis(config.REDIS_URL, {
  lazyConnect: true,
  maxRetriesPerRequest: 1
});

const normalizeInput = (value: string): string => value.trim().replace(/\s+/g, " ");

const deriveIntent = (input: string): IntentType => {
  const normalized = input.toLowerCase();

  if (/\b(read|show|list|get|fetch|view)\b/.test(normalized)) {
    return "read";
  }
  if (/\b(write|create|update|insert|modify)\b/.test(normalized)) {
    return "write";
  }
  if (/\b(delete|remove|drop|erase)\b/.test(normalized)) {
    return "delete";
  }
  if (/\b(run|execute|shell|command|script)\b/.test(normalized)) {
    return "execute";
  }

  return "unknown";
};

const evaluateGuards = (context: PipelineContext): GuardResult[] => {
  const results: GuardResult[] = [];
  const normalized = context.normalizedInput.toLowerCase();

  if (/(drop\s+table|truncate\s+table|rm\s+-rf|sudo\s+rm)/.test(normalized)) {
    results.push({
      safe: false,
      risk: "high",
      reason: "Potential destructive command detected",
      action: "block"
    });
  }

  if (/(ignore\s+previous\s+instructions|reveal\s+system\s+prompt|bypass\s+policy)/.test(normalized)) {
    results.push({
      safe: false,
      risk: "high",
      reason: "Prompt-injection pattern detected",
      action: "require_confirmation"
    });
  }

  if (/<script|javascript:|onerror=|onload=/.test(normalized)) {
    results.push({
      safe: false,
      risk: "medium",
      reason: "Potential script injection content detected",
      action: "sanitize"
    });
  }

  if (results.length === 0) {
    results.push({
      safe: true,
      risk: "low",
      reason: "Input passed baseline policy checks",
      action: "allow"
    });
  }

  return results;
};

const sanitizeInput = (input: string): string =>
  input
    .replace(/<script/gi, "")
    .replace(/javascript:/gi, "")
    .replace(/onerror=/gi, "")
    .replace(/onload=/gi, "");

const riskWeight: Record<GuardResult["risk"], number> = {
  low: 1,
  medium: 5,
  high: 10
};

const pickFinalAction = (results: GuardResult[]): GuardResult["action"] => {
  if (results.some((result) => result.action === "block")) {
    return "block";
  }
  if (results.some((result) => result.action === "require_confirmation")) {
    return "require_confirmation";
  }
  if (results.some((result) => result.action === "sanitize")) {
    return "sanitize";
  }
  return "allow";
};

const pickFinalRisk = (results: GuardResult[]): GuardResult["risk"] => {
  if (results.some((result) => result.risk === "high")) {
    return "high";
  }
  if (results.some((result) => result.risk === "medium")) {
    return "medium";
  }
  return "low";
};

const saveSessionMessages = async (requestData: ZentrisRequest): Promise<void> => {
  const sessionKey = `zentris:session:${requestData.sessionId}`;
  const payload = JSON.stringify(requestData.messages);
  try {
    await redis.set(sessionKey, payload, "EX", 60 * 60 * 24);
  } catch (error) {
    logger.warn({ err: error, sessionId: requestData.sessionId }, "redis_session_persist_failed");
  }
};

const routesPlugin = fp(async (app) => {
  app.get("/health", async () => ({ status: "ok", service: "zentris", timestamp: Date.now() }));

  app.post<{ Body: ChatBody; Reply: ChatResponse }>("/v1/chat", async (request, reply) => {
    const startedAt = Date.now();
    const { sessionId, userId, userRole, message, history = [] } = request.body;
    const normalizedInput = normalizeInput(message);
    const liveMessage: ChatMessage = { role: "user", content: message, timestamp: Date.now() };
    const clippedHistory = history.slice(-config.MAX_SESSION_MESSAGES + 1);
    const messages: ChatMessage[] = [...clippedHistory, liveMessage];

    const zentrisRequest: ZentrisRequest = {
      sessionId,
      userId,
      userRole,
      rawInput: message,
      messages
    };

    const pipelineContext: PipelineContext = {
      request: zentrisRequest,
      guardResults: [],
      normalizedInput,
      sanitizedInput: normalizedInput
    };

    pipelineContext.guardResults = evaluateGuards(pipelineContext);

    if (pipelineContext.guardResults.some((result) => result.action === "sanitize")) {
      pipelineContext.sanitizedInput = sanitizeInput(pipelineContext.normalizedInput);
    }

    const intent = deriveIntent(pipelineContext.normalizedInput);
    const finalAction = pickFinalAction(pipelineContext.guardResults);
    const finalRisk = pickFinalRisk(pipelineContext.guardResults);
    const durationMs = Date.now() - startedAt;
    const riskScore = pipelineContext.guardResults.reduce((score, decision) => score + riskWeight[decision.risk], 0);

    const auditLog: AuditLogEntry = {
      timestamp: Date.now(),
      sessionId: pipelineContext.request.sessionId,
      userId: pipelineContext.request.userId,
      input: pipelineContext.request.rawInput,
      decisions: pipelineContext.guardResults,
      finalAction,
      riskScore,
      durationMs,
      userRole: pipelineContext.request.userRole,
      intent
    };

    logger.info({ auditLog }, "chat_request_audited");

    if (finalAction === "block") {
      reply.code(403);
      return {
        requestId: request.id,
        safe: false,
        action: finalAction,
        risk: finalRisk,
        output: "Request blocked by security policy",
        intent
      };
    }

    await saveSessionMessages(pipelineContext.request);

    return {
      requestId: request.id,
      safe: pipelineContext.guardResults.every((result) => result.safe),
      action: finalAction,
      risk: finalRisk,
      output: pipelineContext.sanitizedInput,
      intent
    };
  });
});

const app = Fastify({ loggerInstance: logger });

app.register(routesPlugin);

app.setErrorHandler((error: Error, request: FastifyRequest, reply: FastifyReply) => {
  request.log.error({ err: error }, "unhandled_request_error");

  if (reply.sent) {
    return;
  }

  reply.code(500).send({
    error: "Internal Server Error",
    message: "An unexpected error occurred"
  });
});

const start = async (): Promise<void> => {
  await app.listen({ port: config.PORT, host: "0.0.0.0" });
};

const shutdown = async (signal: NodeJS.Signals): Promise<void> => {
  logger.info({ signal }, "shutdown_started");

  try {
    await app.close();
    if (redis.status === "ready" || redis.status === "connect" || redis.status === "connecting") {
      await redis.quit();
    } else if (redis.status !== "end") {
      redis.disconnect();
    }
    logger.info({ signal }, "shutdown_complete");
    process.exit(0);
  } catch (error) {
    logger.error({ err: error, signal }, "shutdown_failed");
    process.exit(1);
  }
};

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});

process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

void start().catch((error: unknown) => {
  logger.error({ err: error }, "server_start_failed");
  process.exit(1);
});
