import fp from "fastify-plugin";
import { type FastifyPluginAsync, type FastifyReply } from "fastify";
import { StreamingGuard } from "../guards/streamingGuard";
import { wrapUntrustedData } from "../guards/ragWrapper";
import { StreamingClient } from "../llm/streamingClient";
import { ZentrisPipeline } from "../middleware/pipeline";
import { config } from "../config";
import { type ChatMessage, type UserRole, type ZentrisRequest } from "../types";

interface ChatRouteBody {
  sessionId: string;
  userId: string;
  userRole: UserRole;
  message: string;
  history?: ChatMessage[];
  ragContext?: string;
}

const SESSION_ID_REGEX = /^[A-Za-z0-9-]{1,64}$/;

const bodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["sessionId", "userId", "userRole", "message"],
  properties: {
    sessionId: { type: "string", maxLength: 64, pattern: "^[A-Za-z0-9-]{1,64}$" },
    userId: { type: "string", minLength: 1, maxLength: 128 },
    userRole: { type: "string", enum: ["admin", "operator", "viewer", "anonymous"] },
    message: { type: "string", minLength: 1, maxLength: 8000 },
    ragContext: { type: "string" },
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

const toZentrisRequest = (body: ChatRouteBody): ZentrisRequest => {
  const history = [...(body.history ?? [])].slice(-config.MAX_SESSION_MESSAGES);

  if (body.ragContext && body.ragContext.trim().length > 0) {
    history.push({
      role: "system",
      content: wrapUntrustedData(body.ragContext, "rag_context"),
      timestamp: Date.now()
    });
  }

  return {
    sessionId: body.sessionId,
    userId: body.userId,
    userRole: body.userRole,
    rawInput: body.message,
    messages: history
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

const chatRoutes: FastifyPluginAsync = async (app) => {
  const pipeline = new ZentrisPipeline();
  const streamingClient = new StreamingClient();
  const streamingGuard = new StreamingGuard();

  app.post<{ Body: ChatRouteBody }>(
    "/v1/chat",
    {
      schema: {
        body: bodySchema
      }
    },
    async (request, reply) => {
      const requestId = request.id;
      const body = request.body;

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

      const pipelineResult = await pipeline.run(toZentrisRequest(body));

      if (pipelineResult.action === "block") {
        return sendJsonError(reply, 400, requestId, pipelineResult.riskLevel, {
          error: "Request blocked",
          reason: pipelineResult.guardResult.reason,
          requestId
        });
      }

      if (pipelineResult.action === "require_confirmation") {
        return reply
          .code(202)
          .header("X-Request-ID", requestId)
          .header("X-Risk-Level", pipelineResult.riskLevel)
          .send({
            requiresConfirmation: true,
            message: "High risk action requires confirmation"
          });
      }

      return reply
        .code(200)
        .header("X-Request-ID", requestId)
        .header("X-Risk-Level", pipelineResult.riskLevel)
        .send({
          response: pipelineResult.response ?? "",
          requestId,
          riskLevel: pipelineResult.riskLevel
        });
    }
  );

  app.post<{ Body: ChatRouteBody }>(
    "/v1/chat/stream",
    {
      schema: {
        body: bodySchema
      }
    },
    async (request, reply) => {
      const requestId = request.id;
      const body = request.body;

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

      const guardOutcome = await pipeline.runGuards(toZentrisRequest(body));

      if (guardOutcome.action === "block") {
        return sendJsonError(reply, 400, requestId, guardOutcome.riskLevel, {
          error: "Request blocked",
          reason: guardOutcome.guardResult.reason,
          requestId
        });
      }

      if (guardOutcome.action === "require_confirmation") {
        return reply
          .code(202)
          .header("X-Request-ID", requestId)
          .header("X-Risk-Level", guardOutcome.riskLevel)
          .send({
            requiresConfirmation: true,
            message: "High risk action requires confirmation"
          });
      }

      reply.hijack();

      const response = reply.raw;
      response.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
        "X-Request-ID": requestId,
        "X-Risk-Level": guardOutcome.riskLevel
      });

      let accumulated = "";
      let streamClosed = false;

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

      const disconnectHandler = (): void => {
        streamClosed = true;
        streamingClient.abortCurrentStream();
      };

      request.raw.socket.on("close", disconnectHandler);

      await streamingClient.streamChat(
        guardOutcome.llmMessages,
        {},
        (chunk) => {
          const inspection = streamingGuard.inspect(chunk, accumulated);
          if (inspection.terminate) {
            sendSse({
              error: "stream_terminated",
              reason: inspection.reason ?? "sensitive_pattern"
            });
            streamingClient.abortCurrentStream();
            closeStream();
            return;
          }

          accumulated += chunk;
          sendSse({ chunk });
        },
        () => {
          sendSse({ done: true });
          closeStream();
        },
        () => {
          if (!streamClosed) {
            sendSse({ error: "stream_error" });
            closeStream();
          }
        }
      );

      request.raw.socket.off("close", disconnectHandler);
    }
  );
};

export default fp(chatRoutes, {
  name: "chat-routes"
});
