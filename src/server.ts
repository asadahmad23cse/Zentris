import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import rateLimit from "@fastify/rate-limit";
import authMiddleware from "./auth/authMiddleware";
import { config } from "./config";
import chatRoutes from "./routes/chat";
import { checkRedisHealth, redisClient } from "./services/redisClient";
import { logger } from "./utils/logger";

export const buildServer = async () => {
  const app = Fastify({
    loggerInstance: logger,
    requestTimeout: 60_000,
    bodyLimit: config.REQUEST_BODY_LIMIT_BYTES
  });

  app.addHook("onSend", async (_request, reply, payload) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    reply.header("Cross-Origin-Resource-Policy", "same-origin");
    reply.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    return payload;
  });

  await app.register(rateLimit, {
    global: true,
    max: config.RATE_LIMIT_MAX,
    timeWindow: config.RATE_LIMIT_WINDOW
  });

  app.get("/health", async () => ({ status: "ok", service: "zentris", timestamp: Date.now() }));

  app.get("/health/liveness", async () => ({
    status: "ok",
    service: "zentris",
    timestamp: Date.now(),
    uptimeSeconds: Math.round(process.uptime())
  }));

  app.get("/health/readiness", async (_request, reply) => {
    const redis = await checkRedisHealth();
    const ready = redis.ok;

    return reply.code(ready ? 200 : 503).send({
      status: ready ? "ready" : "not_ready",
      service: "zentris",
      timestamp: Date.now(),
      dependencies: {
        redis
      }
    });
  });

  await app.register(authMiddleware);
  await app.register(chatRoutes);

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

  return app;
};

const shutdown = async (app: Awaited<ReturnType<typeof buildServer>>, signal: NodeJS.Signals): Promise<void> => {
  logger.info({ signal }, "shutdown_started");

  try {
    await app.close();
    if (redisClient.status === "ready" || redisClient.status === "connect" || redisClient.status === "connecting") {
      await redisClient.quit();
    } else if (redisClient.status !== "end") {
      redisClient.disconnect();
    }
    logger.info({ signal }, "shutdown_complete");
    process.exit(0);
  } catch (error) {
    logger.error({ err: error, signal }, "shutdown_failed");
    process.exit(1);
  }
};

const start = async (): Promise<void> => {
  const app = await buildServer();

  process.on("SIGINT", () => {
    void shutdown(app, "SIGINT");
  });

  process.on("SIGTERM", () => {
    void shutdown(app, "SIGTERM");
  });

  await app.listen({ port: config.PORT, host: "0.0.0.0" });
};

if (require.main === module) {
  void start().catch((error: unknown) => {
    logger.error({ err: error }, "server_start_failed");
    process.exit(1);
  });
}
