import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import rateLimit from "@fastify/rate-limit";
import authMiddleware from "./auth/authMiddleware";
import { config } from "./config";
import chatRoutes, { type ChatRouteOptions } from "./routes/chat";
import publicRoutes, { type PublicRouteOptions } from "./routes/public";
import demoRoutes from "./routes/demo";
import { checkRedisHealth, redisClient } from "./services/redisClient";
import { logger } from "./utils/logger";

interface ServerOptions {
  redisHealthCheck?: typeof checkRedisHealth;
  chatRoutes?: ChatRouteOptions;
  publicRoutes?: PublicRouteOptions;
}

export const buildServer = async (options: ServerOptions = {}) => {
  const redisHealthCheck = options.redisHealthCheck ?? checkRedisHealth;
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
    if (_request.raw.url?.startsWith("/demo")) {
      reply.header(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
      );
    } else {
      reply.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    }
    return payload;
  });

  app.addHook("onRequest", async (request, reply) => {
    if (config.ZENTRIS_DEMO_ENABLED && request.raw.url?.startsWith("/api/demo/")) {
      reply.header("Access-Control-Allow-Origin", "*");
      reply.header("Access-Control-Allow-Methods", "POST,OPTIONS");
      reply.header("Access-Control-Allow-Headers", "content-type");
    }

    const origin = request.headers.origin;
    const allowedOrigins = new Set([
      config.PUBLIC_WEB_ORIGIN,
      "https://litellm-dashboard-rose.vercel.app",
      "http://localhost:3000",
      "http://localhost:3001"
    ]);

    if (origin && allowedOrigins.has(origin)) {
      reply.header("Access-Control-Allow-Origin", origin);
      reply.header("Vary", "Origin");
      reply.header("Access-Control-Allow-Headers", "authorization,content-type");
      reply.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    }

    if (request.method === "OPTIONS") {
      return reply.code(204).send();
    }
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
    const redis = await redisHealthCheck();
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

  if (config.ZENTRIS_DEMO_ENABLED) {
    await app.register(demoRoutes);
  }
  await app.register(publicRoutes, options.publicRoutes ?? {});
  await app.register(authMiddleware);
  await app.register(chatRoutes, options.chatRoutes ?? {});

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
