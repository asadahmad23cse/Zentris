import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import rateLimit from "@fastify/rate-limit";
import authMiddleware from "./auth/authMiddleware";
import { config } from "./config";
import chatRoutes, { type ChatRouteOptions } from "./routes/chat";
import demoRoutes from "./routes/demo";
import gatewayRoutes from "./routes/gateway";
import publicRoutes from "./routes/public";
import litellmProxyRoutes from "./routes/litellmProxy";
import { checkRedisHealth, redisClient } from "./services/redisClient";
import { logger } from "./utils/logger";

interface ServerOptions {
  redisHealthCheck?: typeof checkRedisHealth;
  litellmHealthCheck?: () => Promise<{ ok: boolean; status: string; latencyMs: number; reason?: string }>;
  chatRoutes?: ChatRouteOptions;
}

const checkLiteLLMHealth = async (): Promise<{ ok: boolean; status: string; latencyMs: number; reason?: string }> => {
  const startedAt = Date.now();
  try {
    const parsed = new URL(config.LITELLM_BASE_URL);
    parsed.pathname = parsed.pathname.replace(/\/(?:v1)\/?$/, "").replace(/\/$/, "") + "/health/liveliness";
    parsed.search = "";
    const response = await fetch(parsed, { signal: AbortSignal.timeout(2_000) });
    return { ok: response.ok, status: response.ok ? "ready" : "unavailable", latencyMs: Date.now() - startedAt, ...(response.ok ? {} : { reason: `http_${response.status}` }) };
  } catch (error) {
    return { ok: false, status: "unavailable", latencyMs: Date.now() - startedAt, reason: error instanceof Error ? error.name : "connection_failed" };
  }
};

export const buildServer = async (options: ServerOptions = {}) => {
  const redisHealthCheck = options.redisHealthCheck ?? checkRedisHealth;
  const litellmHealthCheck = options.litellmHealthCheck ?? checkLiteLLMHealth;
  const app = Fastify({
    loggerInstance: logger,
    genReqId: () => randomUUID(),
    disableRequestLogging: true,
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
      "http://localhost:3000",
      "http://localhost:3001"
    ]);

    if (origin && allowedOrigins.has(origin)) {
      reply.header("Access-Control-Allow-Origin", origin);
      reply.header("Vary", "Origin");
      reply.header("Access-Control-Allow-Headers", "authorization,content-type,x-zentris-tags,x-stainless-lang,x-stainless-package-version,x-stainless-os,x-stainless-arch,x-stainless-runtime,x-stainless-runtime-version,x-stainless-retry-count,x-stainless-timeout");
      reply.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    }

    if (request.method === "OPTIONS") {
      return reply.code(204).send();
    }
  });

  await app.register(rateLimit, {
    global: true,
    max: Math.max(1, Math.ceil(config.RATE_LIMIT_MAX / (() => {
      const parsed = Number(process.env.ZENTRIS_WORKER_COUNT ?? "1");
      return Number.isInteger(parsed) && parsed > 0 ? parsed : 1;
    })())),
    timeWindow: config.RATE_LIMIT_WINDOW
  });

  app.get("/health", { config: { rateLimit: false } }, async () => ({ status: "ok", service: "zentris", timestamp: Date.now() }));

  app.get("/health/liveness", { config: { rateLimit: false } }, async () => ({
    status: "ok",
    service: "zentris",
    timestamp: Date.now(),
    uptimeSeconds: Math.round(process.uptime())
  }));

  app.get("/health/readiness", { config: { rateLimit: false } }, async (_request, reply) => {
    const [redis, litellm] = await Promise.all([redisHealthCheck(), litellmHealthCheck()]);
    const ready = redis.ok && litellm.ok;

    return reply.code(ready ? 200 : 503).send({
      status: ready ? "ready" : "not_ready",
      service: "zentris",
      timestamp: Date.now(),
      dependencies: {
        redis,
        litellm
      }
    });
  });

  app.setErrorHandler((error: Error & { statusCode?: number; code?: string; validation?: unknown }, request: FastifyRequest, reply: FastifyReply) => {
    const statusCode = typeof error.statusCode === "number" ? error.statusCode : 500;
    const safeStatus = statusCode >= 400 && statusCode < 500 ? statusCode : 500;
    request.log[safeStatus >= 500 ? "error" : "warn"](
      { errorType: error.name, code: error.code, statusCode: safeStatus },
      safeStatus >= 500 ? "unhandled_request_error" : "request_rejected"
    );
    if (reply.sent) return;
    if (error.validation) {
      return reply.code(400).send({
        error: { message: "Request body validation failed", type: "invalid_request_error", code: "invalid_request" }
      });
    }
    if (safeStatus === 429) {
      return reply.code(429).send({ error: { message: "Rate limit exceeded", type: "rate_limit_error", code: "rate_limit_exceeded" } });
    }
    if (safeStatus < 500) {
      return reply.code(safeStatus).send({ error: { message: "Request rejected", type: "request_error", code: error.code ?? "request_rejected" } });
    }
    return reply.code(500).send({ error: { message: "An unexpected error occurred", type: "server_error", code: "internal_error" } });
  });

  if (config.ZENTRIS_DEMO_ENABLED) {
    await app.register(demoRoutes);
  }

  await app.register(publicRoutes, options.chatRoutes ?? {});
  await app.register(authMiddleware);
  await app.register(gatewayRoutes);
  await app.register(chatRoutes, options.chatRoutes ?? {});
  await app.register(litellmProxyRoutes);

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

export const start = async (): Promise<void> => {
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
