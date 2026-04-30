import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import rateLimit from "@fastify/rate-limit";
import { config } from "./config";
import chatRoutes from "./routes/chat";
import { redisClient } from "./services/redisClient";
import { logger } from "./utils/logger";

export const buildServer = async () => {
  const app = Fastify({
    loggerInstance: logger,
    requestTimeout: 60_000
  });

  await app.register(rateLimit, {
    global: true,
    max: 30,
    timeWindow: "1 minute"
  });

  app.get("/health", async () => ({ status: "ok", service: "zentris", timestamp: Date.now() }));

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
