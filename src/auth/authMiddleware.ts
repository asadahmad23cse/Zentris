import fp from "fastify-plugin";
import { type FastifyPluginAsync } from "fastify";
import { config } from "../config";
import { type AuthenticatedIdentity } from "../types";
import { verifyAccessToken } from "./jwt";

declare module "fastify" {
  interface FastifyRequest {
    identity: AuthenticatedIdentity;
  }
}

const authMiddleware: FastifyPluginAsync = async (app) => {
  app.addHook("onRequest", async (request, reply) => {
    const requestUrl = request.raw.url ?? "";
    const isPublicDemo =
      config.ZENTRIS_DEMO_ENABLED && (requestUrl.startsWith("/demo") || requestUrl.startsWith("/api/demo/"));

    const isPublicRoute =
      requestUrl.startsWith("/public/") ||
      requestUrl.startsWith("/.well-known/") ||
      requestUrl.startsWith("/v1/public/");

    if (requestUrl.startsWith("/health") || isPublicDemo || isPublicRoute) {
      return;
    }

    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      reply.code(401).send({
        error: "Unauthorized",
        reason: "missing_bearer_token"
      });
      return;
    }

    const token = authHeader.slice("Bearer ".length).trim();
    if (token.length === 0) {
      reply.code(401).send({
        error: "Unauthorized",
        reason: "missing_bearer_token"
      });
      return;
    }

    try {
      request.identity = verifyAccessToken(token, config.JWT_SECRET);
    } catch (error) {
      request.log.warn(
        { err: error instanceof Error ? error.message : "token_verification_failed" },
        "request_auth_rejected"
      );
      reply.code(401).send({
        error: "Unauthorized",
        reason: "invalid_or_expired_token"
      });
    }
  });
};

export default fp(authMiddleware, {
  name: "auth-middleware"
});
