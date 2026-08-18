import fp from "fastify-plugin";
import { type FastifyPluginAsync } from "fastify";
import { config } from "../config";
import { type AuthenticatedIdentity } from "../types";
import { verifyAccessToken } from "./jwt";
import { resolveLiteLLMIdentity } from "./litellmIdentity";

declare module "fastify" {
  interface FastifyRequest {
    identity: AuthenticatedIdentity;
  }
}

const OWNED_PUBLIC_PATHS = new Set([
  "/.well-known/litellm-ui-config",
  "/public/model_hub/info",
  "/public/model_hub",
  "/public/agent_hub",
  "/public/mcp_hub",
  "/public/dashboard-token",
  "/public/Zentris_model_cost_map",
  "/public/providers/fields",
  "/public/agents/fields"
]);

const authMiddleware: FastifyPluginAsync = async (app) => {
  app.addHook("onRequest", async (request, reply) => {
    const requestUrl = request.raw.url ?? "";
    const requestPath = requestUrl.split("?", 1)[0];
    const isPublicDemo =
      config.ZENTRIS_DEMO_ENABLED && (requestUrl.startsWith("/demo") || requestUrl.startsWith("/api/demo/"));

    const isOwnedPublicRoute = OWNED_PUBLIC_PATHS.has(requestPath) || (
      (config.ZENTRIS_DEMO_ENABLED || config.NODE_ENV === "test") &&
      (requestPath === "/public/llm-status" || requestPath === "/v1/public/chat")
    );

    const isLoginRoute =
      requestUrl.startsWith("/v2/login") ||
      requestUrl.startsWith("/v3/login") ||
      requestUrl.startsWith("/sso/callback");

    // Exempt exact owned paths, never a prefix: an unknown /public/* route must
    // not fall through to internal LiteLLM without authentication.
    if (requestUrl.startsWith("/health") || isPublicDemo || isOwnedPublicRoute || isLoginRoute) {
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
      if (token.split(".").length === 3) {
        try {
          request.identity = verifyAccessToken(token, config.JWT_SECRET);
          return;
        } catch {
          // LiteLLM UI tokens may use a different signing secret; validate them through LiteLLM.
        }
      }
      request.identity = await resolveLiteLLMIdentity(token);
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
