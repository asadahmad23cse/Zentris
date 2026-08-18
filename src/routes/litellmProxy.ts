import fp from "fastify-plugin";
import { type FastifyPluginAsync } from "fastify";
import { config } from "../config";

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
  "transfer-encoding", "upgrade", "host", "content-length"
]);

const PRIVATE_LITELLM_PATHS = new Set(["/v1/zentris/auth/introspect"]);
const MODEL_API_PREFIXES = [
  "/v1/responses", "/responses", "/v1/embeddings", "/embeddings", "/v1/images", "/images",
  "/v1/audio", "/audio", "/v1/rerank", "/rerank", "/v1/messages", "/anthropic/", "/vertex_ai/",
  "/v1/moderations", "/moderations", "/v1/assistants", "/assistants", "/v1/threads", "/threads",
  "/v1/batches", "/batches", "/v1/fine_tuning", "/fine_tuning", "/gemini/", "/openai/",
  "/bedrock/", "/cohere/", "/ollama/"
] as const;

const upstreamBase = (): string => {
  const parsed = new URL(config.LITELLM_BASE_URL);
  parsed.pathname = parsed.pathname.replace(/\/(?:v1)\/?$/, "").replace(/\/$/, "");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/$/, "");
};

const rewriteInternalLoginRedirect = (rawUrl: string, payload: Buffer, contentType: string | null): Buffer => {
  if (!/^\/v[23]\/login(?:\/exchange)?(?:\?|$)/.test(rawUrl) || !contentType?.includes("application/json")) {
    return payload;
  }
  try {
    const body = JSON.parse(payload.toString("utf8")) as Record<string, unknown>;
    if (typeof body.redirect_url !== "string") return payload;
    const redirect = new URL(body.redirect_url, upstreamBase());
    if (redirect.origin !== new URL(upstreamBase()).origin) return payload;
    body.redirect_url = `${redirect.pathname}${redirect.search}${redirect.hash}`;
    return Buffer.from(JSON.stringify(body));
  } catch {
    return payload;
  }
};

const proxyRoutes: FastifyPluginAsync = async (app) => {
  app.addContentTypeParser(/^multipart\//, { parseAs: "buffer", bodyLimit: config.REQUEST_BODY_LIMIT_BYTES }, (_request, body, done) => done(null, body));
  app.addContentTypeParser("application/octet-stream", { parseAs: "buffer", bodyLimit: config.REQUEST_BODY_LIMIT_BYTES }, (_request, body, done) => done(null, body));

  app.setNotFoundHandler(async (request, reply) => {
    const rawUrl = request.raw.url ?? request.url;
    const path = rawUrl.split("?", 1)[0];
    if (PRIVATE_LITELLM_PATHS.has(path)) return reply.code(404).send({ error: "not_found" });
    if (MODEL_API_PREFIXES.some((prefix) => path === prefix.replace(/\/$/, "") || path.startsWith(prefix))) {
      return reply.code(404).send({ error: "Model inference is available only through the Zentris chat gateway" });
    }
    // When LITELLM_BASE_URL points at a raw model provider (e.g. Groq) rather than
    // a real LiteLLM management proxy, unmatched dashboard/management endpoints
    // must NOT be forwarded upstream — that leaks dashboard calls to the provider
    // and returns malformed responses that crash admin pages. Return a clean 404.
    const upstreamHost = new URL(upstreamBase()).host;
    const RAW_PROVIDER_HOSTS = ["groq.com", "openai.com", "anthropic.com", "googleapis.com", "mistral.ai", "cohere.com", "perplexity.ai"];
    if (RAW_PROVIDER_HOSTS.some((h) => upstreamHost === h || upstreamHost.endsWith(`.${h}`))) {
      return reply.code(404).send({ error: "not_found" });
    }
    const url = `${upstreamBase()}${rawUrl}`;
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (HOP_BY_HOP.has(name.toLowerCase()) || value === undefined) continue;
      headers[name] = Array.isArray(value) ? value.join(", ") : String(value);
    }

    let body: BodyInit | undefined;
    if (!["GET", "HEAD"].includes(request.method) && request.body !== undefined) {
      if (Buffer.isBuffer(request.body)) body = new Uint8Array(request.body);
      else if (typeof request.body === "string") body = request.body;
      else body = JSON.stringify(request.body);
    }

    try {
      const upstream = await fetch(url, {
        method: request.method,
        headers,
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(60_000)
      });
      reply.code(upstream.status);
      upstream.headers.forEach((value, name) => {
        const lower = name.toLowerCase();
        if (!HOP_BY_HOP.has(lower) && lower !== "content-encoding" && lower !== "set-cookie") reply.header(name, value);
      });
      const getSetCookie = (upstream.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
      const cookies = getSetCookie?.call(upstream.headers);
      if (cookies && cookies.length > 0) reply.header("set-cookie", cookies);
      const payload = Buffer.from(await upstream.arrayBuffer());
      return reply.send(rewriteInternalLoginRedirect(rawUrl, payload, upstream.headers.get("content-type")));
    } catch (error) {
      request.log.warn({ errorType: error instanceof Error ? error.name : "unknown" }, "litellm_proxy_failed");
      return reply.code(error instanceof Error && error.name === "TimeoutError" ? 504 : 502).send({
        error: { message: "LiteLLM management service unavailable", type: "upstream_error" }
      });
    }
  });
};

export default fp(proxyRoutes, { name: "litellm-management-proxy" });
