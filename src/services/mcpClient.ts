import { logger } from "../utils/logger";

// Minimal MCP "Streamable HTTP" client: speaks JSON-RPC 2.0 over a single POST
// endpoint and parses both plain-JSON and SSE (text/event-stream) responses.
// Used to make the dashboard MCP Servers genuinely functional — list and call
// real tools on a live MCP server.

interface JsonRpcResponse {
  jsonrpc: string;
  id?: number | string;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

export interface McpToolDef {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

const REQUEST_TIMEOUT_MS = 25_000;

const parseMcpBody = (contentType: string, text: string): JsonRpcResponse | null => {
  if (contentType.includes("text/event-stream")) {
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("data:")) continue;
      const payload = trimmed.slice(5).trim();
      if (!payload || payload === "[DONE]") continue;
      try {
        const parsed = JSON.parse(payload) as JsonRpcResponse;
        if (parsed.result !== undefined || parsed.error !== undefined) return parsed;
      } catch {
        // skip malformed SSE data line
      }
    }
    return null;
  }
  try {
    return JSON.parse(text) as JsonRpcResponse;
  } catch {
    return null;
  }
};

const rpc = async (
  url: string,
  method: string,
  params: Record<string, unknown> | undefined,
  sessionId: string | undefined,
  extraHeaders: Record<string, string>
): Promise<{ parsed: JsonRpcResponse | null; sessionId: string | undefined; status: number }> => {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    ...(sessionId ? { "Mcp-Session-Id": sessionId } : {}),
    ...extraHeaders
  };
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: Math.floor(Math.random() * 1e9), method, ...(params ? { params } : {}) }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
  });
  const returnedSession = response.headers.get("mcp-session-id") ?? sessionId;
  const text = await response.text();
  const parsed = parseMcpBody(response.headers.get("content-type") ?? "", text);
  return { parsed, sessionId: returnedSession, status: response.status };
};

const initialize = async (url: string, extraHeaders: Record<string, string>): Promise<string | undefined> => {
  const { parsed, sessionId, status } = await rpc(
    url,
    "initialize",
    { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "zentris-gateway", version: "1.0.0" } },
    undefined,
    extraHeaders
  );
  if (status >= 400 || parsed?.error) {
    throw new Error(parsed?.error?.message ?? `MCP initialize failed (HTTP ${status})`);
  }
  if (sessionId) {
    // Stateful servers require the initialized notification; fire-and-forget.
    await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "Mcp-Session-Id": sessionId,
        ...extraHeaders
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      signal: AbortSignal.timeout(10_000)
    }).catch(() => {
      /* notification is best-effort */
    });
  }
  return sessionId;
};

export const mcpListTools = async (url: string, extraHeaders: Record<string, string> = {}): Promise<McpToolDef[]> => {
  const sessionId = await initialize(url, extraHeaders);
  const { parsed, status } = await rpc(url, "tools/list", {}, sessionId, extraHeaders);
  if (status >= 400 || parsed?.error) throw new Error(parsed?.error?.message ?? `tools/list failed (HTTP ${status})`);
  const tools = parsed?.result?.tools;
  return Array.isArray(tools) ? (tools as McpToolDef[]) : [];
};

export const mcpCallTool = async (
  url: string,
  name: string,
  args: Record<string, unknown>,
  extraHeaders: Record<string, string> = {}
): Promise<Record<string, unknown>> => {
  const sessionId = await initialize(url, extraHeaders);
  const { parsed, status } = await rpc(url, "tools/call", { name, arguments: args ?? {} }, sessionId, extraHeaders);
  if (status >= 400 || parsed?.error) throw new Error(parsed?.error?.message ?? `tools/call failed (HTTP ${status})`);
  return parsed?.result ?? {};
};

// Build upstream auth headers from a stored MCP server's credential fields.
export const mcpAuthHeaders = (server: Record<string, unknown>): Record<string, string> => {
  const headers: Record<string, string> = {};
  const authType = server.auth_type as string | undefined;
  const token = (server.mcp_access_token ?? server.bearer_token ?? server.api_key ?? server.mcp_api_key) as string | undefined;
  if ((authType === "bearer_token" || authType === "api_key" || authType === "token") && token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const staticHeaders = server.static_headers;
  if (staticHeaders && typeof staticHeaders === "object") {
    for (const [key, value] of Object.entries(staticHeaders as Record<string, unknown>)) {
      if (typeof value === "string") headers[key] = value;
    }
  }
  return headers;
};

export const safeLogMcpError = (context: string, error: unknown): void => {
  logger.warn({ err: error instanceof Error ? error.message : "mcp_error", context }, "mcp_client_error");
};
