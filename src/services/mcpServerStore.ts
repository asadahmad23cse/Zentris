import { randomUUID } from "node:crypto";
import { redisClient } from "./redisClient";
import { logger } from "../utils/logger";

// MCP servers are persisted in a single Redis hash keyed by server_id. The
// dashboard MCP Servers page (GET/POST/PUT/DELETE /v1/mcp/server) is backed
// entirely by this store.
const MCP_SERVERS_KEY = "zentris:mcp_servers";

export interface StoredMCPServer {
  server_id: string;
  server_name: string | null;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
  status: string;
  [key: string]: unknown;
}

const parseServer = (value: string): StoredMCPServer | null => {
  try {
    return JSON.parse(value) as StoredMCPServer;
  } catch (error) {
    logger.warn({ err: error }, "mcp_store_parse_failed");
    return null;
  }
};

export const listMCPServers = async (): Promise<StoredMCPServer[]> => {
  try {
    const raw = await redisClient.hgetall(MCP_SERVERS_KEY);
    return Object.values(raw)
      .map(parseServer)
      .filter((server): server is StoredMCPServer => server !== null)
      .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  } catch (error) {
    logger.error({ err: error }, "mcp_store_list_failed");
    return [];
  }
};

export const createMCPServer = async (form: Record<string, unknown>): Promise<StoredMCPServer> => {
  const serverId = (form.server_id as string) || `mcp-${randomUUID()}`;
  const now = new Date().toISOString();
  // TRANSPORT.OPENAPI is a UI-only concept; the wire value must be http/sse/stdio.
  const rawTransport = (form.transport as string) || "http";
  const transport = rawTransport === "openapi" ? "http" : rawTransport;
  const server: StoredMCPServer = {
    ...form,
    server_id: serverId,
    server_name: (form.server_name as string) ?? (form.alias as string) ?? "Unnamed MCP Server",
    alias: (form.alias as string) ?? (form.server_name as string) ?? null,
    description: (form.description as string) ?? null,
    url: (form.url as string) ?? null,
    transport,
    auth_type: (form.auth_type as string) ?? "none",
    mcp_access_groups: (form.mcp_access_groups as string[]) ?? [],
    teams: (form.teams as unknown[]) ?? [],
    status: "unknown",
    approval_status: "active",
    created_at: now,
    created_by: "admin",
    updated_at: now,
    updated_by: "admin"
  };
  await redisClient.hset(MCP_SERVERS_KEY, serverId, JSON.stringify(server));
  return server;
};

export const updateMCPServer = async (form: Record<string, unknown>): Promise<StoredMCPServer | null> => {
  const serverId = form.server_id as string | undefined;
  if (!serverId) return null;
  const raw = await redisClient.hget(MCP_SERVERS_KEY, serverId);
  if (!raw) return null;
  const existing = parseServer(raw);
  if (!existing) return null;
  const updated: StoredMCPServer = {
    ...existing,
    ...form,
    server_id: serverId,
    updated_at: new Date().toISOString(),
    updated_by: "admin"
  };
  await redisClient.hset(MCP_SERVERS_KEY, serverId, JSON.stringify(updated));
  return updated;
};

export const deleteMCPServer = async (serverId: string): Promise<boolean> => {
  const removed = await redisClient.hdel(MCP_SERVERS_KEY, serverId);
  return removed > 0;
};
