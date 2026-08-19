import { randomUUID } from "node:crypto";
import { redisClient } from "./redisClient";
import { logger } from "../utils/logger";

// A2A agents are persisted in a single Redis hash keyed by agent_id. The dashboard
// Agents page (GET/POST/DELETE /v1/agents) is backed entirely by this store.
const AGENTS_KEY = "zentris:agents";

export interface StoredAgent {
  agent_id: string;
  agent_name: string;
  description: string;
  agent_card_params: Record<string, unknown>;
  Zentris_params: Record<string, unknown>;
  spend: number;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

const parseAgent = (value: string): StoredAgent | null => {
  try {
    return JSON.parse(value) as StoredAgent;
  } catch (error) {
    logger.warn({ err: error }, "agent_store_parse_failed");
    return null;
  }
};

export const listAgents = async (): Promise<StoredAgent[]> => {
  try {
    const raw = await redisClient.hgetall(AGENTS_KEY);
    return Object.values(raw)
      .map(parseAgent)
      .filter((agent): agent is StoredAgent => agent !== null)
      .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  } catch (error) {
    logger.error({ err: error }, "agent_store_list_failed");
    return [];
  }
};

export const createAgent = async (body: Record<string, unknown>): Promise<StoredAgent> => {
  const agentId = `agent-${randomUUID()}`;
  const now = new Date().toISOString();
  const card = (body.agent_card_params ?? {}) as Record<string, unknown>;
  const agent: StoredAgent = {
    agent_id: agentId,
    agent_name: (body.agent_name as string) || (card.name as string) || "Unnamed Agent",
    description: (card.description as string) ?? "",
    agent_card_params: card,
    Zentris_params: (body.Zentris_params ?? {}) as Record<string, unknown>,
    spend: 0,
    created_at: now,
    updated_at: now,
    ...(body.tpm_limit != null ? { tpm_limit: body.tpm_limit } : {}),
    ...(body.rpm_limit != null ? { rpm_limit: body.rpm_limit } : {}),
    ...(body.session_tpm_limit != null ? { session_tpm_limit: body.session_tpm_limit } : {}),
    ...(body.session_rpm_limit != null ? { session_rpm_limit: body.session_rpm_limit } : {}),
    ...(body.static_headers != null ? { static_headers: body.static_headers } : {}),
    ...(body.extra_headers != null ? { extra_headers: body.extra_headers } : {})
  };
  await redisClient.hset(AGENTS_KEY, agentId, JSON.stringify(agent));
  return agent;
};

export const deleteAgent = async (agentId: string): Promise<boolean> => {
  const removed = await redisClient.hdel(AGENTS_KEY, agentId);
  return removed > 0;
};

export const setAgentsPublic = async (agentIds: string[]): Promise<void> => {
  for (const id of agentIds) {
    const raw = await redisClient.hget(AGENTS_KEY, id);
    if (!raw) continue;
    const agent = parseAgent(raw);
    if (!agent) continue;
    agent.Zentris_params = { ...(agent.Zentris_params ?? {}), make_public: true };
    agent.updated_at = new Date().toISOString();
    await redisClient.hset(AGENTS_KEY, id, JSON.stringify(agent));
  }
};
