import Redis from "ioredis";
import { config } from "../config";
import { type ChatMessage } from "../types";
import { logger } from "../utils/logger";

const SESSION_TTL_SECONDS = 60 * 60;

const messageListKey = (sessionId: string): string => `zentris:session:${sessionId}:messages`;
const metaHashKey = (sessionId: string): string => `zentris:session:${sessionId}:meta`;
const probeListKey = (sessionId: string): string => `zentris:session:${sessionId}:probes`;
const timestampListKey = (sessionId: string): string => `zentris:session:${sessionId}:timestamps`;

const CONTEXT_STATE_SCRIPT = `
-- context_state_update
redis.call('RPUSH', KEYS[1], ARGV[1])
redis.call('LTRIM', KEYS[1], -tonumber(ARGV[2]), -1)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
local messages = redis.call('LRANGE', KEYS[1], 0, -1)

redis.call('RPUSH', KEYS[2], ARGV[4])
redis.call('LTRIM', KEYS[2], -tonumber(ARGV[5]), -1)
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[6]))
local probes = redis.call('LRANGE', KEYS[2], 0, -1)
local probe_count = 0
for _, value in ipairs(probes) do
  if value == '1' then probe_count = probe_count + 1 end
end
redis.call('HSET', KEYS[4], 'probeCount', tostring(probe_count))
redis.call('EXPIRE', KEYS[4], tonumber(ARGV[6]))

redis.call('RPUSH', KEYS[3], ARGV[7])
redis.call('LTRIM', KEYS[3], -100, -1)
redis.call('EXPIRE', KEYS[3], 3600)
local timestamps = redis.call('LRANGE', KEYS[3], 0, -1)
local recent_timestamp_count = 0
local now = tonumber(ARGV[7])
local velocity_window = tonumber(ARGV[8])
for _, value in ipairs(timestamps) do
  local timestamp = tonumber(value)
  if timestamp and now - timestamp <= velocity_window then
    recent_timestamp_count = recent_timestamp_count + 1
  end
end

return cjson.encode({messages=messages, probeCount=probe_count, recentTimestampCount=recent_timestamp_count})
`;

const isChatMessage = (value: unknown): value is ChatMessage => {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Partial<ChatMessage>;
  return (
    (candidate.role === "system" || candidate.role === "user" || candidate.role === "assistant") &&
    typeof candidate.content === "string" &&
    typeof candidate.timestamp === "number"
  );
};

export const redisClient = new Redis(config.REDIS_URL, {
  lazyConnect: true,
  maxRetriesPerRequest: 2
});

redisClient.on("error", (error: Error) => {
  logger.error({ err: error }, "redis_client_error");
});

export interface RedisHealth {
  ok: boolean;
  status: string;
  latencyMs?: number;
  reason?: string;
}

export const checkRedisHealth = async (timeoutMs = 1_000): Promise<RedisHealth> => {
  const startedAt = Date.now();

  try {
    const ping = redisClient.ping();
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("redis_health_timeout")), timeoutMs);
    });

    const result = await Promise.race([ping, timeout]);
    return {
      ok: result === "PONG",
      status: redisClient.status,
      latencyMs: Date.now() - startedAt
    };
  } catch (error) {
    return {
      ok: false,
      status: redisClient.status,
      latencyMs: Date.now() - startedAt,
      reason: error instanceof Error ? error.message : "redis_health_failed"
    };
  }
};

export const getSession = async (sessionId: string): Promise<ChatMessage[]> => {
  try {
    const messages = await redisClient.lrange(messageListKey(sessionId), 0, -1);
    const parsed: ChatMessage[] = [];

    for (const entry of messages) {
      try {
        const decoded: unknown = JSON.parse(entry);
        if (isChatMessage(decoded)) {
          parsed.push(decoded);
        }
      } catch (error) {
        logger.warn({ err: error, sessionId }, "redis_session_message_parse_failed");
      }
    }

    return parsed;
  } catch (error) {
    logger.error({ err: error, sessionId }, "redis_get_session_failed");
    return [];
  }
};

export const appendToSession = async (
  sessionId: string,
  message: ChatMessage,
  maxMessages: number
): Promise<void> => {
  const key = messageListKey(sessionId);
  const boundedMax = Math.max(1, maxMessages);

  try {
    const pipeline = redisClient.multi();
    pipeline.rpush(key, JSON.stringify(message));
    pipeline.ltrim(key, -boundedMax, -1);
    pipeline.expire(key, SESSION_TTL_SECONDS);
    await pipeline.exec();
  } catch (error) {
    logger.error({ err: error, sessionId }, "redis_append_session_failed");
  }
};

export interface ContextState {
  storedHistory: ChatMessage[];
  probeCount: number;
  recentTimestampCount: number;
}

export const updateContextState = async (
  sessionId: string,
  message: ChatMessage,
  maxMessages: number,
  warningDetected: boolean,
  probeWindowSize: number,
  probeTtlSeconds: number,
  velocityWindowMs: number
): Promise<ContextState> => {
  try {
    const encoded = await redisClient.eval(
      CONTEXT_STATE_SCRIPT,
      4,
      messageListKey(sessionId),
      probeListKey(sessionId),
      timestampListKey(sessionId),
      metaHashKey(sessionId),
      JSON.stringify(message),
      Math.max(1, maxMessages),
      SESSION_TTL_SECONDS,
      warningDetected ? "1" : "0",
      Math.max(1, probeWindowSize),
      Math.max(1, probeTtlSeconds),
      message.timestamp,
      Math.max(1, velocityWindowMs)
    );
    if (typeof encoded !== "string") throw new Error("context_state_invalid_response");
    const decoded = JSON.parse(encoded) as {
      messages?: unknown;
      probeCount?: unknown;
      recentTimestampCount?: unknown;
    };
    const storedHistory: ChatMessage[] = [];
    if (Array.isArray(decoded.messages)) {
      for (const rawMessage of decoded.messages) {
        if (typeof rawMessage !== "string") continue;
        try {
          const parsed: unknown = JSON.parse(rawMessage);
          if (isChatMessage(parsed)) storedHistory.push(parsed);
        } catch {
          // Ignore malformed legacy entries without echoing their content.
        }
      }
    }
    return {
      storedHistory,
      probeCount: typeof decoded.probeCount === "number" ? decoded.probeCount : 0,
      recentTimestampCount: typeof decoded.recentTimestampCount === "number" ? decoded.recentTimestampCount : 0
    };
  } catch (error) {
    logger.error({ err: error, sessionId }, "redis_context_state_update_failed");
    return { storedHistory: [], probeCount: warningDetected ? 1 : 0, recentTimestampCount: 1 };
  }
};

export const getSessionMeta = async (sessionId: string): Promise<Record<string, string>> => {
  try {
    return await redisClient.hgetall(metaHashKey(sessionId));
  } catch (error) {
    logger.error({ err: error, sessionId }, "redis_get_session_meta_failed");
    return {};
  }
};

export const setSessionMeta = async (
  sessionId: string,
  key: string,
  value: string,
  ttlSeconds?: number
): Promise<void> => {
  const ttl = ttlSeconds ?? SESSION_TTL_SECONDS;
  const metaKey = metaHashKey(sessionId);

  try {
    const pipeline = redisClient.multi();
    pipeline.hset(metaKey, key, value);
    pipeline.expire(metaKey, ttl);
    await pipeline.exec();
  } catch (error) {
    logger.error({ err: error, sessionId, key }, "redis_set_session_meta_failed");
  }
};

export const clearSession = async (sessionId: string): Promise<void> => {
  try {
    await redisClient.del(messageListKey(sessionId), metaHashKey(sessionId));
  } catch (error) {
    logger.error({ err: error, sessionId }, "redis_clear_session_failed");
  }
};
