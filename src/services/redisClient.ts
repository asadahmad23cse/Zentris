import Redis from "ioredis";
import { config } from "../config";
import { type ChatMessage } from "../types";
import { logger } from "../utils/logger";

const SESSION_TTL_SECONDS = 60 * 60;

const messageListKey = (sessionId: string): string => `zentris:session:${sessionId}:messages`;
const metaHashKey = (sessionId: string): string => `zentris:session:${sessionId}:meta`;

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
