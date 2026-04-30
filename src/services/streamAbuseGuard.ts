import { config } from "../config";
import { redisClient } from "./redisClient";

const userStreamsKey = (userId: string): string => `zentris:stream:active:user:${userId}`;
const sessionStreamsKey = (sessionId: string): string => `zentris:stream:active:session:${sessionId}`;
const sessionSuspiciousKey = (sessionId: string): string => `zentris:stream:suspicious:${sessionId}`;

const ACQUIRE_STREAM_SLOT_SCRIPT = `
-- stream_limit_acquire
local userKey = KEYS[1]
local sessionKey = KEYS[2]
local streamId = ARGV[1]
local maxUserStreams = tonumber(ARGV[2])
local maxSessionStreams = tonumber(ARGV[3])
local ttlSeconds = tonumber(ARGV[4])

if redis.call("SISMEMBER", userKey, streamId) == 1 then
  local userCount = redis.call("SCARD", userKey)
  local sessionCount = redis.call("SCARD", sessionKey)
  return {1, userCount, sessionCount}
end

local userCount = redis.call("SCARD", userKey)
local sessionCount = redis.call("SCARD", sessionKey)
if userCount >= maxUserStreams or sessionCount >= maxSessionStreams then
  return {0, userCount, sessionCount}
end

redis.call("SADD", userKey, streamId)
redis.call("SADD", sessionKey, streamId)
redis.call("EXPIRE", userKey, ttlSeconds)
redis.call("EXPIRE", sessionKey, ttlSeconds)
return {1, userCount + 1, sessionCount + 1}
`;

const RELEASE_STREAM_SLOT_SCRIPT = `
-- stream_limit_release
local userKey = KEYS[1]
local sessionKey = KEYS[2]
local streamId = ARGV[1]
redis.call("SREM", userKey, streamId)
redis.call("SREM", sessionKey, streamId)
if redis.call("SCARD", userKey) == 0 then
  redis.call("DEL", userKey)
end
if redis.call("SCARD", sessionKey) == 0 then
  redis.call("DEL", sessionKey)
end
return 1
`;

export interface StreamSlotResult {
  allowed: boolean;
  userActiveStreams: number;
  sessionActiveStreams: number;
  reason?: string;
}

export class StreamAbuseGuard {
  public async acquireSlot(userId: string, sessionId: string, streamId: string): Promise<StreamSlotResult> {
    try {
      const result = (await redisClient.eval(
        ACQUIRE_STREAM_SLOT_SCRIPT,
        2,
        userStreamsKey(userId),
        sessionStreamsKey(sessionId),
        streamId,
        String(config.STREAMING_CONCURRENT_LIMIT),
        String(config.STREAMING_CONCURRENT_LIMIT),
        String(config.STREAMING_SLOT_TTL_SECONDS)
      )) as [number, number, number];

      const allowed = Array.isArray(result) && Number(result[0]) === 1;
      const userActiveStreams = Number(result[1] ?? 0);
      const sessionActiveStreams = Number(result[2] ?? 0);

      if (!allowed) {
        return {
          allowed: false,
          userActiveStreams,
          sessionActiveStreams,
          reason: "concurrent_stream_limit_exceeded"
        };
      }

      return {
        allowed: true,
        userActiveStreams,
        sessionActiveStreams
      };
    } catch {
      return {
        allowed: false,
        userActiveStreams: 0,
        sessionActiveStreams: 0,
        reason: "stream_concurrency_control_unavailable"
      };
    }
  }

  public async releaseSlot(userId: string, sessionId: string, streamId: string): Promise<void> {
    try {
      await redisClient.eval(
        RELEASE_STREAM_SLOT_SCRIPT,
        2,
        userStreamsKey(userId),
        sessionStreamsKey(sessionId),
        streamId
      );
    } catch {
      // best-effort cleanup
    }
  }

  public async recordSuspiciousEvents(sessionId: string, increment: number): Promise<number> {
    if (!Number.isFinite(increment) || increment <= 0) {
      return this.getSuspiciousEvents(sessionId);
    }

    const bounded = Math.min(100, Math.max(1, Math.floor(increment)));
    try {
      const total = await redisClient.incrby(sessionSuspiciousKey(sessionId), bounded);
      await redisClient.expire(sessionSuspiciousKey(sessionId), config.STREAMING_SESSION_SUSPICIOUS_WINDOW_SECONDS);
      return total;
    } catch {
      return Number.POSITIVE_INFINITY;
    }
  }

  public async getSuspiciousEvents(sessionId: string): Promise<number> {
    try {
      const value = await redisClient.get(sessionSuspiciousKey(sessionId));
      const parsed = value ? Number.parseInt(value, 10) : 0;
      return Number.isFinite(parsed) ? parsed : 0;
    } catch {
      return Number.POSITIVE_INFINITY;
    }
  }

  public async isSessionWatchdogExceeded(sessionId: string): Promise<boolean> {
    const total = await this.getSuspiciousEvents(sessionId);
    return total >= config.STREAMING_SESSION_SUSPICIOUS_EVENT_LIMIT;
  }
}
