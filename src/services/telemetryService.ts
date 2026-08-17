import { sanitizeForLogging } from "../guards/dlpGuard";
import { type AuthenticatedIdentity, type SecurityMetadata } from "../types";
import { logger } from "../utils/logger";
import { redisClient } from "./redisClient";

const STREAM_KEY = "zentris:telemetry:v1";
const STREAM_MAX_LENGTH = 100_000;
const RAW_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const EVENT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

export interface ConversationTelemetry {
  requestId: string;
  sessionId: string;
  identity: AuthenticatedIdentity;
  route: string;
  model?: string;
  modelParameters?: unknown;
  rawMessages: unknown;
  sanitizedMessages: unknown;
  rawResult?: unknown;
  sanitizedResult?: unknown;
  status: "success" | "failed" | "rejected";
  httpStatus?: number;
  failureCode?: string;
  failureMessage?: string;
  latencyMs: number;
  security: SecurityMetadata;
}

export class TelemetryService {
  public constructor(private readonly appendForTest?: (payload: string) => Promise<void>) {}

  public async enqueue(conversation: ConversationTelemetry): Promise<void> {
    const now = Date.now();
    const payload = {
      version: 1,
      kind: "conversation",
      conversation: {
        ...conversation,
        rawExpiresAt: new Date(now + RAW_RETENTION_MS).toISOString(),
        eventExpiresAt: new Date(now + EVENT_RETENTION_MS).toISOString(),
        createdAt: new Date(now).toISOString()
      }
    };
    try {
      const serialized = JSON.stringify(payload);
      if (this.appendForTest) {
        await this.appendForTest(serialized);
        return;
      }
      if (configForTelemetryTests()) return;
      await redisClient.xadd(
        STREAM_KEY,
        "MAXLEN",
        "~",
        STREAM_MAX_LENGTH,
        "*",
        "payload",
        serialized
      );
    } catch (error) {
      logger.error(sanitizeForLogging({ error, requestId: conversation.requestId }), "telemetry_enqueue_failed");
    }
  }
}

const configForTelemetryTests = (): boolean => process.env.NODE_ENV === "test" && process.env.ZENTRIS_TEST_TELEMETRY !== "true";

export const telemetryStreamKey = STREAM_KEY;
