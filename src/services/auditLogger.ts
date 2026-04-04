import { type AuditLogEntry } from "../types";
import { redisClient } from "./redisClient";
import { logger } from "../utils/logger";

const AUDIT_TTL_SECONDS = 60 * 60 * 24;
const AUDIT_MAX_ENTRIES = 1000;

const auditKey = (sessionId: string): string => `audit:${sessionId}`;

const compareByTimestampDesc = (a: AuditLogEntry, b: AuditLogEntry): number => b.timestamp - a.timestamp;

export class AuditLogger {
  public async log(entry: Omit<AuditLogEntry, "timestamp">): Promise<void> {
    const withTimestamp: AuditLogEntry = {
      ...entry,
      timestamp: Date.now()
    };

    logger.info({ auditEntry: withTimestamp }, "audit_entry_recorded");

    try {
      const key = auditKey(withTimestamp.sessionId);
      const pipeline = redisClient.multi();
      pipeline.lpush(key, JSON.stringify(withTimestamp));
      pipeline.ltrim(key, 0, AUDIT_MAX_ENTRIES - 1);
      pipeline.expire(key, AUDIT_TTL_SECONDS);
      await pipeline.exec();
    } catch (error) {
      logger.error({ err: error, sessionId: withTimestamp.sessionId }, "audit_entry_persist_failed");
    }
  }

  public async getSessionAudit(sessionId: string): Promise<AuditLogEntry[]> {
    try {
      const rawEntries = await redisClient.lrange(auditKey(sessionId), 0, -1);
      const parsed: AuditLogEntry[] = [];

      for (const rawEntry of rawEntries) {
        try {
          const decoded = JSON.parse(rawEntry) as AuditLogEntry;
          parsed.push(decoded);
        } catch (error) {
          logger.warn({ err: error, sessionId }, "audit_entry_parse_failed");
        }
      }

      return parsed.sort(compareByTimestampDesc);
    } catch (error) {
      logger.error({ err: error, sessionId }, "audit_entry_read_failed");
      return [];
    }
  }
}
