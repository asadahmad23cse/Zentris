import { type AuditLogEntry } from "../types";
import { logger } from "../utils/logger";
import { sanitizeForLogging } from "../guards/dlpGuard";

export const toSafeAuditEntry = (
  entry: Omit<AuditLogEntry, "timestamp">,
  timestamp = Date.now()
): AuditLogEntry => ({
  timestamp,
  sessionId: entry.sessionId,
  contentLength: entry.contentLength,
  decisions: entry.decisions,
  finalAction: entry.finalAction,
  riskScore: entry.riskScore,
  durationMs: entry.durationMs,
  userRole: entry.userRole,
  intent: entry.intent
});

export class AuditLogger {
  public async log(entry: Omit<AuditLogEntry, "timestamp">): Promise<void> {
    const withTimestamp = toSafeAuditEntry(entry);
    const sanitizedEntry = sanitizeForLogging(withTimestamp);

    // The bounded telemetry stream is the only persistent audit path. Keeping a
    // second per-session Redis list duplicated writes, increased request latency,
    // and previously risked placing prompt bodies in application logs.
    logger.debug({ auditEntry: sanitizedEntry }, "audit_entry_recorded");
  }
}
