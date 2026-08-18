import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { toSafeAuditEntry } from "../services/auditLogger";

describe("AuditLogger", () => {
  it("projects audit records onto metadata-only fields", () => {
    const unsafe = {
      sessionId: "session-1",
      contentLength: 42,
      decisions: [{ safe: true, risk: "low" as const, reason: "clean", action: "allow" as const }],
      finalAction: "allow" as const,
      riskScore: 10,
      durationMs: 4,
      userRole: "viewer" as const,
      intent: "read" as const,
      input: "do not log this prompt",
      normalizedInput: "do not log this prompt",
      userId: "do-not-log-this-principal"
    };

    const safe = toSafeAuditEntry(unsafe, 1234);
    assert.deepEqual(Object.keys(safe).sort(), [
      "contentLength", "decisions", "durationMs", "finalAction", "intent",
      "riskScore", "sessionId", "timestamp", "userRole"
    ].sort());
    assert.equal(JSON.stringify(safe).includes("do not log"), false);
  });
});
