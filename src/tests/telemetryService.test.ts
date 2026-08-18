import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { TelemetryService } from "../services/telemetryService";

describe("TelemetryService", () => {
  it("creates a versioned, expiring, safe-metadata envelope", async () => {
    let serialized = "";
    const telemetry = new TelemetryService(async (payload) => { serialized = payload; });
    await telemetry.enqueue({
      requestId: "request-1",
      sessionId: "session-1",
      identity: { userId: "user-1", userRole: "operator", tenantId: "tenant-1", orgId: null },
      route: "/v1/chat",
      model: "test-model",
      modelParameters: { temperature: 0.2 },
      rawMessages: [{ role: "user", content: "exact history accepted by policy" }],
      sanitizedMessages: [{ role: "user", content: "sanitized history" }],
      status: "success",
      latencyMs: 12,
      security: {
        requestId: "request-1",
        injectionDetected: true,
        warningApplied: true,
        dlpDetected: false,
        risk: "high",
        score: 80,
        matchedRules: ["instruction_hierarchy_override"],
        findings: [{
          kind: "prompt_injection", ruleId: "instruction_hierarchy_override", category: "instruction_override",
          stage: "input", risk: "high", score: 80, action: "warn"
        }]
      }
    });

    const envelope = JSON.parse(serialized);
    assert.equal(envelope.version, 1);
    assert.equal(envelope.kind, "conversation");
    assert.equal(envelope.conversation.security.findings[0].ruleId, "instruction_hierarchy_override");
    assert.ok(Date.parse(envelope.conversation.rawExpiresAt) > Date.now());
    assert.ok(Date.parse(envelope.conversation.eventExpiresAt) > Date.parse(envelope.conversation.rawExpiresAt));
  });
});
