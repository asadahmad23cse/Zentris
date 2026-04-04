import {
  type AuthorizationResult,
  type ContextGuardResult,
  type GuardResult,
  type IntentClassificationResult,
  type PipelineContext
} from "../types";

interface DecisionInputs {
  injectionResult: GuardResult;
  contextResult: ContextGuardResult;
  intentResult: IntentClassificationResult;
  authResult: AuthorizationResult;
  piiDetected: string[];
}

const assertDecisionInputs = (context: PipelineContext): DecisionInputs => {
  if (!context.injectionResult || !context.contextResult || !context.intentResult || !context.authResult) {
    throw new Error("incomplete_pipeline_context");
  }

  return {
    injectionResult: context.injectionResult,
    contextResult: context.contextResult,
    intentResult: context.intentResult,
    authResult: context.authResult,
    piiDetected: context.piiDetected ?? []
  };
};

export class ExecutionGuard {
  public decide(context: PipelineContext): GuardResult {
    try {
      const { injectionResult, contextResult, intentResult, authResult, piiDetected } =
        assertDecisionInputs(context);

      if (injectionResult.safe === false && injectionResult.risk === "high") {
        return {
          safe: false,
          risk: "high",
          action: "block",
          reason: "injection_detected_high"
        };
      }

      if (authResult.authorized === false) {
        return {
          safe: false,
          risk: "high",
          action: "block",
          reason: `unauthorized: ${authResult.reason}`
        };
      }

      if (contextResult.riskScore >= 70) {
        return {
          safe: false,
          risk: "high",
          action: "block",
          reason: `context_anomaly: ${contextResult.reason}`
        };
      }

      if (injectionResult.risk === "medium" || contextResult.riskScore >= 40) {
        return {
          safe: false,
          risk: "medium",
          action: "sanitize",
          reason: "elevated_risk"
        };
      }

      if (intentResult.intent === "execute" && intentResult.riskScore >= 50) {
        return {
          safe: false,
          risk: "medium",
          action: "require_confirmation",
          reason: "execute_intent_requires_confirmation"
        };
      }

      if (piiDetected.length > 0) {
        return {
          safe: false,
          risk: "medium",
          action: "sanitize",
          reason: `pii_detected: ${piiDetected.join(", ")}`
        };
      }

      return {
        safe: true,
        risk: "low",
        action: "allow",
        reason: "allowed"
      };
    } catch {
      return {
        safe: false,
        risk: "high",
        action: "block",
        reason: "guard_internal_error"
      };
    }
  }
}
