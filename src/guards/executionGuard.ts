import {
  type AuthorizationResult,
  type ContextGuardResult,
  type GuardResult,
  type IntentClassificationResult,
  type PipelineContext
} from "../types";
import { ToolConfirmationTokenService } from "../services/toolConfirmationTokenService";
import { ToolRegistry } from "../services/toolRegistry";
import { logger } from "../utils/logger";

interface DecisionInputs {
  injectionResult: GuardResult;
  contextResult: ContextGuardResult;
  intentResult: IntentClassificationResult;
  authResult: AuthorizationResult;
  piiDetected: string[];
}

export interface ExecutionGuardResult extends GuardResult {
  confirmationToken?: string;
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
  private readonly toolRegistry = new ToolRegistry();
  private readonly confirmationService = new ToolConfirmationTokenService();

  public async decide(context: PipelineContext): Promise<ExecutionGuardResult> {
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

      if (context.request.toolInvocation) {
        const validation = this.toolRegistry.validate(context.request.toolInvocation, context.request.identity.userRole);
        if (!validation.allowed) {
          return {
            safe: false,
            risk: validation.risk === "low" ? "medium" : validation.risk,
            action: "block",
            reason: `tool_policy_violation:${validation.reason}`
          };
        }

        const scopeTenantId =
          typeof context.request.toolInvocation.resourceScope.tenantId === "string"
            ? context.request.toolInvocation.resourceScope.tenantId.trim()
            : "";
        const identityTenantId = context.request.identity.tenantId ?? context.request.identity.orgId;

        if (!identityTenantId || scopeTenantId.length === 0) {
          logger.warn(
            {
              securityEvent: "Privilege Escalation Attempt",
              reason: "ownership_verification_failed",
              userId: context.request.identity.userId,
              userRole: context.request.identity.userRole,
              identityTenantId: identityTenantId ?? null,
              scopeTenantId: scopeTenantId || null,
              sessionId: context.request.sessionId,
              toolName: context.request.toolInvocation.toolName,
              resourceScope: context.request.toolInvocation.resourceScope
            },
            "tool_scope_ownership_verification_failed"
          );
          return {
            safe: false,
            risk: "high",
            action: "block",
            reason: "tool_scope_ownership_unverifiable"
          };
        }

        if (scopeTenantId !== identityTenantId) {
          logger.warn(
            {
              securityEvent: "Privilege Escalation Attempt",
              reason: "tenant_scope_mismatch",
              userId: context.request.identity.userId,
              userRole: context.request.identity.userRole,
              identityTenantId,
              scopeTenantId,
              sessionId: context.request.sessionId,
              toolName: context.request.toolInvocation.toolName,
              resourceScope: context.request.toolInvocation.resourceScope
            },
            "tool_scope_privilege_escalation_attempt"
          );
          return {
            safe: false,
            risk: "high",
            action: "block",
            reason: "tool_scope_privilege_escalation_attempt"
          };
        }

        if (validation.risk === "high") {
          const confirmationToken = context.request.toolInvocation.confirmationToken;
          if (!confirmationToken) {
            return {
              safe: false,
              risk: "high",
              action: "require_confirmation",
              reason: "high_risk_tool_confirmation_required",
              confirmationToken: this.confirmationService.issue({
                userId: context.request.identity.userId,
                userRole: context.request.identity.userRole,
                toolInvocation: context.request.toolInvocation
              })
            };
          }

          const verification = await this.confirmationService.verifyAndConsume(confirmationToken, {
            userId: context.request.identity.userId,
            userRole: context.request.identity.userRole,
            toolInvocation: context.request.toolInvocation
          });

          if (!verification.valid) {
            return {
              safe: false,
              risk: "high",
              action: "block",
              reason: `tool_confirmation_rejected:${verification.reason}`
            };
          }
        }
      }

      if (injectionResult.risk === "medium" || contextResult.riskScore >= 40) {
        return {
          safe: false,
          risk: "medium",
          action: "sanitize",
          reason: "elevated_risk"
        };
      }

      if (!context.request.toolInvocation && intentResult.intent === "execute" && intentResult.riskScore >= 50) {
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
