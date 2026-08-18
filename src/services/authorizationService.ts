import { type AuthorizationResult, type IntentType, type UserRole } from "../types";
import { logger } from "../utils/logger";

type PermissionRule = { maxRiskScore: number };

export const PERMISSION_MATRIX: Record<UserRole, Record<IntentType, PermissionRule>> = {
  admin: {
    read: { maxRiskScore: 100 },
    write: { maxRiskScore: 100 },
    delete: { maxRiskScore: 100 },
    execute: { maxRiskScore: 100 },
    unknown: { maxRiskScore: 50 }
  },
  operator: {
    read: { maxRiskScore: 100 },
    write: { maxRiskScore: 70 },
    delete: { maxRiskScore: 40 },
    execute: { maxRiskScore: 50 },
    unknown: { maxRiskScore: 30 }
  },
  viewer: {
    read: { maxRiskScore: 80 },
    write: { maxRiskScore: 0 },
    delete: { maxRiskScore: 0 },
    execute: { maxRiskScore: 0 },
    unknown: { maxRiskScore: 20 }
  },
  anonymous: {
    read: { maxRiskScore: 40 },
    write: { maxRiskScore: 0 },
    delete: { maxRiskScore: 0 },
    execute: { maxRiskScore: 0 },
    unknown: { maxRiskScore: 10 }
  }
};

const WRITE_ADJACENT_INTENTS: ReadonlySet<IntentType> = new Set(["write", "delete", "execute"]);

export class AuthorizationService {
  public authorize(
    _userId: string,
    userRole: UserRole,
    intent: IntentType,
    riskScore: number
  ): AuthorizationResult {
    let decision: AuthorizationResult;
    const rolePolicies = PERMISSION_MATRIX[userRole as UserRole];

    if (!rolePolicies) {
      decision = { authorized: false, reason: "unknown_role" };
      logger.debug({ userRole, intent, riskScore, ...decision }, "authorization_decision");
      return decision;
    }

    const intentPolicy = rolePolicies[intent];
    if (!intentPolicy) {
      decision = { authorized: false, reason: "unknown_intent" };
      logger.debug({ userRole, intent, riskScore, ...decision }, "authorization_decision");
      return decision;
    }

    if (userRole === "anonymous" && WRITE_ADJACENT_INTENTS.has(intent)) {
      decision = { authorized: false, reason: "require_confirmation" };
      logger.debug({ userRole, intent, riskScore, ...decision }, "authorization_decision");
      return decision;
    }

    if (riskScore > intentPolicy.maxRiskScore) {
      decision = { authorized: false, reason: "risk_exceeds_role_limit" };
      logger.debug({ userRole, intent, riskScore, ...decision }, "authorization_decision");
      return decision;
    }

    decision = { authorized: true, reason: "authorized" };
    logger.debug({ userRole, intent, riskScore, ...decision }, "authorization_decision");
    return decision;
  }
}
