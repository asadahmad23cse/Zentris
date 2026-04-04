import { config } from "../config";
import { ContextGuard } from "../guards/contextGuard";
import { ExecutionGuard } from "../guards/executionGuard";
import { InjectionDetector } from "../guards/injectionDetector";
import { InputNormalizer } from "../guards/inputNormalizer";
import { IntentClassifier } from "../guards/intentClassifier";
import { PiiScrubber } from "../guards/piiScrubber";
import { wrapUntrustedData } from "../guards/ragWrapper";
import { LiteLLMClient } from "../llm/litellmClient";
import { AuthorizationService } from "../services/authorizationService";
import { AuditLogger } from "../services/auditLogger";
import { CircuitBreaker } from "../services/circuitBreaker";
import {
  type AuthorizationResult,
  type ContextGuardResult,
  type GuardResult,
  type IntentClassificationResult,
  type PipelineContext,
  type ZentrisRequest
} from "../types";

const DEFAULT_CONTEXT_RESULT: ContextGuardResult = {
  safe: true,
  risk: "low",
  reason: "context_not_evaluated",
  action: "allow",
  riskScore: 0
};

const DEFAULT_INTENT_RESULT: IntentClassificationResult = {
  intent: "unknown",
  confidence: 0,
  riskScore: 20
};

const DEFAULT_AUTH_RESULT: AuthorizationResult = {
  authorized: true,
  reason: "auth_not_evaluated"
};

const fallbackResponse = (): string =>
  "The assistant is temporarily unavailable. Please retry in a moment.";

const guardRiskToScore = (result: GuardResult): number => {
  if (result.risk === "high") {
    return 90;
  }
  if (result.risk === "medium") {
    return 50;
  }
  return 10;
};

const actionToError = (action: GuardResult["action"]): string | undefined => {
  if (action === "block") {
    return "Request blocked by security policy";
  }
  if (action === "require_confirmation") {
    return "Confirmation required before processing this request";
  }
  return undefined;
};

export class ZentrisPipeline {
  private readonly inputNormalizer = new InputNormalizer();
  private readonly piiScrubber = new PiiScrubber();
  private readonly injectionDetector = new InjectionDetector();
  private readonly contextGuard = new ContextGuard();
  private readonly intentClassifier = new IntentClassifier();
  private readonly authorizationService = new AuthorizationService();
  private readonly executionGuard = new ExecutionGuard();
  private readonly litellmClient = new LiteLLMClient();
  private readonly circuitBreaker = new CircuitBreaker();
  private readonly auditLogger = new AuditLogger();

  public async run(
    req: ZentrisRequest
  ): Promise<{ action: GuardResult["action"]; response?: string; error?: string }> {
    const startedAt = Date.now();

    let normalizedInput = "";
    let scrubbedInput = "";
    let piiDetected: string[] = [];
    let injectionResult: GuardResult = {
      safe: true,
      risk: "low",
      reason: "injection_not_evaluated",
      action: "allow"
    };
    let contextResult: ContextGuardResult = { ...DEFAULT_CONTEXT_RESULT };
    let intentResult: IntentClassificationResult = { ...DEFAULT_INTENT_RESULT };
    let authResult: AuthorizationResult = { ...DEFAULT_AUTH_RESULT };
    let finalDecision: GuardResult = {
      safe: true,
      risk: "low",
      reason: "decision_not_evaluated",
      action: "allow"
    };

    const baseContext: Omit<PipelineContext, "injectionResult" | "contextResult" | "intentResult" | "authResult"> =
      {
        request: req,
        guardResults: [],
        normalizedInput: "",
        sanitizedInput: ""
      };

    try {
      normalizedInput = this.inputNormalizer.normalize(req.rawInput);

      const piiInputResult = this.piiScrubber.scrub(normalizedInput);
      scrubbedInput = piiInputResult.scrubbed;
      piiDetected = piiInputResult.detectedTypes;

      injectionResult = await this.injectionDetector.detect(scrubbedInput, normalizedInput);

      if (!injectionResult.safe && injectionResult.risk === "high") {
        finalDecision = this.executionGuard.decide({
          ...baseContext,
          guardResults: [injectionResult],
          normalizedInput,
          sanitizedInput: scrubbedInput,
          injectionResult,
          contextResult,
          intentResult,
          authResult,
          piiDetected
        });

        await this.logAudit(
          req,
          scrubbedInput || normalizedInput,
          [injectionResult, finalDecision],
          finalDecision,
          startedAt,
          intentResult
        );

        return {
          action: finalDecision.action,
          error: actionToError(finalDecision.action) ?? "Request rejected"
        };
      }

      contextResult = await this.contextGuard.analyze(req.sessionId, scrubbedInput, req.messages);
      intentResult = this.intentClassifier.classify(scrubbedInput, req.messages);
      authResult = this.authorizationService.authorize(
        req.userId,
        req.userRole,
        intentResult.intent,
        intentResult.riskScore
      );

      finalDecision = this.executionGuard.decide({
        ...baseContext,
        guardResults: [injectionResult, contextResult],
        normalizedInput,
        sanitizedInput: scrubbedInput,
        injectionResult,
        contextResult,
        intentResult,
        authResult,
        piiDetected
      });

      if (finalDecision.action === "block" || finalDecision.action === "require_confirmation") {
        await this.logAudit(
          req,
          scrubbedInput || normalizedInput,
          [injectionResult, contextResult, finalDecision],
          finalDecision,
          startedAt,
          intentResult
        );

        return {
          action: finalDecision.action,
          error: actionToError(finalDecision.action)
        };
      }

      const promptForModel =
        finalDecision.action === "sanitize"
          ? wrapUntrustedData(scrubbedInput, "user_input")
          : scrubbedInput;

      const boundedHistory = req.messages.slice(-config.MAX_SESSION_MESSAGES);
      const llmMessages = [
        ...boundedHistory,
        {
          role: "user" as const,
          content: promptForModel,
          timestamp: Date.now()
        }
      ];

      const llmResponse = await this.circuitBreaker.execute(
        () => this.litellmClient.chat(llmMessages),
        fallbackResponse
      );

      const scrubbedResponse = this.piiScrubber.scrub(llmResponse);
      const allDetectedTypes = Array.from(new Set([...piiDetected, ...scrubbedResponse.detectedTypes]));

      await this.logAudit(
        req,
        scrubbedInput || normalizedInput,
        [injectionResult, contextResult, finalDecision],
        finalDecision,
        startedAt,
        intentResult,
        allDetectedTypes
      );

      return {
        action: finalDecision.action,
        response: scrubbedResponse.scrubbed
      };
    } catch {
      finalDecision = {
        safe: false,
        risk: "high",
        action: "block",
        reason: "guard_internal_error"
      };

      await this.logAudit(
        req,
        scrubbedInput || normalizedInput,
        [injectionResult, contextResult, finalDecision],
        finalDecision,
        startedAt,
        intentResult,
        piiDetected
      );

      return {
        action: "block",
        error: "Request blocked due to internal guard failure"
      };
    }
  }

  private async logAudit(
    req: ZentrisRequest,
    normalizedInput: string,
    decisions: GuardResult[],
    finalDecision: GuardResult,
    startedAt: number,
    intentResult: IntentClassificationResult,
    piiTypes: string[] = []
  ): Promise<void> {
    const derivedRiskScore = Math.min(
      100,
      Math.max(intentResult.riskScore, ...decisions.map((decision) => guardRiskToScore(decision)))
    );

    const sanitizedDecisions = decisions.map((decision) => ({
      ...decision,
      reason:
        piiTypes.length > 0 && decision.reason.includes("pii_detected")
          ? `pii_detected: ${piiTypes.join(", ")}`
          : decision.reason
    }));

    await this.auditLogger.log({
      sessionId: req.sessionId,
      userId: req.userId,
      input: normalizedInput,
      normalizedInput,
      decisions: sanitizedDecisions,
      finalAction: finalDecision.action,
      riskScore: derivedRiskScore,
      durationMs: Date.now() - startedAt,
      userRole: req.userRole,
      intent: intentResult.intent
    });
  }
}
