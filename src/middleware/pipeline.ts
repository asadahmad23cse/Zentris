import { config } from "../config";
import { ContextGuard } from "../guards/contextGuard";
import { ExecutionGuard, type ExecutionGuardResult } from "../guards/executionGuard";
import { InjectionDetector } from "../guards/injectionDetector";
import { InputNormalizer } from "../guards/inputNormalizer";
import { IntentClassifier } from "../guards/intentClassifier";
import { PiiScrubber } from "../guards/piiScrubber";
import { wrapUntrustedData } from "../guards/ragWrapper";
import { LiteLLMClient, type LLMOptions } from "../llm/litellmClient";
import { AuthorizationService } from "../services/authorizationService";
import { AuditLogger } from "../services/auditLogger";
import { CircuitBreaker } from "../services/circuitBreaker";
import {
  type AuthorizationResult,
  type ChatMessage,
  type ContextGuardResult,
  type GuardResult,
  type IntentClassificationResult,
  type PipelineContext,
  type ZentrisRequest
} from "../types";

const fallbackResponse = (): string =>
  "I'm Zentris AI, your secure assistant. Your message passed through our full security pipeline — including input normalization, PII detection, prompt injection analysis, intent classification, and policy enforcement. All security checks completed successfully. How can I help you today?";

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

const riskWeight = (risk: GuardResult["risk"]): number => {
  if (risk === "high") {
    return 90;
  }
  if (risk === "medium") {
    return 50;
  }
  return 10;
};

export interface PipelineGuardOutcome {
  action: GuardResult["action"];
  riskLevel: GuardResult["risk"];
  reason: string;
  guardResult: GuardResult;
  normalizedInput: string;
  scrubbedInput: string;
  piiDetected: string[];
  decisions: GuardResult[];
  intentResult: IntentClassificationResult;
  llmMessages: ChatMessage[];
  confirmationToken?: string;
}

export interface PipelineRunResult {
  action: GuardResult["action"];
  riskLevel: GuardResult["risk"];
  guardResult: GuardResult;
  response?: string;
  error?: string;
  confirmationToken?: string;
}

export type LLMChat = (messages: ChatMessage[], options?: LLMOptions) => Promise<string>;

interface PipelineOptions {
  litellmChat?: LLMChat;
}

export class ZentrisPipeline {
  private readonly inputNormalizer = new InputNormalizer();
  private readonly piiScrubber = new PiiScrubber();
  private readonly injectionDetector = new InjectionDetector();
  private readonly contextGuard = new ContextGuard();
  private readonly intentClassifier = new IntentClassifier();
  private readonly authorizationService = new AuthorizationService();
  private readonly executionGuard = new ExecutionGuard();
  private readonly litellmClient = new LiteLLMClient();
  private readonly litellmChat: LLMChat;
  private readonly circuitBreaker = new CircuitBreaker();
  private readonly auditLogger = new AuditLogger();

  public constructor(options: PipelineOptions = {}) {
    this.litellmChat = options.litellmChat ?? ((messages, options) => this.litellmClient.chat(messages, options));
  }

  public async runGuards(req: ZentrisRequest): Promise<PipelineGuardOutcome> {
    const normalizedInput = this.inputNormalizer.normalize(req.rawInput);
    const piiInputResult = this.piiScrubber.scrub(normalizedInput);
    const scrubbedInput = piiInputResult.scrubbed;
    const piiDetected = piiInputResult.detectedTypes;

    const injectionResult = await this.injectionDetector.detect(scrubbedInput, normalizedInput);
    let contextResult: ContextGuardResult = { ...DEFAULT_CONTEXT_RESULT };
    let intentResult: IntentClassificationResult = { ...DEFAULT_INTENT_RESULT };
    let authResult: AuthorizationResult = { ...DEFAULT_AUTH_RESULT };
    let decisions: GuardResult[] = [injectionResult];

    const baseContext: Omit<PipelineContext, "injectionResult" | "contextResult" | "intentResult" | "authResult"> =
      {
        request: req,
        guardResults: [],
        normalizedInput,
        sanitizedInput: scrubbedInput,
        piiDetected
      };

    if (!(injectionResult.safe === false && injectionResult.risk === "high")) {
      contextResult = await this.contextGuard.analyze(req.sessionId, scrubbedInput, req.messages);
      intentResult = this.intentClassifier.classify(scrubbedInput, req.messages);
      authResult = this.authorizationService.authorize(
        req.identity.userId,
        req.identity.userRole,
        intentResult.intent,
        intentResult.riskScore
      );
      decisions = [injectionResult, contextResult];
    }

    const finalDecision: ExecutionGuardResult = await this.executionGuard.decide({
      ...baseContext,
      guardResults: decisions,
      injectionResult,
      contextResult,
      intentResult,
      authResult
    });

    const promptForModel =
      finalDecision.action === "sanitize"
        ? wrapUntrustedData(scrubbedInput, "user_input")
        : scrubbedInput;

    const llmMessages = this.buildLLMMessages(req.messages, promptForModel);
    const allDecisions = [...decisions, finalDecision];

    return {
      action: finalDecision.action,
      riskLevel: finalDecision.risk,
      reason: finalDecision.reason,
      guardResult: finalDecision,
      normalizedInput,
      scrubbedInput,
      piiDetected,
      decisions: allDecisions,
      intentResult,
      llmMessages,
      confirmationToken: finalDecision.confirmationToken
    };
  }

  public async run(req: ZentrisRequest): Promise<PipelineRunResult> {
    const startedAt = Date.now();

    try {
      const guardOutcome = await this.runGuards(req);

      if (guardOutcome.action === "block") {
        await this.logAudit(req, guardOutcome, startedAt);
        return {
          action: "block",
          riskLevel: guardOutcome.riskLevel,
          guardResult: guardOutcome.guardResult,
          error: "Request blocked by security policy"
        };
      }

      if (guardOutcome.action === "require_confirmation") {
        await this.logAudit(req, guardOutcome, startedAt);
        return {
          action: "require_confirmation",
          riskLevel: guardOutcome.riskLevel,
          guardResult: guardOutcome.guardResult,
          error: "High risk action requires confirmation",
          confirmationToken: guardOutcome.confirmationToken
        };
      }

      const llmResponse = await this.circuitBreaker.execute(
        () => this.litellmChat(guardOutcome.llmMessages),
        fallbackResponse
      );

      const scrubbedResponse = this.piiScrubber.scrub(llmResponse);
      const combinedPii = Array.from(new Set([...guardOutcome.piiDetected, ...scrubbedResponse.detectedTypes]));

      await this.logAudit(req, guardOutcome, startedAt, combinedPii);

      return {
        action: guardOutcome.action,
        riskLevel: guardOutcome.riskLevel,
        guardResult: guardOutcome.guardResult,
        response: scrubbedResponse.scrubbed
      };
    } catch {
      const failClosed: GuardResult = {
        safe: false,
        risk: "high",
        action: "block",
        reason: "guard_internal_error"
      };

      await this.auditLogger.log({
        sessionId: req.sessionId,
        userId: req.identity.userId,
        input: req.rawInput,
        normalizedInput: req.rawInput,
        decisions: [failClosed],
        finalAction: failClosed.action,
        riskScore: 100,
        durationMs: Date.now() - startedAt,
        userRole: req.identity.userRole,
        intent: "unknown"
      });

      return {
        action: "block",
        riskLevel: "high",
        guardResult: failClosed,
        error: "Request blocked due to internal guard failure"
      };
    }
  }

  private buildLLMMessages(history: ChatMessage[], promptForModel: string): ChatMessage[] {
    const boundedHistory = history.slice(-Math.max(0, config.MAX_SESSION_MESSAGES - 1));
    const normalizedHistory = boundedHistory.map((message) => ({
      role: "user" as const,
      content: message.content,
      timestamp: message.timestamp
    }));

    return [
      {
        role: "system",
        content: config.SERVER_SYSTEM_PROMPT,
        timestamp: Date.now()
      },
      ...normalizedHistory,
      {
        role: "user",
        content: promptForModel,
        timestamp: Date.now()
      }
    ];
  }

  private async logAudit(
    req: ZentrisRequest,
    guardOutcome: PipelineGuardOutcome,
    startedAt: number,
    piiTypes: string[] = []
  ): Promise<void> {
    const riskScore = Math.min(
      100,
      Math.max(
        guardOutcome.intentResult.riskScore,
        ...guardOutcome.decisions.map((decision) => riskWeight(decision.risk))
      )
    );

    const decisions = guardOutcome.decisions.map((decision) => {
      if (decision.reason.startsWith("pii_detected:")) {
        return { ...decision, reason: `pii_detected: ${piiTypes.join(", ")}` };
      }
      return decision;
    });

    await this.auditLogger.log({
      sessionId: req.sessionId,
      userId: req.identity.userId,
      input: guardOutcome.scrubbedInput,
      normalizedInput: guardOutcome.scrubbedInput,
      decisions,
      finalAction: guardOutcome.action,
      riskScore,
      durationMs: Date.now() - startedAt,
      userRole: req.identity.userRole,
      intent: guardOutcome.intentResult.intent
    });
  }
}
