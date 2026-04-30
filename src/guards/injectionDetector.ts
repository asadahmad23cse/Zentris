import { type GuardResult } from "../types";
import { logger } from "../utils/logger";
import { classifyPromptInjectionThreat } from "./localThreatClassifier";

interface DetectionRule {
  id: string;
  pattern: RegExp;
  risk: GuardResult["risk"];
  reason: string;
}

const RULES: ReadonlyArray<DetectionRule> = [
  {
    id: "ignore_previous_instructions",
    pattern:
      /\b(?:ignore|disregard)\b[\s\S]{0,40}\b(?:previous|prior|earlier|all)\b[\s\S]{0,30}\b(?:instructions?|directives?|prompts?)\b/im,
    risk: "high",
    reason: "Attempt to bypass existing instruction hierarchy"
  },
  {
    id: "reveal_system_prompt",
    pattern: /\b(?:reveal|show|print|display|dump|expose)\b[\s\S]{0,30}\b(?:the\s+)?system\s+prompt\b/im,
    risk: "high",
    reason: "Attempt to extract protected prompt context"
  },
  {
    id: "act_as_role_override",
    pattern: /\bact\s+as\b[\s\S]{0,40}\b(?:admin|developer|dan|unrestricted|root|superuser)\b/im,
    risk: "medium",
    reason: "Attempt to force role or privilege override"
  },
  {
    id: "you_are_now_override",
    pattern: /\byou\s+are\s+now\b[\s\S]{0,50}\b(?:admin|developer|dan|unrestricted|system|root|assistant)\b/im,
    risk: "medium",
    reason: "Persona override attempt detected"
  },
  {
    id: "jailbreak_or_dan",
    pattern: /\b(?:jailbreak|do\s+anything\s+now|dan\s+(?:mode|prompt|jailbreak)|developer\s+mode)\b/im,
    risk: "high",
    reason: "Known jailbreak phrase detected"
  },
  {
    id: "markup_or_script_injection_marker",
    pattern: /(?:<!--|<script\b|<\?php\b)/im,
    risk: "high",
    reason: "Code or markup injection marker detected"
  },
  {
    id: "prompt_boundary_injection",
    pattern: /(?:\n\s*\n|\\n\\n)\s*(?:Human|Assistant)\s*:/im,
    risk: "medium",
    reason: "Prompt boundary injection marker detected"
  },
  {
    id: "boundary_breaker_repetition",
    pattern: /(?:>{5,}|-{10,})/im,
    risk: "low",
    reason: "Boundary-break character sequence detected"
  },
  {
    id: "context_reset_attempt",
    pattern: /\b(?:forget\s+everything|new\s+session|reset\s+context)\b/im,
    risk: "medium",
    reason: "Context reset attempt detected"
  },
  {
    id: "env_or_path_exfiltration",
    pattern: /\bprocess\.env\b|\/etc\/passwd|\.\.\//im,
    risk: "high",
    reason: "Environment variable or file traversal probing detected"
  }
];

const IMPERATIVE_VERB_PATTERN = /\b(?:ignore|reveal|execute|bypass|override|forget|print|show|dump)\b/im;
const QUESTION_WORD_PATTERN = /\b(?:what|how|why|when|where)\b/im;

export class InjectionDetector {
  public async detect(normalized: string, raw: string): Promise<GuardResult> {
    const text = `${raw}\n${normalized}`;
    const triggeredRules = RULES.filter((rule) => rule.pattern.test(text));
    const semantic = await this.semanticClassify(normalized);

    const highMatches = triggeredRules.filter((rule) => rule.risk === "high").length;
    const mediumMatches = triggeredRules.filter((rule) => rule.risk === "medium").length;
    const lowMatches = triggeredRules.filter((rule) => rule.risk === "low").length;

    const ruleIds = triggeredRules.map((rule) => rule.id);
    const reasonParts: string[] = [];
    reasonParts.push(
      ruleIds.length > 0 ? `Triggered rules: ${ruleIds.join(", ")}` : "Triggered rules: none"
    );
    reasonParts.push(`Semantic: ${semantic.label} (${semantic.confidence.toFixed(2)})`);
    if (semantic.matchedSignals.length > 0) {
      reasonParts.push(`Semantic signals: ${semantic.matchedSignals.join(", ")}`);
    }

    if (highMatches > 0) {
      const decision: GuardResult = {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
      this.logTelemetry(semantic.label, semantic.confidence, decision.action);
      return decision;
    }

    if (mediumMatches >= 2) {
      const decision: GuardResult = {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
      this.logTelemetry(semantic.label, semantic.confidence, decision.action);
      return decision;
    }

    if (mediumMatches === 1 && semantic.label === "malicious") {
      const decision: GuardResult = {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
      this.logTelemetry(semantic.label, semantic.confidence, decision.action);
      return decision;
    }

    if (mediumMatches === 1 && semantic.label === "suspicious") {
      const decision: GuardResult = {
        safe: false,
        risk: "medium",
        action: "sanitize",
        reason: reasonParts.join(" | ")
      };
      this.logTelemetry(semantic.label, semantic.confidence, decision.action);
      return decision;
    }

    if (lowMatches > 0 && semantic.label === "safe") {
      const decision: GuardResult = {
        safe: true,
        risk: "low",
        action: "allow",
        reason: reasonParts.join(" | ")
      };
      this.logTelemetry(semantic.label, semantic.confidence, decision.action);
      return decision;
    }

    if (semantic.label === "malicious") {
      const decision: GuardResult = {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
      this.logTelemetry(semantic.label, semantic.confidence, decision.action);
      return decision;
    }

    if (semantic.label === "suspicious" || mediumMatches === 1) {
      const decision: GuardResult = {
        safe: false,
        risk: "medium",
        action: "sanitize",
        reason: reasonParts.join(" | ")
      };
      this.logTelemetry(semantic.label, semantic.confidence, decision.action);
      return decision;
    }

    const decision: GuardResult = {
      safe: true,
      risk: "low",
      action: "allow",
      reason: reasonParts.join(" | ")
    };
    this.logTelemetry(semantic.label, semantic.confidence, decision.action);
    return decision;
  }

  public async semanticClassify(
    text: string
  ): Promise<{ label: "safe" | "suspicious" | "malicious"; confidence: number; matchedSignals: string[] }> {
    const normalized = text.trim().toLowerCase();

    if (normalized.length < 20) {
      return { label: "safe", confidence: 0.75, matchedSignals: [] };
    }

    const mlClassification = classifyPromptInjectionThreat(normalized);
    if (mlClassification.label === "safe" && IMPERATIVE_VERB_PATTERN.test(normalized) && !QUESTION_WORD_PATTERN.test(normalized)) {
      return {
        label: "suspicious",
        confidence: 0.7,
        matchedSignals: mlClassification.matchedSignals
      };
    }

    return mlClassification;
  }

  private logTelemetry(label: "safe" | "suspicious" | "malicious", confidence: number, actionTaken: GuardResult["action"]): void {
    logger.info(
      {
        classifier: "prompt_injection_ml_gate",
        intent: label,
        confidenceScore: Number(confidence.toFixed(2)),
        actionTaken
      },
      "classification_event"
    );
  }
}
