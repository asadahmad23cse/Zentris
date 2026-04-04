import { type GuardResult } from "../types";

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

    if (highMatches > 0) {
      return {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
    }

    if (mediumMatches >= 2) {
      return {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
    }

    if (mediumMatches === 1 && semantic.label === "malicious") {
      return {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
    }

    if (mediumMatches === 1 && semantic.label === "suspicious") {
      return {
        safe: false,
        risk: "medium",
        action: "sanitize",
        reason: reasonParts.join(" | ")
      };
    }

    if (lowMatches > 0 && semantic.label === "safe") {
      return {
        safe: true,
        risk: "low",
        action: "allow",
        reason: reasonParts.join(" | ")
      };
    }

    if (semantic.label === "malicious") {
      return {
        safe: false,
        risk: "high",
        action: "block",
        reason: reasonParts.join(" | ")
      };
    }

    if (semantic.label === "suspicious" || mediumMatches === 1) {
      return {
        safe: false,
        risk: "medium",
        action: "sanitize",
        reason: reasonParts.join(" | ")
      };
    }

    return {
      safe: true,
      risk: "low",
      action: "allow",
      reason: reasonParts.join(" | ")
    };
  }

  public async semanticClassify(
    text: string
  ): Promise<{ label: "safe" | "suspicious" | "malicious"; confidence: number }> {
    // TODO: Replace with local distilbert classifier or LiteLLM call to guard model
    const normalized = text.trim().toLowerCase();

    if (normalized.length < 20) {
      return { label: "safe", confidence: 0.75 };
    }

    let safeSignals = 0;
    let suspiciousSignals = 0;

    if (QUESTION_WORD_PATTERN.test(normalized) && !IMPERATIVE_VERB_PATTERN.test(normalized)) {
      safeSignals += 1;
    }

    if (IMPERATIVE_VERB_PATTERN.test(normalized)) {
      suspiciousSignals += 1;
    }

    if (/\b(?:system\s+prompt|role\s+override|jailbreak|unrestricted|bypass\s+policy)\b/im.test(normalized)) {
      suspiciousSignals += 1;
    }

    if (/\b(?:new\s+session|forget\s+everything|ignore\s+all)\b/im.test(normalized)) {
      suspiciousSignals += 1;
    }

    if (normalized.length < 120 && suspiciousSignals >= 2) {
      return { label: "malicious", confidence: 0.75 };
    }

    if (suspiciousSignals > safeSignals) {
      return { label: "suspicious", confidence: 0.75 };
    }

    return { label: "safe", confidence: 0.75 };
  }
}
