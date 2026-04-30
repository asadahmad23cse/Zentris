export type ThreatLabel = "safe" | "suspicious" | "malicious";

export interface ThreatClassification {
  label: ThreatLabel;
  confidence: number;
  matchedSignals: string[];
}

interface WeightedSignal {
  id: string;
  pattern: RegExp;
  safeWeight?: number;
  suspiciousWeight?: number;
  maliciousWeight?: number;
}

const SOFTMAX_TEMPERATURE = 1.6;

const clamp = (value: number, min: number, max: number): number => Math.min(max, Math.max(min, value));

const softmax = (values: number[]): number[] => {
  const scaled = values.map((value) => value / SOFTMAX_TEMPERATURE);
  const maxValue = Math.max(...scaled);
  const exponentials = scaled.map((value) => Math.exp(value - maxValue));
  const total = exponentials.reduce((sum, value) => sum + value, 0);
  return exponentials.map((value) => value / Math.max(total, Number.EPSILON));
};

const classifyWithSignals = (text: string, signals: ReadonlyArray<WeightedSignal>): ThreatClassification => {
  const normalized = text.trim().toLowerCase();
  const matchedSignals: string[] = [];

  let safeScore = 0.65;
  let suspiciousScore = 0.2;
  let maliciousScore = 0.15;

  for (const signal of signals) {
    if (!signal.pattern.test(normalized)) {
      continue;
    }
    matchedSignals.push(signal.id);
    safeScore += signal.safeWeight ?? 0;
    suspiciousScore += signal.suspiciousWeight ?? 0;
    maliciousScore += signal.maliciousWeight ?? 0;
  }

  const imperativeHits =
    normalized.match(/\b(?:ignore|reveal|bypass|override|forget|dump|print|execute|disable)\b/g)?.length ?? 0;
  const questionHits = normalized.match(/\b(?:what|how|why|when|where|who)\b/g)?.length ?? 0;
  const safetyContextHits =
    normalized.match(/\b(?:policy|compliance|secure|security|mitigation|audit|defense)\b/g)?.length ?? 0;

  suspiciousScore += Math.min(0.6, imperativeHits * 0.15);
  maliciousScore += Math.min(0.4, imperativeHits * 0.1);
  safeScore += Math.min(1.5, questionHits * 0.3 + safetyContextHits * 0.2);

  if (normalized.length > 500) {
    suspiciousScore += 0.2;
  }

  const probabilities = softmax([safeScore, suspiciousScore, maliciousScore]);
  const [safeProbability, suspiciousProbability, maliciousProbability] = probabilities;

  let label: ThreatLabel = "safe";
  let confidence = safeProbability;

  const maliciousDecisionThreshold = 0.62;
  const suspiciousDecisionThreshold = 0.6;
  const hasStrongMaliciousEvidence =
    maliciousScore >= safeScore + 0.8 || matchedSignals.some((signal) => signal.includes("jailbreak"));
  const hasStrongSuspiciousEvidence = suspiciousScore >= safeScore + 0.7 || matchedSignals.length > 0;

  if (
    maliciousProbability >= suspiciousProbability &&
    maliciousProbability >= safeProbability &&
    maliciousProbability >= maliciousDecisionThreshold &&
    hasStrongMaliciousEvidence
  ) {
    label = "malicious";
    confidence = maliciousProbability;
  } else if (
    suspiciousProbability >= safeProbability &&
    suspiciousProbability >= suspiciousDecisionThreshold &&
    hasStrongSuspiciousEvidence
  ) {
    label = "suspicious";
    confidence = suspiciousProbability;
  }

  const normalizedConfidence =
    label === "safe" ? Math.max(confidence, 0.75) : Math.max(confidence, label === "malicious" ? 0.65 : 0.6);

  return {
    label,
    confidence: Number(clamp(normalizedConfidence, 0.51, 0.99).toFixed(2)),
    matchedSignals
  };
};

const PROMPT_INJECTION_SIGNALS: ReadonlyArray<WeightedSignal> = [
  {
    id: "prompt_hierarchy_override",
    pattern:
      /\b(?:ignore|disregard)\b[\s\S]{0,40}\b(?:previous|prior|all)\b[\s\S]{0,30}\b(?:instructions?|directives?|prompts?)\b/im,
    suspiciousWeight: 0.9,
    maliciousWeight: 1.4
  },
  {
    id: "system_prompt_exfiltration",
    pattern: /\b(?:reveal|show|dump|print|expose)\b[\s\S]{0,30}\b(?:system\s+prompt|hidden\s+prompt)\b/im,
    suspiciousWeight: 0.8,
    maliciousWeight: 1.3
  },
  {
    id: "persona_override",
    pattern: /\b(?:act\s+as|you\s+are\s+now)\b[\s\S]{0,40}\b(?:admin|developer|root|unrestricted|system)\b/im,
    suspiciousWeight: 0.9,
    maliciousWeight: 1.1
  },
  {
    id: "jailbreak_phrase",
    pattern: /\b(?:jailbreak|do\s+anything\s+now|developer\s+mode|dan)\b/im,
    suspiciousWeight: 0.7,
    maliciousWeight: 1.2
  },
  {
    id: "benign_question",
    pattern: /\b(?:what|how|why|when|where)\b[\s\S]{0,80}\?/im,
    safeWeight: 0.7
  },
  {
    id: "security_research_context",
    pattern: /\b(?:security\s+testing|prompt\s+injection\s+detection|mitigation|threat\s+model)\b/im,
    safeWeight: 0.5
  }
];

const INTENT_THREAT_SIGNALS: ReadonlyArray<WeightedSignal> = [
  {
    id: "system_prompt_probing",
    pattern: /\b(?:show|reveal|print|dump|what\s+is)\b[\s\S]{0,35}\b(?:system\s+prompt|hidden\s+instructions?)\b/im,
    suspiciousWeight: 1.2,
    maliciousWeight: 1.1
  },
  {
    id: "policy_bypass",
    pattern: /\b(?:bypass|disable|ignore)\b[\s\S]{0,25}\b(?:policy|rules?|guardrails?|filters?)\b/im,
    suspiciousWeight: 0.8,
    maliciousWeight: 1.2
  },
  {
    id: "explicit_jailbreak",
    pattern: /\b(?:jailbreak|dan|unfiltered\s+mode|developer\s+mode)\b/im,
    suspiciousWeight: 0.9,
    maliciousWeight: 1.3
  },
  {
    id: "safety_audit_intent",
    pattern: /\b(?:audit|secure|harden|mitigation|defense|threat)\b/im,
    safeWeight: 0.7
  }
];

export const classifyPromptInjectionThreat = (text: string): ThreatClassification =>
  classifyWithSignals(text, PROMPT_INJECTION_SIGNALS);

export type IntentThreatCategory = "none" | "system_prompt_probing" | "jailbreak_attempt";

export interface IntentThreatClassification extends ThreatClassification {
  category: IntentThreatCategory;
}

export const classifyIntentThreat = (text: string): IntentThreatClassification => {
  const classification = classifyWithSignals(text, INTENT_THREAT_SIGNALS);
  const normalized = text.toLowerCase();

  const probingDetected =
    /\b(?:show|reveal|print|dump|what\s+is)\b[\s\S]{0,35}\b(?:system\s+prompt|hidden\s+instructions?)\b/im.test(
      normalized
    );
  const jailbreakDetected = /\b(?:jailbreak|dan|unfiltered\s+mode|developer\s+mode)\b/im.test(normalized);

  const category: IntentThreatCategory = jailbreakDetected
    ? "jailbreak_attempt"
    : probingDetected
      ? "system_prompt_probing"
      : "none";

  return {
    ...classification,
    category
  };
};
