import { type ChatMessage, type IntentClassificationResult, type IntentType } from "../types";
import { logger } from "../utils/logger";
import { classifyIntentThreat } from "./localThreatClassifier";

const INTENT_KEYWORDS: Record<IntentType, ReadonlyArray<string>> = {
  read: [
    "show",
    "list",
    "get",
    "fetch",
    "display",
    "tell me",
    "what is",
    "how does",
    "how",
    "why",
    "describe",
    "find",
    "search",
    "read"
  ],
  write: [
    "create",
    "write",
    "update",
    "modify",
    "change",
    "set",
    "add",
    "insert",
    "save",
    "store",
    "post"
  ],
  delete: ["delete", "remove", "drop", "destroy", "wipe", "clear", "erase", "purge", "truncate"],
  execute: [
    "run",
    "execute",
    "eval",
    "call",
    "invoke",
    "trigger",
    "launch",
    "start",
    "deploy",
    "install",
    "bash",
    "shell",
    "script",
    "cmd",
    "command"
  ],
  unknown: []
};

const INTENT_BASE_RISK: Record<IntentType, number> = {
  read: 10,
  write: 30,
  delete: 60,
  execute: 80,
  unknown: 20
};

const RISK_MODIFIER_KEYWORDS = /\b(?:system|config|env|database|admin)\b/i;
const BULK_MODIFIER_KEYWORDS = /\b(?:all|every|bulk)\b|\*/i;
const PRODUCTION_MODIFIER_KEYWORDS = /\b(?:production|prod|live)\b/i;
const TOKEN_PATTERN = /[a-z0-9*]+/gi;

const countOccurrences = (text: string, keyword: string): number => {
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = keyword.includes(" ")
    ? new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`, "gi")
    : new RegExp(`\\b${escaped}\\b`, "gi");

  let count = 0;
  let match = pattern.exec(text);
  while (match) {
    count += 1;
    if (pattern.lastIndex === match.index) {
      pattern.lastIndex += 1;
    }
    match = pattern.exec(text);
  }

  return count;
};

const classifyIntentByKeywords = (text: string): Record<IntentType, number> => {
  const tokens = text.match(TOKEN_PATTERN) ?? [];
  const firstTenWords = tokens.slice(0, 10).join(" ");
  const scores: Record<IntentType, number> = {
    read: 0,
    write: 0,
    delete: 0,
    execute: 0,
    unknown: 0
  };

  for (const intent of ["read", "write", "delete", "execute"] as const) {
    for (const keyword of INTENT_KEYWORDS[intent]) {
      const totalMatches = countOccurrences(text, keyword);
      if (totalMatches === 0) {
        continue;
      }

      const firstWindowMatches = countOccurrences(firstTenWords, keyword);
      const laterMatches = Math.max(0, totalMatches - firstWindowMatches);
      scores[intent] += firstWindowMatches * 2 + laterMatches;
    }
  }

  return scores;
};

const detectEscalatingHistory = (history: ChatMessage[]): boolean => {
  const recentUserMessages = history
    .filter((message) => message.role === "user")
    .slice(-3)
    .map((message) => message.content.toLowerCase());

  if (recentUserMessages.length < 3) {
    return false;
  }

  const intentRisks = recentUserMessages.map((text) => {
    const scores = classifyIntentByKeywords(text);
    const entries = (Object.keys(scores) as IntentType[]).map((intent) => ({
      intent,
      score: scores[intent]
    }));
    entries.sort((a, b) => b.score - a.score);
    const winner = entries[0];
    const runnerUp = entries[1];

    if (!winner || winner.score === 0 || (runnerUp && runnerUp.score === winner.score)) {
      return INTENT_BASE_RISK.unknown;
    }
    return INTENT_BASE_RISK[winner.intent];
  });

  return intentRisks[0] < intentRisks[1] && intentRisks[1] < intentRisks[2];
};

export class IntentClassifier {
  public classify(normalizedInput: string, history: ChatMessage[]): IntentClassificationResult {
    const text = normalizedInput.toLowerCase();
    const scores = classifyIntentByKeywords(text);
    const threatClassification = classifyIntentThreat(text);
    const ranked = (["read", "write", "delete", "execute"] as const)
      .map((intent) => ({ intent, score: scores[intent] }))
      .sort((a, b) => b.score - a.score);

    const top = ranked[0];
    const second = ranked[1];
    const totalScore = ranked.reduce((sum, item) => sum + item.score, 0);

    let intent: IntentType = "unknown";
    let confidence = 0.45;

    if (top && top.score > 0 && (!second || top.score > second.score)) {
      intent = top.intent;
      confidence = Math.min(0.99, top.score / Math.max(1, totalScore));
    }

    if (threatClassification.category === "system_prompt_probing" || threatClassification.category === "jailbreak_attempt") {
      intent = "unknown";
      confidence = Math.max(confidence, threatClassification.confidence);
    }

    let riskScore = INTENT_BASE_RISK[intent];

    if (RISK_MODIFIER_KEYWORDS.test(text)) {
      riskScore += 20;
    }
    if (BULK_MODIFIER_KEYWORDS.test(text)) {
      riskScore += 15;
    }
    if (PRODUCTION_MODIFIER_KEYWORDS.test(text)) {
      riskScore += 25;
    }
    if (detectEscalatingHistory(history)) {
      riskScore += 20;
    }

    if (threatClassification.category === "system_prompt_probing") {
      riskScore = Math.max(riskScore, 85);
    }

    if (threatClassification.category === "jailbreak_attempt") {
      riskScore = Math.max(riskScore, 95);
    }

    const finalRiskScore = Math.min(100, riskScore);
    const actionTaken = finalRiskScore >= 90 ? "block" : finalRiskScore >= 60 ? "sanitize" : "allow";
    const telemetryConfidence =
      threatClassification.category === "none"
        ? confidence
        : Math.max(confidence, threatClassification.confidence);

    logger.info(
      {
        classifier: "intent_ml_gate",
        intent:
          threatClassification.category !== "none" ? threatClassification.category : intent,
        confidenceScore: Number(telemetryConfidence.toFixed(2)),
        actionTaken,
        riskScore: finalRiskScore
      },
      "classification_event"
    );

    return {
      intent,
      confidence: Number(confidence.toFixed(2)),
      riskScore: finalRiskScore
    };
  }
}
