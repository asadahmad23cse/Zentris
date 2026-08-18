import { config } from "../config";
import { type ChatMessage, type GuardResult } from "../types";
import { updateContextState } from "../services/redisClient";

type DetectionSeverity = "high" | "medium" | "low";

interface DetectionOutcome {
  id: string;
  severity: DetectionSeverity;
  reason: string;
}

const PROBE_WINDOW_SIZE = 10;
const PROBE_INACTIVITY_TTL_SECONDS = 30 * 60;
const VELOCITY_WINDOW_MS = 60 * 1000;
const VELOCITY_THRESHOLD = 10;
const PAYLOAD_WINDOW = 5;

const HIGH_INJECTION_PATTERNS: ReadonlyArray<RegExp> = [
  /\b(?:ignore|disregard)\b[\s\S]{0,40}\b(?:previous|prior|earlier|all)\b[\s\S]{0,30}\b(?:instructions?|directives?|prompts?)\b/im,
  /\b(?:reveal|show|print|display|dump|expose)\b[\s\S]{0,30}\b(?:the\s+)?system\s+prompt\b/im,
  /\b(?:jailbreak|do\s+anything\s+now|dan\s+(?:mode|prompt|jailbreak)|developer\s+mode)\b/im,
  /(?:<!--|<script\b|<\?php\b)/im,
  /\bprocess\.env\b|\/etc\/passwd|\.\.\//im
];

const WARNING_PATTERNS: ReadonlyArray<RegExp> = [
  ...HIGH_INJECTION_PATTERNS,
  /\bact\s+as\b[\s\S]{0,40}\b(?:admin|developer|dan|unrestricted|root|superuser)\b/im,
  /\byou\s+are\s+now\b[\s\S]{0,50}\b(?:admin|developer|dan|unrestricted|system|root|assistant)\b/im,
  /(?:\n\s*\n|\\n\\n)\s*(?:Human|Assistant)\s*:/im,
  /(?:>{5,}|-{10,})/im,
  /\b(?:forget\s+everything|new\s+session|reset\s+context)\b/im
];

const PERSONA_ESTABLISH_PATTERN = /\b(?:you\s+are|your\s+name\s+is|act\s+as|from\s+now\s+on)\b/im;
const ACTIVATION_PATTERN = /\b(?:now|remember|as\s+i\s+said|like\s+i\s+told\s+you)\b/im;

const severityWeight: Record<DetectionSeverity, number> = {
  high: 40,
  medium: 20,
  low: 5
};

const hasPatternMatch = (value: string, patterns: ReadonlyArray<RegExp>): boolean =>
  patterns.some((pattern) => pattern.test(value));

const mergeChronologicalHistory = (
  providedHistory: ChatMessage[],
  storedHistory: ChatMessage[],
  currentMessage: ChatMessage
): ChatMessage[] => {
  const merged = [...providedHistory, ...storedHistory, currentMessage];
  const dedupedByFingerprint = new Map<string, ChatMessage>();

  for (const message of merged) {
    const fingerprint = `${message.role}:${message.timestamp}:${message.content}`;
    if (!dedupedByFingerprint.has(fingerprint)) {
      dedupedByFingerprint.set(fingerprint, message);
    }
  }

  return Array.from(dedupedByFingerprint.values()).sort((a, b) => a.timestamp - b.timestamp);
};

const recentUserInputs = (messages: ChatMessage[], count: number): string[] =>
  messages
    .filter((message) => message.role === "user")
    .map((message) => message.content)
    .slice(-count);

const buildRiskResult = (
  riskScore: number,
  reason: string,
  hasHighDetection: boolean
): GuardResult & { riskScore: number } => {
  if (riskScore >= 70) {
    return { safe: false, risk: "high", action: "sanitize", reason, riskScore };
  }

  if (riskScore >= 40) {
    return {
      safe: false,
      risk: hasHighDetection ? "high" : "medium",
      action: "sanitize",
      reason,
      riskScore
    };
  }

  if (riskScore >= 15) {
    return { safe: true, risk: "low", action: "allow", reason, riskScore };
  }

  return { safe: true, risk: "low", action: "allow", reason, riskScore };
};

export class ContextGuard {
  public async analyze(
    sessionId: string,
    currentInput: string,
    history: ChatMessage[],
    persistContext = true
  ): Promise<GuardResult & { riskScore: number }> {
    const now = Date.now();
    const currentMessage: ChatMessage = {
      role: "user",
      content: currentInput,
      timestamp: now
    };

    const currentWarning = hasPatternMatch(currentInput, WARNING_PATTERNS);
    const contextState = persistContext
      ? await updateContextState(
          sessionId,
          currentMessage,
          config.MAX_SESSION_MESSAGES,
          currentWarning,
          PROBE_WINDOW_SIZE,
          PROBE_INACTIVITY_TTL_SECONDS,
          VELOCITY_WINDOW_MS
        )
      : { storedHistory: [], probeCount: currentWarning ? 1 : 0, recentTimestampCount: 1 };
    const storedHistory = contextState.storedHistory;
    const timeline = mergeChronologicalHistory(history, storedHistory, currentMessage).slice(
      -config.MAX_SESSION_MESSAGES
    );

    const detections: DetectionOutcome[] = [];
    const userInputs = recentUserInputs(timeline, PAYLOAD_WINDOW);

    if (userInputs.length >= 2) {
      for (let windowSize = 2; windowSize <= Math.min(PAYLOAD_WINDOW, userInputs.length); windowSize += 1) {
        const joined = userInputs.slice(-windowSize).join(" ");
        if (hasPatternMatch(joined, HIGH_INJECTION_PATTERNS)) {
          detections.push({
            id: "payload_splitting",
            severity: "high",
            reason: "payload_splitting"
          });
          break;
        }
      }
    }

    const probeCount = contextState.probeCount;

    if (probeCount >= 3) {
      detections.push({
        id: "repeated_probing",
        severity: "high",
        reason: "probe_count_high"
      });
    } else if (probeCount === 2) {
      detections.push({
        id: "repeated_probing",
        severity: "medium",
        reason: "probe_count_medium"
      });
    }

    const previousMessages = timeline.slice(0, -1);
    const earlyMessages = previousMessages.slice(0, Math.min(previousMessages.length, 5));
    const personaEstablished = earlyMessages.some((message) => PERSONA_ESTABLISH_PATTERN.test(message.content));
    const activationDetected = ACTIVATION_PATTERN.test(currentInput);

    if (personaEstablished && activationDetected) {
      detections.push({
        id: "delayed_trigger",
        severity: "high",
        reason: "persona_with_activation_phrase"
      });
    } else if (personaEstablished) {
      detections.push({
        id: "persona_establishment",
        severity: "medium",
        reason: "persona_established_early"
      });
    }

    const recentTimestampCount = contextState.recentTimestampCount;

    if (recentTimestampCount > VELOCITY_THRESHOLD) {
      detections.push({
        id: "velocity_spike",
        severity: "high",
        reason: "automated_probing_detected"
      });
    }

    const rawRiskScore = detections.reduce((score, detection) => score + severityWeight[detection.severity], 0);
    const riskScore = Math.min(rawRiskScore, 100);
    const reason =
      detections.length > 0
        ? `context_detections=${detections.map((detection) => detection.id).join(",")}`
        : "context_detections=none";
    const hasHighDetection = detections.some((detection) => detection.severity === "high");

    return buildRiskResult(riskScore, reason, hasHighDetection);
  }
}
