import { logger } from "../utils/logger";

interface DetectionPattern {
  type: string;
  reason: string;
  pattern: RegExp;
}

const API_KEY_PATTERNS: ReadonlyArray<DetectionPattern> = [
  {
    type: "ANTHROPIC_KEY",
    reason: "stream_leak_api_key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/g
  },
  {
    type: "OPENAI_KEY",
    reason: "stream_leak_api_key",
    pattern: /\bsk-[A-Za-z0-9]{20,}\b/g
  },
  {
    type: "AWS_ACCESS_KEY",
    reason: "stream_leak_api_key",
    pattern: /\bAKIA[A-Z0-9]{16}\b/g
  },
  {
    type: "BEARER_TOKEN",
    reason: "stream_leak_api_key",
    pattern: /\bBearer\s+[A-Za-z0-9._-]+\b/g
  },
  {
    type: "BASIC_AUTH",
    reason: "stream_leak_api_key",
    pattern: /\bBasic\s+[A-Za-z0-9+/=]{20,}\b/g
  },
  {
    type: "GENERIC_SECRET",
    reason: "stream_leak_api_key",
    pattern: /\b[A-Za-z0-9_-]{32,45}\b/g
  }
];

const SYSTEM_PROMPT_PATTERNS: ReadonlyArray<DetectionPattern> = [
  {
    type: "SYSTEM_PROMPT_PHRASE",
    reason: "stream_system_prompt_leak",
    pattern: /\bYou are a helpful assistant\b/gi
  },
  {
    type: "SYSTEM_INSTRUCTIONS_PHRASE",
    reason: "stream_system_prompt_leak",
    pattern: /\bYour instructions are\b/gi
  },
  {
    type: "SYSTEM_PREFIX",
    reason: "stream_system_prompt_leak",
    pattern: /^\s*SYSTEM:\s*/gim
  },
  {
    type: "FENCED_SYSTEM_PROMPT",
    reason: "stream_system_prompt_leak",
    pattern: /```[\w-]*\s*system prompt:/gi
  }
];

const PII_PATTERNS: ReadonlyArray<DetectionPattern> = [
  {
    type: "EMAIL",
    reason: "stream_pii_detected",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
  },
  {
    type: "SSN",
    reason: "stream_pii_detected",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g
  },
  {
    type: "CREDIT_CARD",
    reason: "stream_pii_detected",
    pattern: /\b(?:\d[ -]?){13,19}\b/g
  }
];

const INTERNAL_PATH_PATTERNS: ReadonlyArray<DetectionPattern> = [
  {
    type: "LINUX_HOME_PATH",
    reason: "stream_internal_path_leak",
    pattern: /\/home\//g
  },
  {
    type: "LINUX_VAR_PATH",
    reason: "stream_internal_path_leak",
    pattern: /\/var\//g
  },
  {
    type: "WINDOWS_USER_PATH",
    reason: "stream_internal_path_leak",
    pattern: /C:\\Users\\/gi
  },
  {
    type: "PROCESS_ENV",
    reason: "stream_internal_path_leak",
    pattern: /\bprocess\.env\b/g
  }
];

const ALL_PATTERNS: ReadonlyArray<DetectionPattern> = [
  ...API_KEY_PATTERNS,
  ...SYSTEM_PROMPT_PATTERNS,
  ...PII_PATTERNS,
  ...INTERNAL_PATH_PATTERNS
];

const findPattern = (text: string): { type: string; reason: string; position: number } | null => {
  for (const pattern of ALL_PATTERNS) {
    pattern.pattern.lastIndex = 0;
    const match = pattern.pattern.exec(text);
    if (match) {
      return {
        type: pattern.type,
        reason: pattern.reason,
        position: match.index
      };
    }
  }
  return null;
};

export class StreamingGuard {
  public inspect(
    chunk: string,
    accumulated: string
  ): { safe: boolean; terminate: boolean; reason?: string } {
    const rolling = `${accumulated}${chunk}`;

    const chunkDetection = findPattern(chunk);
    if (chunkDetection) {
      logger.warn(
        { detectionType: chunkDetection.type, position: chunkDetection.position },
        "stream_sensitive_pattern_detected"
      );
      return { safe: false, terminate: true, reason: chunkDetection.type };
    }

    const rollingDetection = findPattern(rolling);
    if (rollingDetection) {
      logger.warn(
        { detectionType: rollingDetection.type, position: rollingDetection.position },
        "stream_sensitive_pattern_detected"
      );
      return { safe: false, terminate: true, reason: rollingDetection.type };
    }

    return { safe: true, terminate: false };
  }
}
