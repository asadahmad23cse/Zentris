interface DlpPattern {
  type: string;
  regex: RegExp;
}

interface MatchRange {
  type: string;
  start: number;
  end: number;
  length: number;
}

export interface DlpResult {
  redacted: string;
  detectedTypes: string[];
  findings: Array<{ type: string; start: number; end: number }>;
}

const DLP_PATTERNS: ReadonlyArray<DlpPattern> = [
  { type: "ANTHROPIC_KEY", regex: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/g },
  { type: "OPENAI_KEY", regex: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { type: "AWS_ACCESS_KEY", regex: /\bAKIA[A-Z0-9]{16}\b/g },
  { type: "JWT_TOKEN", regex: /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  {
    type: "PRIVATE_KEY",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g
  },
  {
    type: "DATABASE_URL",
    regex: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|oracle):\/\/[^\s'"`]+/gi
  },
  { type: "BASIC_AUTH", regex: /\bBasic\s+[A-Za-z0-9+/=]{20,}\b/g },
  { type: "BEARER_TOKEN", regex: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/g },
  {
    type: "GENERIC_ASSIGNMENT_SECRET",
    regex: /\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*["']?[A-Za-z0-9+/_=-]{16,}["']?/gi
  },
  { type: "EMAIL", regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "SSN", regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: "CREDIT_CARD", regex: /\b(?:\d[ -]?){13,19}\b/g }
];

const ENTROPY_CANDIDATE_REGEX = /\b[A-Za-z0-9+/_=-]{24,}\b/g;

const shannonEntropy = (value: string): number => {
  const frequencies = new Map<string, number>();
  for (const char of value) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

const isEntropySecretCandidate = (token: string): boolean => {
  if (token.length < 24) {
    return false;
  }
  if (!/[A-Za-z]/.test(token) || !/\d/.test(token)) {
    return false;
  }
  if (/^[A-Fa-f0-9]+$/.test(token)) {
    return false;
  }
  if (token.startsWith("http") || token.includes("://")) {
    return false;
  }
  const entropy = shannonEntropy(token);
  return entropy >= 3.6;
};

const collectPatternMatches = (text: string): MatchRange[] => {
  const matches: MatchRange[] = [];

  for (const pattern of DLP_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let result = pattern.regex.exec(text);

    while (result) {
      const value = result[0];
      const start = result.index;
      const end = start + value.length;

      matches.push({
        type: pattern.type,
        start,
        end,
        length: value.length
      });

      if (pattern.regex.lastIndex === result.index) {
        pattern.regex.lastIndex += 1;
      }
      result = pattern.regex.exec(text);
    }
  }

  return matches;
};

const collectEntropyMatches = (text: string): MatchRange[] => {
  const matches: MatchRange[] = [];
  ENTROPY_CANDIDATE_REGEX.lastIndex = 0;
  let result = ENTROPY_CANDIDATE_REGEX.exec(text);

  while (result) {
    const value = result[0];
    const start = result.index;
    const end = start + value.length;

    if (isEntropySecretCandidate(value)) {
      matches.push({
        type: "HIGH_ENTROPY_SECRET",
        start,
        end,
        length: value.length
      });
    }

    if (ENTROPY_CANDIDATE_REGEX.lastIndex === result.index) {
      ENTROPY_CANDIDATE_REGEX.lastIndex += 1;
    }
    result = ENTROPY_CANDIDATE_REGEX.exec(text);
  }

  return matches;
};

const selectLongestNonOverlapping = (matches: MatchRange[]): MatchRange[] => {
  const byLongestFirst = [...matches].sort((a, b) => {
    if (b.length !== a.length) {
      return b.length - a.length;
    }
    return a.start - b.start;
  });

  const selected: MatchRange[] = [];
  for (const candidate of byLongestFirst) {
    const hasOverlap = selected.some(
      (existing) => candidate.start < existing.end && candidate.end > existing.start
    );
    if (!hasOverlap) {
      selected.push(candidate);
    }
  }

  return selected.sort((a, b) => a.start - b.start);
};

export const scanAndRedactSensitiveData = (text: string): DlpResult => {
  if (!text || text.length === 0) {
    return { redacted: text, detectedTypes: [], findings: [] };
  }

  const matches = selectLongestNonOverlapping([
    ...collectPatternMatches(text),
    ...collectEntropyMatches(text)
  ]);

  if (matches.length === 0) {
    return { redacted: text, detectedTypes: [], findings: [] };
  }

  let cursor = 0;
  let redacted = "";
  const detectedTypes: string[] = [];
  const findings: Array<{ type: string; start: number; end: number }> = [];

  for (const match of matches) {
    redacted += text.slice(cursor, match.start);
    redacted += `[REDACTED:${match.type}]`;
    cursor = match.end;
    detectedTypes.push(match.type);
    findings.push({ type: match.type, start: match.start, end: match.end });
  }

  redacted += text.slice(cursor);

  return {
    redacted,
    detectedTypes: Array.from(new Set(detectedTypes)),
    findings
  };
};

const sanitizeUnknown = (value: unknown, visited: WeakSet<object>): unknown => {
  if (typeof value === "string") {
    return scanAndRedactSensitiveData(value).redacted;
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeUnknown(entry, visited));
  }

  if (value instanceof Error) {
    const safeMessage = scanAndRedactSensitiveData(value.message).redacted;
    return {
      name: value.name,
      message: safeMessage
    };
  }

  if (typeof value === "object") {
    if (visited.has(value)) {
      return "[Circular]";
    }
    visited.add(value);

    const output: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      output[key] = sanitizeUnknown(entry, visited);
    }
    return output;
  }

  return value;
};

export const sanitizeForLogging = <T>(value: T): T => sanitizeUnknown(value, new WeakSet<object>()) as T;
