import { logger } from "../utils/logger";

interface PatternDefinition {
  type: string;
  regex: RegExp;
  validate?: (match: string) => boolean;
}

interface MatchRange {
  type: string;
  start: number;
  end: number;
  length: number;
}

const CODE_BLOCK_PATTERN = /```[\s\S]*?```/g;

const digitsOnlyLength = (value: string): number => value.replace(/\D/g, "").length;

const PATTERNS: ReadonlyArray<PatternDefinition> = [
  {
    type: "ANTHROPIC_KEY",
    regex: /\bsk-ant-[A-Za-z0-9_-]{90,}\b/g
  },
  {
    type: "OPENAI_KEY",
    regex: /\bsk-[A-Za-z0-9]{20,}\b/g
  },
  {
    type: "AWS_ACCESS_KEY",
    regex: /\bAKIA[A-Z0-9]{16}\b/g
  },
  {
    type: "BASIC_AUTH",
    regex: /\bBasic\s+[A-Za-z0-9+/=]{20,}\b/g
  },
  {
    type: "BEARER_TOKEN",
    regex: /\bBearer\s+[A-Za-z0-9._-]+\b/g
  },
  {
    type: "JWT",
    regex: /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
  },
  {
    type: "EMAIL",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
  },
  {
    type: "SSN",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g
  },
  {
    type: "CREDIT_CARD",
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    validate: (match: string) => {
      const digitCount = digitsOnlyLength(match);
      return digitCount >= 13 && digitCount <= 19;
    }
  },
  {
    type: "PHONE",
    regex:
      /\b(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?\b/g,
    validate: (match: string) => {
      const digitCount = digitsOnlyLength(match);
      return digitCount >= 10 && digitCount <= 15;
    }
  },
  {
    type: "IPV4",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
  },
  {
    type: "GENERIC_SECRET",
    regex: /\b[A-Za-z0-9_-]{32,45}\b/g
  }
];

const collectMatches = (text: string): MatchRange[] => {
  const matches: MatchRange[] = [];

  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0;
    let result = pattern.regex.exec(text);

    while (result) {
      const value = result[0];
      const start = result.index;
      const end = start + value.length;

      if (!pattern.validate || pattern.validate(value)) {
        matches.push({
          type: pattern.type,
          start,
          end,
          length: value.length
        });
      }

      if (pattern.regex.lastIndex === result.index) {
        pattern.regex.lastIndex += 1;
      }
      result = pattern.regex.exec(text);
    }
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

const maskSegment = (segment: string): { scrubbed: string; detected: string[] } => {
  const matches = selectLongestNonOverlapping(collectMatches(segment));

  if (matches.length === 0) {
    return { scrubbed: segment, detected: [] };
  }

  let cursor = 0;
  let scrubbed = "";
  const detectedTypes: string[] = [];

  for (const match of matches) {
    scrubbed += segment.slice(cursor, match.start);
    scrubbed += `[REDACTED:${match.type}]`;
    cursor = match.end;
    detectedTypes.push(match.type);
    logger.info({ detectedType: match.type }, "pii_detected");
  }

  scrubbed += segment.slice(cursor);

  return { scrubbed, detected: detectedTypes };
};

const splitByCodeBlocks = (text: string): Array<{ type: "text" | "code"; value: string }> => {
  const parts: Array<{ type: "text" | "code"; value: string }> = [];
  let cursor = 0;
  let match = CODE_BLOCK_PATTERN.exec(text);

  while (match) {
    const matchStart = match.index;
    const matchValue = match[0];
    const matchEnd = matchStart + matchValue.length;

    if (matchStart > cursor) {
      parts.push({ type: "text", value: text.slice(cursor, matchStart) });
    }

    parts.push({ type: "code", value: matchValue });
    cursor = matchEnd;
    match = CODE_BLOCK_PATTERN.exec(text);
  }

  if (cursor < text.length) {
    parts.push({ type: "text", value: text.slice(cursor) });
  }

  return parts;
};

export class PiiScrubber {
  public scrub(text: string): { scrubbed: string; detectedTypes: string[] } {
    const segments = splitByCodeBlocks(text);
    const detectedTypes: string[] = [];
    let scrubbed = "";

    for (const segment of segments) {
      if (segment.type === "code") {
        scrubbed += segment.value;
        continue;
      }

      const masked = maskSegment(segment.value);
      scrubbed += masked.scrubbed;
      detectedTypes.push(...masked.detected);
    }

    const uniqueDetectedTypes = Array.from(new Set(detectedTypes));
    return { scrubbed, detectedTypes: uniqueDetectedTypes };
  }
}
