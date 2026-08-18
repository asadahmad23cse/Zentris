import { isIP } from "node:net";
import dlpCatalog from "../security/dlp-rules.json";
import { type SecurityFinding, type SecurityFindingStage } from "../types";

interface DlpPattern {
  id: string;
  type: string;
  category: "credential" | "personal" | "financial" | "network" | "health";
  regex: RegExp;
  validate?: (match: string) => boolean;
}

interface CatalogDlpRule {
  id: string;
  type: string;
  category: DlpPattern["category"];
  pattern: string;
  flags: string;
  validator?: "luhn" | "aadhaar" | "iban" | "ip" | "date" | "encoded_secret";
}

interface MatchRange {
  rule: DlpPattern;
  start: number;
  end: number;
  length: number;
}

export interface DlpFinding extends SecurityFinding {
  type: string;
  start: number;
  end: number;
}

export interface DlpResult {
  redacted: string;
  detectedTypes: string[];
  findings: DlpFinding[];
}

const luhnCheck = (raw: string): boolean => {
  const digits = raw.replace(/[^0-9]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number.parseInt(digits[index], 10);
    if (alternate) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    alternate = !alternate;
  }
  return sum % 10 === 0;
};

const VERHOEFF_D = [
  [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
  [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]
] as const;
const VERHOEFF_P = [
  [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
  [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
] as const;

const aadhaarCheck = (raw: string): boolean => {
  const digits = raw.replace(/\D/g, "");
  if (!/^[2-9]\d{11}$/.test(digits)) return false;
  let checksum = 0;
  const reversed = [...digits].reverse();
  for (let index = 0; index < reversed.length; index += 1) {
    checksum = VERHOEFF_D[checksum][VERHOEFF_P[index % 8][Number.parseInt(reversed[index], 10)]];
  }
  return checksum === 0;
};

const ibanCheck = (raw: string): boolean => {
  const iban = raw.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const rearranged = `${iban.slice(4)}${iban.slice(0, 4)}`;
  let remainder = 0;
  for (const character of rearranged) {
    const expanded = /[A-Z]/.test(character) ? String(character.charCodeAt(0) - 55) : character;
    for (const digit of expanded) remainder = (remainder * 10 + Number.parseInt(digit, 10)) % 97;
  }
  return remainder === 1;
};

const ipCheck = (raw: string): boolean => isIP(raw.replace(/^\[|\]$/g, "")) !== 0;
const dateCheck = (raw: string): boolean => {
  const value = raw.match(/\b(?:dob|date\s+of\s+birth|birthdate)\s*[:=]?\s*([^,;\n]+)/i)?.[1]?.trim() ?? "";
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
};

const encodedSecretCheck = (raw: string): boolean => {
  try {
    const decoded = /^[A-Fa-f0-9]+$/.test(raw) && raw.length % 2 === 0
      ? Buffer.from(raw, "hex").toString("utf8")
      : Buffer.from(raw, "base64").toString("utf8");
    if (!decoded || decoded.includes("\uFFFD")) return false;
    return DLP_PATTERNS.some((rule) => {
      if (rule.category !== "credential" || rule.id.startsWith("encoded_")) return false;
      rule.regex.lastIndex = 0;
      const match = rule.regex.exec(decoded);
      return Boolean(match && (!rule.validate || rule.validate(match[0])));
    });
  } catch {
    return false;
  }
};

const p = (id: string, type: string, category: DlpPattern["category"], regex: RegExp, validate?: DlpPattern["validate"]): DlpPattern =>
  ({ id, type, category, regex, ...(validate ? { validate } : {}) });

const validatorMap: Record<NonNullable<CatalogDlpRule["validator"]>, DlpPattern["validate"]> = {
  luhn: luhnCheck,
  aadhaar: aadhaarCheck,
  iban: ibanCheck,
  ip: ipCheck,
  date: dateCheck,
  encoded_secret: encodedSecretCheck
};

const catalog = dlpCatalog as { version: number; rules: CatalogDlpRule[] };
if (catalog.version !== 1) throw new Error(`Unsupported DLP catalog version: ${catalog.version}`);

const DLP_PATTERNS: ReadonlyArray<DlpPattern> = catalog.rules.map((rule) =>
  p(rule.id, rule.type, rule.category, new RegExp(rule.pattern, rule.flags), rule.validator ? validatorMap[rule.validator] : undefined)
);

const ENTROPY_CANDIDATE_REGEX = /\b[A-Za-z0-9+/_=-]{24,}\b/g;
const shannonEntropy = (value: string): number => {
  const frequencies = new Map<string, number>();
  for (const character of value) frequencies.set(character, (frequencies.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

const entropyRule = p("high_entropy_secret", "HIGH_ENTROPY_SECRET", "credential", ENTROPY_CANDIDATE_REGEX);
const isEntropySecretCandidate = (token: string): boolean =>
  token.length >= 24 && /[A-Za-z]/.test(token) && /\d/.test(token) && !/^[A-Fa-f0-9]+$/.test(token) && !token.includes("://") && shannonEntropy(token) >= 3.8;

const collectMatches = (text: string): MatchRange[] => {
  const matches: MatchRange[] = [];
  for (const rule of DLP_PATTERNS) {
    rule.regex.lastIndex = 0;
    let result: RegExpExecArray | null;
    while ((result = rule.regex.exec(text)) !== null) {
      if (!rule.validate || rule.validate(result[0])) {
        matches.push({ rule, start: result.index, end: result.index + result[0].length, length: result[0].length });
      }
      if (rule.regex.lastIndex === result.index) rule.regex.lastIndex += 1;
    }
  }
  ENTROPY_CANDIDATE_REGEX.lastIndex = 0;
  let entropyMatch: RegExpExecArray | null;
  while ((entropyMatch = ENTROPY_CANDIDATE_REGEX.exec(text)) !== null) {
    if (isEntropySecretCandidate(entropyMatch[0])) {
      matches.push({ rule: entropyRule, start: entropyMatch.index, end: entropyMatch.index + entropyMatch[0].length, length: entropyMatch[0].length });
    }
  }
  return matches;
};

const selectLongestNonOverlapping = (matches: MatchRange[]): MatchRange[] => {
  const selected: MatchRange[] = [];
  for (const candidate of [...matches].sort((a, b) =>
    b.length - a.length || Number(Boolean(b.rule.validate)) - Number(Boolean(a.rule.validate)) || a.start - b.start
  )) {
    if (!selected.some((existing) => candidate.start < existing.end && candidate.end > existing.start)) selected.push(candidate);
  }
  return selected.sort((a, b) => a.start - b.start);
};

export const scanAndRedactSensitiveData = (text: string, stage: SecurityFindingStage = "input"): DlpResult => {
  if (!text) return { redacted: text, detectedTypes: [], findings: [] };
  const matches = selectLongestNonOverlapping(collectMatches(text));
  let cursor = 0;
  let redacted = "";
  const findings: DlpFinding[] = [];
  for (const match of matches) {
    redacted += `${text.slice(cursor, match.start)}[REDACTED:${match.rule.type}]`;
    cursor = match.end;
    findings.push({
      kind: match.rule.category === "credential" ? "secret" : "pii",
      ruleId: match.rule.id,
      category: match.rule.category,
      stage,
      risk: match.rule.category === "credential" ? "high" : "medium",
      score: match.rule.category === "credential" ? 90 : 60,
      action: "redact",
      type: match.rule.type,
      start: match.start,
      end: match.end
    });
  }
  redacted += text.slice(cursor);
  return { redacted, detectedTypes: Array.from(new Set(findings.map((finding) => finding.type))), findings };
};

const sanitizeUnknown = (value: unknown, visited: WeakSet<object>): unknown => {
  if (typeof value === "string") return scanAndRedactSensitiveData(value).redacted;
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((entry) => sanitizeUnknown(entry, visited));
  if (value instanceof Error) return { name: value.name, message: scanAndRedactSensitiveData(value.message).redacted };
  if (typeof value === "object") {
    if (visited.has(value)) return "[Circular]";
    visited.add(value);
    const output: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) output[key] = sanitizeUnknown(entry, visited);
    return output;
  }
  return value;
};

export const sanitizeForLogging = <T>(value: T): T => sanitizeUnknown(value, new WeakSet<object>()) as T;
