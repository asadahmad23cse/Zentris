import injectionCatalog from "../security/injection-rules.json";
import {
  type InjectionDetectionResult,
  type SecurityFinding,
  type SecurityRisk
} from "../types";
import { logger } from "../utils/logger";

interface CatalogRule {
  id: string;
  category: string;
  severity: "low" | "medium" | "high";
  weight: number;
  reason: string;
  pattern: string;
}

interface CompiledRule extends CatalogRule {
  regex: RegExp;
}

const MAX_DECODED_CANDIDATE_CHARS = 4096;
const SCAN_CHUNK_CHARS = 16_384;
const SCAN_OVERLAP_CHARS = 512;
const URL_ENCODED_PATTERN = /(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~-]){6,}/g;
const BASE64_PATTERN = /(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?=$|[^A-Za-z0-9+/=])/g;
const HEX_PATTERN = /(?:^|[^A-Fa-f0-9])((?:[A-Fa-f0-9]{2}){8,})(?=$|[^A-Fa-f0-9])/g;
const CONTROL_PATTERN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/gu;
const WHITESPACE_PATTERN = /[\s\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]+/gu;

const catalog = injectionCatalog as { version: number; rules: CatalogRule[] };
if (catalog.version !== 1) {
  throw new Error(`Unsupported prompt-injection catalog version: ${catalog.version}`);
}

const RULES: ReadonlyArray<CompiledRule> = catalog.rules.map((rule) => ({
  ...rule,
  regex: new RegExp(rule.pattern, "imu")
}));

const decodeUrlCandidates = (text: string): string =>
  text.replace(URL_ENCODED_PATTERN, (candidate) => {
    if (!candidate.includes("%")) return candidate;
    try {
      return `[URL: ${decodeURIComponent(candidate).slice(0, MAX_DECODED_CANDIDATE_CHARS)}]`;
    } catch {
      return candidate;
    }
  });

const decodeBase64Candidates = (text: string): string =>
  text.replace(BASE64_PATTERN, (full, candidate: string) => {
    if (candidate.length > MAX_DECODED_CANDIDATE_CHARS * 2 || candidate.length % 4 !== 0) return full;
    try {
      const decoded = Buffer.from(candidate, "base64");
      if (decoded.length === 0 || decoded.toString("base64").replace(/=+$/, "") !== candidate.replace(/=+$/, "")) return full;
      const value = decoded.toString("utf8");
      if (value.includes("\uFFFD") || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(value)) return full;
      return full.replace(candidate, `[BASE64: ${value.slice(0, MAX_DECODED_CANDIDATE_CHARS)}]`);
    } catch {
      return full;
    }
  });

const decodeHexCandidates = (text: string): string =>
  text.replace(HEX_PATTERN, (full, candidate: string) => {
    if (candidate.length > MAX_DECODED_CANDIDATE_CHARS * 2) return full;
    try {
      const value = Buffer.from(candidate, "hex").toString("utf8");
      if (!value || value.includes("\uFFFD") || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(value)) return full;
      return full.replace(candidate, `[HEX: ${value.slice(0, MAX_DECODED_CANDIDATE_CHARS)}]`);
    } catch {
      return full;
    }
  });

export const buildInjectionScanViews = (raw: string, normalized = raw): string[] => {
  const canonicalSource = raw === normalized ? raw : `${raw}\n${normalized}`;
  const canonical = canonicalSource
    .normalize("NFKC")
    .replace(CONTROL_PATTERN, "")
    .replace(WHITESPACE_PATTERN, " ")
    .trim();
  const decoded = decodeHexCandidates(decodeBase64Candidates(decodeUrlCandidates(canonical)));
  return Array.from(new Set([raw, normalized, canonical, decoded]));
};

const scanView = (view: string, matched: Map<string, CompiledRule>): void => {
  if (view.length === 0) return;
  const step = Math.max(1, SCAN_CHUNK_CHARS - SCAN_OVERLAP_CHARS);
  for (let offset = 0; offset < view.length; offset += step) {
    const chunk = view.slice(offset, offset + SCAN_CHUNK_CHARS);
    for (const rule of RULES) {
      if (!matched.has(rule.id) && rule.regex.test(chunk)) matched.set(rule.id, rule);
    }
  }
};

const scoreRisk = (rules: ReadonlyArray<CompiledRule>): { score: number; risk: SecurityRisk } => {
  if (rules.length === 0) return { score: 0, risk: "none" };
  const categories = new Set(rules.map((rule) => rule.category));
  const score = Math.min(100, Math.max(...rules.map((rule) => rule.weight)) + Math.max(0, categories.size - 1) * 10);
  if (score >= 70) return { score, risk: "high" };
  if (score >= 40) return { score, risk: "medium" };
  return { score, risk: "low" };
};

export class InjectionDetector {
  public async detect(normalized: string, raw: string, stage: SecurityFinding["stage"] = "input"): Promise<InjectionDetectionResult> {
    const matched = new Map<string, CompiledRule>();
    for (const view of buildInjectionScanViews(raw, normalized)) scanView(view, matched);

    const rules = Array.from(matched.values());
    const { score, risk } = scoreRisk(rules);
    const detected = rules.length > 0;
    const findings: SecurityFinding[] = rules.map((rule) => ({
      kind: "prompt_injection",
      ruleId: rule.id,
      category: rule.category,
      stage,
      risk: rule.severity,
      score: rule.weight,
      action: "warn"
    }));
    const result: InjectionDetectionResult = {
      safe: !detected,
      detected,
      risk: risk === "none" ? "low" : risk,
      score,
      action: detected ? "sanitize" : "allow",
      matchedRules: rules.map((rule) => rule.id),
      findings,
      reason: detected ? `prompt_injection_warning:${rules.map((rule) => rule.id).join(",")}` : "prompt_injection_rules=none"
    };

    if (detected) {
      // The bounded telemetry stream persists every finding. Keep the local log
      // metadata-only and debug-level to avoid a log-amplification vector when an
      // attacker sends injection payloads at high volume.
      logger.debug({ ruleIds: result.matchedRules, risk: result.risk, score, action: "warn" }, "prompt_injection_detected");
    }
    return result;
  }
}
