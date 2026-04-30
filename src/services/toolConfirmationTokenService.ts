import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { config } from "../config";
import { type ToolInvocation, type UserRole } from "../types";

interface ConfirmationTokenHeader {
  alg: "HS256";
  typ: "TOOLCONF";
}

interface ConfirmationTokenPayload {
  sub: string;
  role: UserRole;
  tool: string;
  argsDigest: string;
  scopeDigest: string;
  iat: number;
  exp: number;
}

interface TokenValidationContext {
  userId: string;
  userRole: UserRole;
  toolInvocation: ToolInvocation;
}

const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/;

const base64UrlEncode = (value: string): string =>
  Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const base64UrlDecode = (value: string): string =>
  Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");

const stableStringify = (value: unknown): string => {
  if (value === null || value === undefined) {
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  const content = entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`).join(",");
  return `{${content}}`;
};

const sha256Hex = (value: string): string => createHash("sha256").update(value).digest("hex");

const computeInvocationDigests = (
  invocation: Pick<ToolInvocation, "arguments" | "resourceScope">
): { argsDigest: string; scopeDigest: string } => {
  return {
    argsDigest: sha256Hex(stableStringify(invocation.arguments)),
    scopeDigest: sha256Hex(stableStringify(invocation.resourceScope))
  };
};

const parseJson = <T>(encoded: string): T | null => {
  try {
    return JSON.parse(base64UrlDecode(encoded)) as T;
  } catch {
    return null;
  }
};

export class ToolConfirmationTokenService {
  public issue(context: TokenValidationContext): string {
    const now = Math.floor(Date.now() / 1000);
    const digests = computeInvocationDigests(context.toolInvocation);

    const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "TOOLCONF" } as ConfirmationTokenHeader));
    const payload = base64UrlEncode(
      JSON.stringify({
        sub: context.userId,
        role: context.userRole,
        tool: context.toolInvocation.toolName,
        argsDigest: digests.argsDigest,
        scopeDigest: digests.scopeDigest,
        iat: now,
        exp: now + config.CONFIRMATION_TOKEN_TTL_SECONDS
      } as ConfirmationTokenPayload)
    );
    const signature = createHmac("sha256", config.CONFIRMATION_TOKEN_SECRET)
      .update(`${header}.${payload}`)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    return `${header}.${payload}.${signature}`;
  }

  public verify(token: string, context: TokenValidationContext): { valid: boolean; reason: string } {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return { valid: false, reason: "tool_confirmation_token_format_invalid" };
    }

    const [headerSegment, payloadSegment, signatureSegment] = parts;
    if (!headerSegment || !payloadSegment || !signatureSegment) {
      return { valid: false, reason: "tool_confirmation_token_format_invalid" };
    }

    if (
      !BASE64_URL_PATTERN.test(headerSegment) ||
      !BASE64_URL_PATTERN.test(payloadSegment) ||
      !BASE64_URL_PATTERN.test(signatureSegment)
    ) {
      return { valid: false, reason: "tool_confirmation_token_encoding_invalid" };
    }

    const header = parseJson<ConfirmationTokenHeader>(headerSegment);
    const payload = parseJson<ConfirmationTokenPayload>(payloadSegment);
    if (!header || header.alg !== "HS256" || header.typ !== "TOOLCONF" || !payload) {
      return { valid: false, reason: "tool_confirmation_token_payload_invalid" };
    }

    const expectedSignature = createHmac("sha256", config.CONFIRMATION_TOKEN_SECRET)
      .update(`${headerSegment}.${payloadSegment}`)
      .digest();
    const actualSignature = Buffer.from(signatureSegment.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    if (
      actualSignature.length !== expectedSignature.length ||
      !timingSafeEqual(actualSignature, expectedSignature)
    ) {
      return { valid: false, reason: "tool_confirmation_token_signature_invalid" };
    }

    const now = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(payload.exp) || now >= payload.exp) {
      return { valid: false, reason: "tool_confirmation_token_expired" };
    }

    if (payload.sub !== context.userId || payload.role !== context.userRole || payload.tool !== context.toolInvocation.toolName) {
      return { valid: false, reason: "tool_confirmation_token_subject_mismatch" };
    }

    const expectedDigests = computeInvocationDigests(context.toolInvocation);
    if (payload.argsDigest !== expectedDigests.argsDigest || payload.scopeDigest !== expectedDigests.scopeDigest) {
      return { valid: false, reason: "tool_confirmation_token_scope_mismatch" };
    }

    return { valid: true, reason: "tool_confirmation_token_valid" };
  }
}
