import { randomUUID, createHash, createHmac, timingSafeEqual } from "node:crypto";
import { config } from "../config";
import { redisClient } from "./redisClient";
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
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
}

interface TokenValidationContext {
  userId: string;
  userRole: UserRole;
  toolInvocation: ToolInvocation;
}

const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const JTI_PATTERN = /^[A-Za-z0-9-]{16,128}$/;
const JTI_KEY_PREFIX = "zentris:tool_confirmation:jti";

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

const confirmationJtiKey = (jti: string): string => `${JTI_KEY_PREFIX}:${jti}`;

const isFiniteInteger = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && Number.isInteger(value);

export class ToolConfirmationTokenService {
  public issue(context: TokenValidationContext): string {
    const now = Math.floor(Date.now() / 1000);
    const digests = computeInvocationDigests(context.toolInvocation);
    const jti = randomUUID();

    const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "TOOLCONF" } as ConfirmationTokenHeader));
    const payload = base64UrlEncode(
      JSON.stringify({
        sub: context.userId,
        role: context.userRole,
        tool: context.toolInvocation.toolName,
        argsDigest: digests.argsDigest,
        scopeDigest: digests.scopeDigest,
        jti,
        iat: now,
        nbf: now,
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

  public async verifyAndConsume(
    token: string,
    context: TokenValidationContext
  ): Promise<{ valid: boolean; reason: string }> {
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

    const skewSeconds = config.CONFIRMATION_TOKEN_MAX_CLOCK_SKEW_SECONDS;
    const now = Math.floor(Date.now() / 1000);
    if (
      !isFiniteInteger(payload.iat) ||
      !isFiniteInteger(payload.nbf) ||
      !isFiniteInteger(payload.exp) ||
      payload.exp <= payload.iat
    ) {
      return { valid: false, reason: "tool_confirmation_token_time_claims_invalid" };
    }
    if (now + skewSeconds < payload.nbf) {
      return { valid: false, reason: "tool_confirmation_token_not_active" };
    }
    if (now - skewSeconds >= payload.exp) {
      return { valid: false, reason: "tool_confirmation_token_expired" };
    }
    if (payload.iat > payload.exp) {
      return { valid: false, reason: "tool_confirmation_token_time_claims_invalid" };
    }

    if (!JTI_PATTERN.test(payload.jti)) {
      return { valid: false, reason: "tool_confirmation_token_jti_invalid" };
    }

    if (
      payload.sub !== context.userId ||
      payload.role !== context.userRole ||
      payload.tool !== context.toolInvocation.toolName
    ) {
      return { valid: false, reason: "tool_confirmation_token_subject_mismatch" };
    }

    const expectedDigests = computeInvocationDigests(context.toolInvocation);
    if (payload.argsDigest !== expectedDigests.argsDigest || payload.scopeDigest !== expectedDigests.scopeDigest) {
      return { valid: false, reason: "tool_confirmation_token_scope_mismatch" };
    }

    const ttlSeconds = Math.max(1, payload.exp - now + skewSeconds);
    try {
      const inserted = await redisClient.set(
        confirmationJtiKey(payload.jti),
        JSON.stringify({ consumedAt: now, userId: context.userId, tool: context.toolInvocation.toolName }),
        "EX",
        ttlSeconds,
        "NX"
      );

      if (inserted !== "OK") {
        return { valid: false, reason: "tool_confirmation_token_replay_detected" };
      }
    } catch {
      return { valid: false, reason: "tool_confirmation_redis_unavailable" };
    }

    return { valid: true, reason: "tool_confirmation_token_valid" };
  }
}
