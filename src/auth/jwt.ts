import { createHmac, timingSafeEqual } from "node:crypto";
import { type AuthenticatedIdentity, type UserRole } from "../types";

interface JwtPayload {
  sub?: unknown;
  role?: unknown;
  tenantId?: unknown;
  orgId?: unknown;
  exp?: unknown;
  nbf?: unknown;
}

const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/;

const base64UrlToUtf8 = (value: string): string =>
  Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");

const sign = (header: string, payload: string, secret: string): Buffer =>
  createHmac("sha256", secret).update(`${header}.${payload}`).digest();

const parseJson = <T>(encoded: string): T | null => {
  try {
    return JSON.parse(base64UrlToUtf8(encoded)) as T;
  } catch {
    return null;
  }
};

const asFiniteNumber = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const parseRole = (role: unknown): UserRole | null => {
  if (role === "admin" || role === "operator" || role === "viewer" || role === "anonymous") {
    return role;
  }
  return null;
};

const parseScopeId = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 128) {
    return null;
  }
  return normalized;
};

export const verifyAccessToken = (token: string, secret: string): AuthenticatedIdentity => {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("token_format_invalid");
  }

  const [headerSegment, payloadSegment, signatureSegment] = parts;
  if (!headerSegment || !payloadSegment || !signatureSegment) {
    throw new Error("token_format_invalid");
  }

  if (!BASE64_URL_PATTERN.test(headerSegment) || !BASE64_URL_PATTERN.test(payloadSegment)) {
    throw new Error("token_encoding_invalid");
  }

  const header = parseJson<{ alg?: unknown; typ?: unknown }>(headerSegment);
  if (!header || header.alg !== "HS256" || header.typ !== "JWT") {
    throw new Error("token_header_invalid");
  }

  if (!BASE64_URL_PATTERN.test(signatureSegment)) {
    throw new Error("token_signature_encoding_invalid");
  }

  const signature = Buffer.from(signatureSegment.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const expectedSignature = sign(headerSegment, payloadSegment, secret);

  if (signature.length !== expectedSignature.length || !timingSafeEqual(signature, expectedSignature)) {
    throw new Error("token_signature_invalid");
  }

  const payload = parseJson<JwtPayload>(payloadSegment);
  if (!payload) {
    throw new Error("token_payload_invalid");
  }

  const userId = typeof payload.sub === "string" ? payload.sub.trim() : "";
  if (userId.length < 1 || userId.length > 128) {
    throw new Error("token_subject_invalid");
  }

  const userRole = parseRole(payload.role);
  if (!userRole) {
    throw new Error("token_role_invalid");
  }

  const tenantId = parseScopeId(payload.tenantId);
  const orgId = parseScopeId(payload.orgId);

  const nowEpochSeconds = Math.floor(Date.now() / 1000);
  const exp = asFiniteNumber(payload.exp);
  const nbf = asFiniteNumber(payload.nbf);

  if (exp !== null && nowEpochSeconds >= exp) {
    throw new Error("token_expired");
  }

  if (nbf !== null && nowEpochSeconds < nbf) {
    throw new Error("token_not_active");
  }

  return { userId, userRole, tenantId, orgId };
};
