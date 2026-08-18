import { createHash } from "node:crypto";
import { config } from "../config";
import { type AuthenticatedIdentity, type UserRole } from "../types";

interface CacheEntry { identity: AuthenticatedIdentity; expiresAt: number; }
interface IntrospectionResponse {
  user_id?: unknown;
  user_role?: unknown;
  team_id?: unknown;
  organization_id?: unknown;
}

const CACHE_TTL_MS = 60_000;
const MAX_CACHE_ENTRIES = 10_000;
const cache = new Map<string, CacheEntry>();
const pending = new Map<string, Promise<AuthenticatedIdentity>>();

export class LiteLLMIdentityError extends Error {
  public readonly statusCode: number;
  public constructor(message: string, statusCode = 401) {
    super(message);
    this.name = "LiteLLMIdentityError";
    this.statusCode = statusCode;
  }
}

const managementBaseUrl = (): string => {
  const parsed = new URL(config.LITELLM_BASE_URL);
  parsed.pathname = parsed.pathname.replace(/\/(?:v1)\/?$/, "").replace(/\/$/, "");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/$/, "");
};

const mapRole = (role: unknown): UserRole => {
  if (role === "proxy_admin" || role === "Admin") return "admin";
  if (role === "proxy_admin_viewer" || role === "viewer") return "viewer";
  return "operator";
};

const tokenHash = (token: string): string => createHash("sha256").update(token).digest("hex");

export const resolveLiteLLMIdentity = async (token: string): Promise<AuthenticatedIdentity> => {
  const hash = tokenHash(token);
  const cached = cache.get(hash);
  if (cached && cached.expiresAt > Date.now()) return cached.identity;
  if (cached) cache.delete(hash);

  const existing = pending.get(hash);
  if (existing) return existing;

  const resolution = resolveUncachedIdentity(token, hash);
  pending.set(hash, resolution);
  try {
    return await resolution;
  } finally {
    pending.delete(hash);
  }
};

const resolveUncachedIdentity = async (token: string, hash: string): Promise<AuthenticatedIdentity> => {
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
  const response = await fetch(`${managementBaseUrl()}/v1/zentris/auth/introspect`, {
    headers,
    signal: AbortSignal.timeout(5_000)
  });
  if (!response.ok) throw new LiteLLMIdentityError("invalid_litellm_key", response.status === 403 ? 403 : 401);
  const principal = await response.json() as IntrospectionResponse;
  const userId = typeof principal.user_id === "string" && principal.user_id ? principal.user_id : `key:${hash.slice(0, 16)}`;

  const identity: AuthenticatedIdentity = {
    userId,
    userRole: mapRole(principal.user_role),
    tenantId: typeof principal.team_id === "string" ? principal.team_id : null,
    orgId: typeof principal.organization_id === "string" ? principal.organization_id : null
  };
  if (cache.size >= MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value as string);
  cache.set(hash, { identity, expiresAt: Date.now() + CACHE_TTL_MS });
  return identity;
};

export const clearLiteLLMIdentityCache = (): void => {
  cache.clear();
  pending.clear();
};
