import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { type AppConfig } from "../config";

let ConfigValidationError: typeof import("../config").ConfigValidationError;
let validateConfig: typeof import("../config").validateConfig;

const validConfig = (overrides: Partial<AppConfig> = {}): AppConfig => ({
  NODE_ENV: "production",
  ZENTRIS_STRICT_CONFIG: true,
  ZENTRIS_DEMO_ENABLED: false,
  REDIS_URL: "rediss://redis.internal:6379",
  LITELLM_BASE_URL: "https://llm.internal",
  LITELLM_API_KEY: "sk-production-key-1234567890",
  LITELLM_MODEL: "gpt-4o-mini",
  JWT_SECRET: "jwt-secret-1234567890-1234567890",
  RATE_LIMIT_MAX: 30,
  RATE_LIMIT_WINDOW: "1 minute",
  REQUEST_BODY_LIMIT_BYTES: 1_048_576,
  CONFIRMATION_TOKEN_SECRET: "confirmation-secret-1234567890-1234567890",
  CONFIRMATION_TOKEN_TTL_SECONDS: 120,
  CONFIRMATION_TOKEN_MAX_CLOCK_SKEW_SECONDS: 15,
  STREAMING_CONCURRENT_LIMIT: 2,
  STREAMING_SLOT_TTL_SECONDS: 120,
  STREAMING_ROLLING_BUFFER_CHARS: 512,
  STREAMING_SUSPICIOUS_EVENT_LIMIT: 2,
  STREAMING_SESSION_SUSPICIOUS_EVENT_LIMIT: 10,
  STREAMING_SESSION_SUSPICIOUS_WINDOW_SECONDS: 900,
  SERVER_SYSTEM_PROMPT: "Stay within the server-owned safety policy.",
  MAX_SESSION_MESSAGES: 20,
  CIRCUIT_BREAKER_ENABLED: true,
  LOG_LEVEL: "info",
  PORT: 3000,
  PUBLIC_WEB_ORIGIN: "https://litellm-dashboard-rose.vercel.app",
  ...overrides
});

describe("configuration validation", () => {
  before(async () => {
    process.env.REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";
    process.env.LITELLM_BASE_URL = process.env.LITELLM_BASE_URL ?? "http://localhost:4000";
    process.env.LITELLM_API_KEY = process.env.LITELLM_API_KEY ?? "sk-test-key";
    process.env.JWT_SECRET = process.env.JWT_SECRET ?? "unit-test-jwt-secret";
    process.env.LOG_LEVEL = process.env.LOG_LEVEL ?? "info";
    process.env.PORT = process.env.PORT ?? "3100";

    ({ ConfigValidationError, validateConfig } = await import("../config"));
  });

  test("accepts production-grade configuration", () => {
    assert.doesNotThrow(() => validateConfig(validConfig()));
  });

  test("rejects placeholder production secrets", () => {
    assert.throws(
      () =>
        validateConfig(
          validConfig({
            JWT_SECRET: "REPLACE_WITH_64_BYTE_RANDOM_BASE64_SECRET",
            CONFIRMATION_TOKEN_SECRET: "REPLACE_WITH_64_BYTE_RANDOM_BASE64_SECRET"
          })
        ),
      ConfigValidationError
    );
  });

  test("rejects shared JWT and confirmation secrets", () => {
    const sharedSecret = "shared-secret-1234567890-1234567890";

    assert.throws(
      () =>
        validateConfig(
          validConfig({
            JWT_SECRET: sharedSecret,
            CONFIRMATION_TOKEN_SECRET: sharedSecret
          })
        ),
      /must be distinct/
    );
  });

  test("rejects invalid upstream and Redis URLs", () => {
    assert.throws(
      () =>
        validateConfig(
          validConfig({
            REDIS_URL: "localhost:6379",
            LITELLM_BASE_URL: "llm.internal"
          })
        ),
      /REDIS_URL.*LITELLM_BASE_URL/
    );
  });

  test("rejects oversized confirmation replay window", () => {
    assert.throws(
      () =>
        validateConfig(
          validConfig({
            CONFIRMATION_TOKEN_TTL_SECONDS: 3600,
            CONFIRMATION_TOKEN_MAX_CLOCK_SKEW_SECONDS: 120
          })
        ),
      /CONFIRMATION_TOKEN_TTL_SECONDS.*CONFIRMATION_TOKEN_MAX_CLOCK_SKEW_SECONDS/
    );
  });

  test("rejects unsafe request body limits", () => {
    assert.throws(
      () =>
        validateConfig(
          validConfig({
            REQUEST_BODY_LIMIT_BYTES: 10_000_000
          })
        ),
      /REQUEST_BODY_LIMIT_BYTES/
    );
  });
});
