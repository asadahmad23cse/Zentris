import assert from "node:assert/strict";
import { afterEach, before, beforeEach, describe, test } from "node:test";
import sinon, { type SinonSandbox } from "sinon";

let buildServer: typeof import("../server").buildServer;
let redisClient: typeof import("../services/redisClient").redisClient;

describe("health endpoints", () => {
  let sandbox: SinonSandbox;
  let app: Awaited<ReturnType<typeof buildServer>>;

  before(async () => {
    process.env.REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";
    process.env.LITELLM_BASE_URL = process.env.LITELLM_BASE_URL ?? "http://localhost:4000";
    process.env.LITELLM_API_KEY = process.env.LITELLM_API_KEY ?? "sk-test-key";
    process.env.JWT_SECRET = process.env.JWT_SECRET ?? "unit-test-jwt-secret";
    process.env.LOG_LEVEL = process.env.LOG_LEVEL ?? "info";
    process.env.PORT = process.env.PORT ?? "3100";

    ({ buildServer } = await import("../server"));
    ({ redisClient } = await import("../services/redisClient"));
  });

  beforeEach(async () => {
    sandbox = sinon.createSandbox();
    app = await buildServer();
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
    sandbox.restore();
  });

  test("liveness endpoint does not require authentication", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health/liveness"
    });

    assert.equal(response.statusCode, 200);
    assert.equal(response.json().status, "ok");
  });

  test("health responses include defensive security headers", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health/liveness"
    });

    assert.equal(response.headers["x-content-type-options"], "nosniff");
    assert.equal(response.headers["x-frame-options"], "DENY");
    assert.equal(response.headers["referrer-policy"], "no-referrer");
    assert.equal(response.headers["cross-origin-resource-policy"], "same-origin");
    assert.equal(response.headers["content-security-policy"], "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  });

  test("readiness endpoint reports ready when Redis responds", async () => {
    sandbox.stub(redisClient, "ping").resolves("PONG");

    const response = await app.inject({
      method: "GET",
      url: "/health/readiness"
    });

    const body = response.json();
    assert.equal(response.statusCode, 200);
    assert.equal(body.status, "ready");
    assert.equal(body.dependencies.redis.ok, true);
  });

  test("readiness endpoint returns 503 when Redis is unavailable", async () => {
    sandbox.stub(redisClient, "ping").rejects(new Error("redis_down"));

    const response = await app.inject({
      method: "GET",
      url: "/health/readiness"
    });

    const body = response.json();
    assert.equal(response.statusCode, 503);
    assert.equal(body.status, "not_ready");
    assert.equal(body.dependencies.redis.ok, false);
  });
});
