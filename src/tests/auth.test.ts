import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, test } from "node:test";
import { verifyAccessToken } from "../auth/jwt";

const SECRET = "unit-test-jwt-secret";

const toBase64Url = (value: string): string =>
  Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const signToken = (payload: Record<string, unknown>, secret: string = SECRET): string => {
  const headerSegment = toBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payloadSegment = toBase64Url(JSON.stringify(payload));
  const signature = createHmac("sha256", secret)
    .update(`${headerSegment}.${payloadSegment}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${headerSegment}.${payloadSegment}.${signature}`;
};

describe("JWT auth verification", () => {
  test("accepts valid signed token", () => {
    const now = Math.floor(Date.now() / 1000);
    const token = signToken({
      sub: "user-1",
      role: "operator",
      tenantId: "tenant-a",
      exp: now + 300
    });

    const identity = verifyAccessToken(token, SECRET);

    assert.equal(identity.userId, "user-1");
    assert.equal(identity.userRole, "operator");
    assert.equal(identity.tenantId, "tenant-a");
  });

  test("rejects token signed with wrong secret", () => {
    const now = Math.floor(Date.now() / 1000);
    const token = signToken(
      {
        sub: "user-2",
        role: "admin",
        tenantId: "tenant-a",
        exp: now + 300
      },
      "different-secret"
    );

    assert.throws(() => verifyAccessToken(token, SECRET), /token_signature_invalid/);
  });
});
