import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  clearLiteLLMIdentityCache,
  LiteLLMIdentityError,
  resolveLiteLLMIdentity
} from "../auth/litellmIdentity";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  clearLiteLLMIdentityCache();
});

describe("LiteLLM identity introspection", () => {
  it("forwards the bearer token and caches the principal by token digest", async () => {
    const calls: Array<{ url: string; authorization: string | null }> = [];
    globalThis.fetch = (async (input, init) => {
      const headers = new Headers(init?.headers);
      calls.push({ url: String(input), authorization: headers.get("authorization") });
      return new Response(JSON.stringify({
        user_id: "user-1",
        user_role: "proxy_admin",
        team_id: "team-1",
        organization_id: "org-1"
      }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;

    const first = await resolveLiteLLMIdentity("virtual-key-one");
    const second = await resolveLiteLLMIdentity("virtual-key-one");

    assert.deepEqual(first, {
      userId: "user-1",
      userRole: "admin",
      tenantId: "team-1",
      orgId: "org-1"
    });
    assert.deepEqual(second, first);
    assert.equal(calls.length, 1);
    assert.match(calls[0]?.url ?? "", /\/v1\/zentris\/auth\/introspect$/);
    assert.equal(calls[0]?.authorization, "Bearer virtual-key-one");
  });

  it("does not share cached principals between different virtual keys", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      return new Response(JSON.stringify({ user_id: `user-${calls}`, user_role: "operator" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }) as typeof fetch;

    assert.equal((await resolveLiteLLMIdentity("key-a")).userId, "user-1");
    assert.equal((await resolveLiteLLMIdentity("key-b")).userId, "user-2");
    assert.equal(calls, 2);
  });

  it("coalesces concurrent cache misses for the same virtual key", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return new Response(JSON.stringify({ user_id: "coalesced-user", user_role: "operator" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }) as typeof fetch;

    const identities = await Promise.all(
      Array.from({ length: 100 }, () => resolveLiteLLMIdentity("shared-concurrent-key"))
    );
    assert.equal(calls, 1);
    assert.equal(identities.every((identity) => identity.userId === "coalesced-user"), true);
  });

  it("maps rejected introspection to a safe authentication error", async () => {
    globalThis.fetch = (async () => new Response(null, { status: 403 })) as typeof fetch;
    await assert.rejects(
      resolveLiteLLMIdentity("rejected-key"),
      (error: unknown) => error instanceof LiteLLMIdentityError && error.statusCode === 403 && error.message === "invalid_litellm_key"
    );
  });
});
