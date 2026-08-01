import { test } from "node:test";
import assert from "node:assert/strict";

import { issueAccessToken } from "../lib/auth/tokens";
import { mcpResourceUrl } from "../lib/config";
import { resetRateLimitState } from "../lib/security/rateLimit";
import { POST as mcpPost } from "../app/api/mcp/route";

process.env.ALLOWED_EMAIL = "me@example.com";
process.env.PUBLIC_BASE_URL = "https://helios.example.com";
process.env.APPS_SCRIPT_URL = "https://script.google.com/macros/s/AK/exec";
process.env.APPS_SCRIPT_SECRET = "s".repeat(32);
process.env.AUTH_SECRET = "a".repeat(32);
process.env.GOOGLE_CLIENT_ID = "cid.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "gsecret";
Object.assign(process.env, { NODE_ENV: "production" });

async function bearer(): Promise<string> {
  return issueAccessToken({
    authSecret: process.env.AUTH_SECRET!,
    issuer: process.env.PUBLIC_BASE_URL!,
    audience: mcpResourceUrl(process.env.PUBLIC_BASE_URL!),
    email: process.env.ALLOWED_EMAIL!,
    clientId: "test-client",
    scope: "helios.read",
  });
}

async function parseMcpResponse(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text();
  if ((res.headers.get("content-type") ?? "").includes("application/json")) {
    return JSON.parse(text) as Record<string, unknown>;
  }
  const data = text
    .split("\n")
    .find((line) => line.startsWith("data: "))
    ?.slice("data: ".length);
  assert.ok(data, "odpowiedź MCP powinna zawierać komunikat JSON");
  return JSON.parse(data) as Record<string, unknown>;
}

test("tools/list publikuje schematy wyjścia i bezpieczne adnotacje dla wszystkich narzędzi", async () => {
  resetRateLimitState();
  const token = await bearer();
  const req = new Request("https://helios.example.com/api/mcp", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": "2025-06-18",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });

  const res = await mcpPost(req);
  assert.equal(res.status, 200);
  const body = await parseMcpResponse(res) as {
    result?: { tools?: Array<Record<string, unknown>> };
  };
  const tools = body.result?.tools ?? [];
  assert.equal(tools.length, 7);
  for (const tool of tools) {
    assert.deepEqual(tool.annotations, {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    });
    assert.equal((tool.outputSchema as { type?: string } | undefined)?.type, "object");
  }
});

test("helios_status zwraca structuredContent bez identyfikatora folderu Drive", async () => {
  resetRateLimitState();
  const token = await bearer();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(
      JSON.stringify({
        ok: true,
        result: {
          ok: true,
          rootId: "private-drive-folder-id",
          rootName: "helios",
          serverTime: "2026-08-02T00:00:00.000Z",
          readOnly: true,
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    )) as typeof fetch;

  try {
    const req = new Request("https://helios.example.com/api/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": "2025-06-18",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "helios_status", arguments: {} },
      }),
    });
    const res = await mcpPost(req);
    assert.equal(res.status, 200);
    const body = await parseMcpResponse(res) as {
      result?: { structuredContent?: Record<string, unknown>; content?: Array<{ text?: string }> };
    };
    assert.equal(body.result?.structuredContent?.readOnly, true);
    assert.equal(body.result?.structuredContent?.rootName, "helios");
    assert.equal("rootId" in (body.result?.structuredContent ?? {}), false);
    assert.doesNotMatch(body.result?.content?.[0]?.text ?? "", /private-drive-folder-id/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
