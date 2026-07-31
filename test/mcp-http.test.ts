import { test } from "node:test";
import assert from "node:assert/strict";

import { authorizationServerMetadata } from "../lib/auth/metadata";
import { corsHeaders, withCors } from "../lib/http";

process.env.ALLOWED_EMAIL = "me@example.com";
process.env.PUBLIC_BASE_URL = "https://helios.example.com";
process.env.APPS_SCRIPT_URL = "https://script.google.com/macros/s/AK/exec";
process.env.APPS_SCRIPT_SECRET = "s".repeat(32);
process.env.AUTH_SECRET = "a".repeat(32);
process.env.GOOGLE_CLIENT_ID = "cid.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "gsecret";
Object.assign(process.env, { NODE_ENV: "production" });

test("MCP OPTIONS ma kompletne nagłówki CORS dla klientów webowych", () => {
  const headers = new Headers(corsHeaders());
  assert.equal(headers.get("access-control-allow-origin"), "*");
  assert.match(headers.get("access-control-allow-methods") ?? "", /DELETE/);
  assert.match(headers.get("access-control-allow-headers") ?? "", /mcp-protocol-version/i);
  assert.match(headers.get("access-control-allow-headers") ?? "", /mcp-session-id/i);
  assert.match(headers.get("access-control-expose-headers") ?? "", /www-authenticate/i);
});

test("warstwa MCP dodaje do 401 CORS i wymagany scope", () => {
  const source = new Response(JSON.stringify({ error: "invalid_token" }), {
    status: 401,
    headers: {
      "www-authenticate":
        'Bearer error="invalid_token", resource_metadata="https://helios.example.com/.well-known/oauth-protected-resource"',
    },
  });
  const res = withCors(source, "helios.read");
  assert.equal(res.status, 401);
  assert.equal(res.headers.get("access-control-allow-origin"), "*");
  const challenge = res.headers.get("www-authenticate") ?? "";
  assert.match(challenge, /resource_metadata="https:\/\/helios\.example\.com\/\.well-known\/oauth-protected-resource"/);
  assert.match(challenge, /scope="helios\.read"/);
});

test("metadane OAuth deklarują identyfikację wystawcy odpowiedzi", () => {
  const metadata = authorizationServerMetadata("https://helios.example.com");
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);
});
