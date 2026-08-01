import { test } from "node:test";
import assert from "node:assert/strict";

import { authorizationServerMetadata } from "../lib/auth/metadata";
import { corsHeaders, htmlError, htmlSecurityHeaders, withCors } from "../lib/http";
import { READ_ONLY_TOOL_ANNOTATIONS } from "../lib/tools/annotations";

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

test("wszystkie narzędzia deklarują zamknięty tryb tylko do odczytu", () => {
  assert.deepEqual(READ_ONLY_TOOL_ANNOTATIONS, {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  });
});

test("CSP dopuszcza tylko HTTPS i lokalny HTTP jako cele formularza", () => {
  const csp = new Headers(
    htmlSecurityHeaders([
      "https://trusted.example/callback",
      "http://localhost:3000/callback",
      "http://127.0.0.1:4000/callback",
      "http://remote.example/callback",
      "javascript:alert(1)",
    ]),
  ).get("content-security-policy") ?? "";
  assert.match(csp, /https:\/\/trusted\.example/);
  assert.match(csp, /http:\/\/localhost:3000/);
  assert.match(csp, /http:\/\/127\.0\.0\.1:4000/);
  assert.doesNotMatch(csp, /remote\.example/);
  assert.doesNotMatch(csp, /javascript/);
});

test("strony błędów OAuth mają pełne nagłówki bezpieczeństwa", () => {
  const res = htmlError("Błąd", "Test");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/);
  assert.match(res.headers.get("permissions-policy") ?? "", /camera=\(\)/);
  assert.match(res.headers.get("strict-transport-security") ?? "", /max-age=31536000/);
});
