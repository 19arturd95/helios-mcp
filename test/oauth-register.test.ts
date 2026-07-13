import { test } from "node:test";
import assert from "node:assert/strict";

import { resetRateLimitState } from "../lib/security/rateLimit.js";
import { POST } from "../app/oauth/register/route.js";

// loadConfig() czyta process.env na żywo przy każdym żądaniu — możemy więc
// ustawić je raz dla tego pliku testowego.
process.env.ALLOWED_EMAIL = "me@example.com";
process.env.PUBLIC_BASE_URL = "https://helios.example.com";
process.env.APPS_SCRIPT_URL = "https://script.google.com/macros/s/AK/exec";
process.env.APPS_SCRIPT_SECRET = "s".repeat(32);
process.env.AUTH_SECRET = "a".repeat(32);
process.env.GOOGLE_CLIENT_ID = "cid.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "gsecret";
process.env.NODE_ENV = "production";
delete process.env.ALLOWED_OAUTH_REDIRECT_URIS;

function registerReq(body: unknown, ip = "203.0.113.1"): Request {
  return new Request("https://helios.example.com/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: JSON.stringify(body),
  });
}

test("rejestracja z poprawnym https redirect_uri zwraca 201 i client_id", async () => {
  resetRateLimitState();
  const res = await POST(registerReq({ redirect_uris: ["https://client.example.com/cb"], client_name: "Test" }));
  assert.equal(res.status, 201);
  const body = await res.json();
  assert.ok(body.client_id);
  assert.equal(body.token_endpoint_auth_method, "none");
  assert.deepEqual(body.redirect_uris, ["https://client.example.com/cb"]);
});

test("rejestracja bez redirect_uris jest odrzucana", async () => {
  resetRateLimitState();
  const res = await POST(registerReq({}));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_client_metadata");
});

test("rejestracja z http (nie-localhost) w trybie production jest odrzucana", async () => {
  resetRateLimitState();
  const res = await POST(registerReq({ redirect_uris: ["http://not-localhost.example.com/cb"] }));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_redirect_uri");
});

test("rejestracja z ciałem, które nie jest JSON-em, jest odrzucana", async () => {
  resetRateLimitState();
  const req = new Request("https://helios.example.com/oauth/register", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.5" },
    body: "to nie jest json",
  });
  const res = await POST(req);
  assert.equal(res.status, 400);
});

test("rate limiting: więcej niż 10 rejestracji z tego samego IP w oknie 5 min zwraca 429", async () => {
  resetRateLimitState();
  const ip = "203.0.113.42";
  let lastStatus = 0;
  for (let i = 0; i < 11; i++) {
    const res = await POST(registerReq({ redirect_uris: ["https://client.example.com/cb"] }, ip));
    lastStatus = res.status;
  }
  assert.equal(lastStatus, 429);
});

test("gdy ustawiono ALLOWED_OAUTH_REDIRECT_URIS, redirect_uri spoza listy jest odrzucany mimo https", async () => {
  resetRateLimitState();
  process.env.ALLOWED_OAUTH_REDIRECT_URIS = "https://allowed.example.com/cb";
  try {
    const rejected = await POST(registerReq({ redirect_uris: ["https://not-allowed.example.com/cb"] }, "203.0.113.60"));
    assert.equal(rejected.status, 400);

    const accepted = await POST(registerReq({ redirect_uris: ["https://allowed.example.com/cb"] }, "203.0.113.61"));
    assert.equal(accepted.status, 201);
  } finally {
    delete process.env.ALLOWED_OAUTH_REDIRECT_URIS;
  }
});
