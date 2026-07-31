import { test } from "node:test";
import assert from "node:assert/strict";

import { resetRateLimitState } from "../lib/security/rateLimit";
import { issueConsentToken } from "../lib/auth/tokens";
import { POST as consentPost } from "../app/oauth/consent/route";

process.env.ALLOWED_EMAIL = "me@example.com";
process.env.PUBLIC_BASE_URL = "https://helios.example.com";
process.env.APPS_SCRIPT_URL = "https://script.google.com/macros/s/AK/exec";
process.env.APPS_SCRIPT_SECRET = "s".repeat(32);
process.env.AUTH_SECRET = "a".repeat(32);
process.env.GOOGLE_CLIENT_ID = "cid.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "gsecret";
Object.assign(process.env, { NODE_ENV: "production" });

const AUTH_SECRET = process.env.AUTH_SECRET!;
const BASE_URL = process.env.PUBLIC_BASE_URL!;

async function makeConsentToken(overrides: Partial<Parameters<typeof issueConsentToken>[2]> = {}) {
  return issueConsentToken(AUTH_SECRET, BASE_URL, {
    clientId: "client-abc",
    clientName: "Demo Client",
    redirectUri: "https://client.example.com/cb",
    codeChallenge: "challenge-xyz",
    scope: "helios.read",
    resource: `${BASE_URL}/api/mcp`,
    state: "client-original-state",
    ...overrides,
  });
}

function consentReq(fields: Record<string, string>, cookie?: string, ip = "203.0.113.20"): Request {
  const form = new URLSearchParams(fields);
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    "x-forwarded-for": ip,
  };
  if (cookie) headers["cookie"] = cookie;
  return new Request("https://helios.example.com/oauth/consent", {
    method: "POST",
    headers,
    body: form.toString(),
  });
}

test("Zezwól: przekierowuje do Google, ustawia state, czyści ciasteczko CSRF", async () => {
  resetRateLimitState();
  const csrf = "csrf-token-value-1";
  const consentToken = await makeConsentToken();
  const res = await consentPost(
    consentReq({ consent_token: consentToken, csrf_token: csrf, decision: "allow" }, `helios_csrf=${csrf}`),
  );
  assert.equal(res.status, 302);
  const location = res.headers.get("location") ?? "";
  assert.match(location, /^https:\/\/accounts\.google\.com\//);
  const url = new URL(location);
  assert.equal(url.searchParams.get("client_id"), process.env.GOOGLE_CLIENT_ID);
  assert.equal(url.searchParams.get("redirect_uri"), `${BASE_URL}/oauth/callback`);
  assert.ok(url.searchParams.get("state")); // nasz podpisany oauthState, nie oryginalny state klienta
  const setCookie = res.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /helios_csrf=;/);
  assert.match(setCookie, /Max-Age=0/);
});

test("Odrzuć: wraca do redirect_uri klienta z error=access_denied, BEZ kodu", async () => {
  resetRateLimitState();
  const csrf = "csrf-token-value-2";
  const consentToken = await makeConsentToken({ state: "abc-state" });
  const res = await consentPost(
    consentReq({ consent_token: consentToken, csrf_token: csrf, decision: "deny" }, `helios_csrf=${csrf}`),
  );
  assert.equal(res.status, 302);
  const location = res.headers.get("location") ?? "";
  assert.match(location, /^https:\/\/client\.example\.com\/cb/);
  const url = new URL(location);
  assert.equal(url.searchParams.get("error"), "access_denied");
  assert.equal(url.searchParams.get("code"), null);
  assert.equal(url.searchParams.get("state"), "abc-state");
});

test("brak dopasowania CSRF (cookie != pole formularza) jest odrzucany, bez przekierowania", async () => {
  resetRateLimitState();
  const consentToken = await makeConsentToken();
  const res = await consentPost(
    consentReq({ consent_token: consentToken, csrf_token: "wartosc-formularza", decision: "allow" }, "helios_csrf=inna-wartosc"),
  );
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("location"), null);
});

test("brak ciasteczka CSRF jest odrzucany", async () => {
  resetRateLimitState();
  const consentToken = await makeConsentToken();
  const res = await consentPost(consentReq({ consent_token: consentToken, csrf_token: "cokolwiek", decision: "allow" }));
  assert.equal(res.status, 400);
});

test("zmodyfikowany (podrobiony) stan zgody jest odrzucany", async () => {
  resetRateLimitState();
  const csrf = "csrf-3";
  const consentToken = await makeConsentToken();
  const parts = consentToken.split(".");
  const tamperedPayload = Buffer.from(
    JSON.stringify({ clientId: "attacker", redirectUri: "https://evil.example/cb", state: "" }),
  ).toString("base64url");
  const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
  const res = await consentPost(consentReq({ consent_token: tampered, csrf_token: csrf, decision: "allow" }, `helios_csrf=${csrf}`));
  assert.equal(res.status, 400);
});

test("wygasły stan zgody jest odrzucany", async () => {
  resetRateLimitState();
  const csrf = "csrf-4";
  const now = Math.floor(Date.now() / 1000);
  const consentToken = await issueConsentToken(
    AUTH_SECRET,
    BASE_URL,
    {
      clientId: "client-abc",
      clientName: "Demo",
      redirectUri: "https://client.example.com/cb",
      codeChallenge: "x",
      scope: "helios.read",
      resource: `${BASE_URL}/api/mcp`,
      state: "s",
    },
    5,
    now - 1000,
  );
  const res = await consentPost(consentReq({ consent_token: consentToken, csrf_token: csrf, decision: "allow" }, `helios_csrf=${csrf}`));
  assert.equal(res.status, 400);
});
