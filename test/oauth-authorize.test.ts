import { test } from "node:test";
import assert from "node:assert/strict";

import { resetRateLimitState } from "../lib/security/rateLimit";
import { issueClientId } from "../lib/auth/tokens";
import { GET as authorizeGet } from "../app/oauth/authorize/route";

process.env.ALLOWED_EMAIL = "me@example.com";
process.env.PUBLIC_BASE_URL = "https://helios.example.com";
process.env.APPS_SCRIPT_URL = "https://script.google.com/macros/s/AK/exec";
process.env.APPS_SCRIPT_SECRET = "s".repeat(32);
process.env.AUTH_SECRET = "a".repeat(32);
process.env.GOOGLE_CLIENT_ID = "cid.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "gsecret";
Object.assign(process.env, { NODE_ENV: "production" });
delete process.env.ALLOWED_OAUTH_REDIRECT_URIS;

const AUTH_SECRET = process.env.AUTH_SECRET!;
const BASE_URL = process.env.PUBLIC_BASE_URL!;
const RESOURCE = `${BASE_URL}/api/mcp`;
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

async function registeredClientId(redirectUris: string[], clientName = "Demo Client"): Promise<string> {
  return issueClientId(AUTH_SECRET, BASE_URL, { redirectUris, clientName });
}

function authorizeUrl(params: Record<string, string>): string {
  const url = new URL("https://helios.example.com/oauth/authorize");
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.toString();
}

function authorizeReq(params: Record<string, string>, ip = "203.0.113.10"): Request {
  return new Request(authorizeUrl(params), { headers: { "x-forwarded-for": ip } });
}

test("response_type inny niż code jest odrzucany", async () => {
  resetRateLimitState();
  const res = await authorizeGet(authorizeReq({ response_type: "token" }));
  assert.equal(res.status, 400);
  assert.match(await res.text(), /response_type=code/);
});

test("brak PKCE (code_challenge) jest odrzucany", async () => {
  resetRateLimitState();
  const res = await authorizeGet(authorizeReq({ response_type: "code" }));
  assert.equal(res.status, 400);
  assert.match(await res.text(), /PKCE/);
});

test("code_challenge_method inny niż S256 jest odrzucany", async () => {
  resetRateLimitState();
  const res = await authorizeGet(
    authorizeReq({ response_type: "code", code_challenge: CHALLENGE, code_challenge_method: "plain" }),
  );
  assert.equal(res.status, 400);
  assert.match(await res.text(), /S256/);
});

test("nieznany client_id jest odrzucany", async () => {
  resetRateLimitState();
  const res = await authorizeGet(
    authorizeReq({
      response_type: "code",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      client_id: "not-a-real-jwt",
      redirect_uri: "https://client.example.com/cb",
    }),
  );
  assert.equal(res.status, 400);
  assert.match(await res.text(), /Nieznany|nieprawidłowy/);
});

test("wygasły client_id (rejestracja DCR) jest odrzucany", async () => {
  resetRateLimitState();
  const now = Math.floor(Date.now() / 1000);
  const expiredClientId = await issueClientId(
    AUTH_SECRET,
    BASE_URL,
    { redirectUris: ["https://client.example.com/cb"] },
    10, // ttlSeconds
    now - 1000, // wystawiony dawno temu, już wygasł
  );
  const res = await authorizeGet(
    authorizeReq({
      response_type: "code",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      client_id: expiredClientId,
      redirect_uri: "https://client.example.com/cb",
    }),
  );
  assert.equal(res.status, 400);
  assert.match(await res.text(), /wygasły/);
});

test("redirect_uri spoza zarejestrowanych dla klienta jest odrzucany (ochrona przed open redirect)", async () => {
  resetRateLimitState();
  const clientId = await registeredClientId(["https://good.example.com/cb"]);
  const res = await authorizeGet(
    authorizeReq({
      response_type: "code",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      client_id: clientId,
      redirect_uri: "https://evil.example.com/cb",
    }),
  );
  assert.equal(res.status, 400);
  assert.match(await res.text(), /redirect_uri/);
});

test("poprawne żądanie renderuje ekran zgody (nie przekierowuje automatycznie do Google)", async () => {
  resetRateLimitState();
  const clientId = await registeredClientId(["https://client.example.com/cb"], "Moja Aplikacja");
  const res = await authorizeGet(
    authorizeReq({
      response_type: "code",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      client_id: clientId,
      redirect_uri: "https://client.example.com/cb",
      scope: "helios.read",
      resource: RESOURCE,
      state: "client-state-123",
    }),
  );
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
  // Nigdy nie przekierowujemy z samego GET.
  assert.equal(res.headers.get("location"), null);

  const html = await res.text();
  assert.match(html, /Moja Aplikacja/);
  assert.match(html, /client\.example\.com/);
  assert.match(html, /name="consent_token"/);
  assert.match(html, /name="csrf_token"/);
  assert.match(html, /action="\/oauth\/consent"/);

  // Nagłówki bezpieczeństwa ekranu zgody.
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.match(res.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.equal(res.headers.get("cache-control"), "no-store");

  // Ciasteczko CSRF ustawione, HttpOnly.
  const setCookie = res.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /helios_csrf=/);
  assert.match(setCookie, /HttpOnly/);
});

test("brak wymaganego parametru resource jest odrzucany", async () => {
  resetRateLimitState();
  const clientId = await registeredClientId(["https://client.example.com/cb"]);
  const res = await authorizeGet(
    authorizeReq({
      response_type: "code",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      client_id: clientId,
      redirect_uri: "https://client.example.com/cb",
      scope: "helios.read",
    }),
  );
  assert.equal(res.status, 400);
  assert.match(await res.text(), /resource/);
});

test("inny resource lub scope zapisu jest odrzucany", async () => {
  resetRateLimitState();
  const clientId = await registeredClientId(["https://client.example.com/cb"]);
  const base = {
    response_type: "code",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    client_id: clientId,
    redirect_uri: "https://client.example.com/cb",
  };
  const wrongResource = await authorizeGet(
    authorizeReq({ ...base, scope: "helios.read", resource: "https://evil.example.com/api/mcp" }),
  );
  assert.equal(wrongResource.status, 400);
  assert.match(await wrongResource.text(), /resource/);

  resetRateLimitState();
  const wrongScope = await authorizeGet(
    authorizeReq({ ...base, scope: "helios.write", resource: RESOURCE }),
  );
  assert.equal(wrongScope.status, 400);
  assert.match(await wrongScope.text(), /scope/);
});

test("rate limiting: więcej niż 20 żądań z tego samego IP w oknie 5 min zwraca 429", async () => {
  resetRateLimitState();
  const clientId = await registeredClientId(["https://client.example.com/cb"]);
  const ip = "203.0.113.77";
  let lastStatus = 0;
  for (let i = 0; i < 21; i++) {
    const res = await authorizeGet(
      authorizeReq(
        {
          response_type: "code",
          code_challenge: CHALLENGE,
          code_challenge_method: "S256",
          client_id: clientId,
          redirect_uri: "https://client.example.com/cb",
          scope: "helios.read",
          resource: RESOURCE,
        },
        ip,
      ),
    );
    lastStatus = res.status;
  }
  assert.equal(lastStatus, 429);
});
