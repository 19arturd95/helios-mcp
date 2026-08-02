/**
 * Regresja dla /oauth/callback — powiązanie logowania Google z przeglądarką.
 *
 * Bez tego powiązania działał następujący atak (potwierdzony PoC podczas audytu):
 *   1. atakujący rejestruje klienta przez otwarty DCR z własnym redirect_uri,
 *   2. sam przechodzi ekran zgody i przechwytuje gotowy link accounts.google.com,
 *   3. podsyła link ofierze — ofiara wybiera swoje konto Google,
 *   4. kod autoryzacyjny wystawiony na konto OFIARY trafia do atakującego.
 *
 * Testy poniżej uruchamiają PRAWDZIWY handler trasy. Google (endpoint tokenu
 * i JWKS) jest podstawiony lokalnie — żaden pakiet nie opuszcza procesu.
 */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import { EventEmitter } from "node:events";
import { generateKeyPair, exportJWK, SignJWT, type KeyLike } from "jose";

process.env.ALLOWED_EMAIL = "owner@example.com";
process.env.PUBLIC_BASE_URL = "https://helios.example.com";
process.env.APPS_SCRIPT_URL = "https://script.google.com/macros/s/AK/exec";
process.env.APPS_SCRIPT_SECRET = "s".repeat(32);
process.env.AUTH_SECRET = "a".repeat(32);
process.env.GOOGLE_CLIENT_ID = "cid.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "gsecret";
Object.assign(process.env, { NODE_ENV: "production" });

import { issueClientId, issueOAuthState } from "../lib/auth/tokens";
import { sha256Hex } from "../lib/security/signing";
import { LOGIN_COOKIE } from "../lib/auth/loginBinding";
import { resetRateLimitState } from "../lib/security/rateLimit";

const BASE = "https://helios.example.com";
const AUTH_SECRET = "a".repeat(32);
const ATTACKER_REDIRECT = "https://attacker.example/collect";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

let privateKey: KeyLike;
let idTokenToServe: string;
let callback: typeof import("../app/oauth/callback/route");

async function googleIdToken(opts: { email?: string; verified?: boolean; nonce?: string } = {}) {
  return new SignJWT({
    email: opts.email ?? "owner@example.com",
    email_verified: opts.verified ?? true,
    ...(opts.nonce === undefined ? {} : { nonce: opts.nonce }),
  })
    .setProtectedHeader({ alg: "RS256", kid: "k" })
    .setIssuer("https://accounts.google.com")
    .setAudience("cid.apps.googleusercontent.com")
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
}

before(async () => {
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: "k", alg: "RS256", use: "sig" };

  // jose (build node) pobiera JWKS przez https.get, nie przez globalThis.fetch.
  const realGet = https.get;
  (https as unknown as { get: unknown }).get = (url: unknown, o?: unknown) => {
    if (!String((url as { href?: string })?.href ?? url).includes("oauth2/v3/certs")) {
      return (realGet as unknown as (...a: unknown[]) => unknown)(url, o);
    }
    const req = new EventEmitter() as EventEmitter & { destroy(): void };
    req.destroy = () => {};
    queueMicrotask(() => {
      const res = new EventEmitter() as EventEmitter & { statusCode: number };
      res.statusCode = 200;
      (res as unknown as Record<symbol, unknown>)[Symbol.asyncIterator] = async function* () {
        yield Buffer.from(JSON.stringify({ keys: [jwk] }));
      };
      req.emit("response", res);
    });
    return req;
  };

  globalThis.fetch = (async (url: unknown) => {
    if (String((url as { url?: string })?.url ?? url).includes("oauth2.googleapis.com/token")) {
      return new Response(JSON.stringify({ id_token: idTokenToServe }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error("unexpected fetch");
  }) as unknown as typeof fetch;

  callback = await import("../app/oauth/callback/route");
});

async function stateFor(loginSecret: string | null, googleNonce = "gn-1") {
  const clientId = await issueClientId(AUTH_SECRET, BASE, { redirectUris: [ATTACKER_REDIRECT] });
  return issueOAuthState(AUTH_SECRET, BASE, {
    clientId,
    redirectUri: ATTACKER_REDIRECT,
    codeChallenge: CHALLENGE,
    scope: "helios.read",
    resource: `${BASE}/api/mcp`,
    state: "s",
    browserBinding: loginSecret === null ? "" : await sha256Hex(loginSecret),
    googleNonce,
  });
}

async function hitCallback(state: string, cookie?: string) {
  resetRateLimitState();
  const headers: Record<string, string> = {};
  if (cookie !== undefined) headers.cookie = cookie;
  const res = await callback.GET(
    new Request(`${BASE}/oauth/callback?code=GOOGLE_CODE&state=${encodeURIComponent(state)}`, { headers }),
  );
  const location = res.headers.get("location");
  return {
    status: res.status,
    location,
    issuedCode: location ? new URL(location).searchParams.get("code") : null,
    setCookie: res.headers.get("set-cookie") ?? "",
  };
}

test("logowanie kończy się sukcesem tylko w przeglądarce, która kliknęła „Zezwól”", async () => {
  idTokenToServe = await googleIdToken({ nonce: "gn-1" });
  const secret = "browser-secret-value";
  const r = await hitCallback(await stateFor(secret), `${LOGIN_COOKIE}=${secret}`);
  assert.equal(r.status, 302);
  assert.ok(r.issuedCode, "kod autoryzacyjny powinien zostać wystawiony");
  assert.match(r.setCookie, new RegExp(`${LOGIN_COOKIE}=;`), "ciasteczko wiążące musi zostać wyczyszczone");
});

test("state podstawiony ofierze BEZ ciasteczka nie wystawia kodu (główny atak)", async () => {
  idTokenToServe = await googleIdToken({ nonce: "gn-1" });
  const r = await hitCallback(await stateFor("attacker-secret"));
  assert.equal(r.status, 400);
  assert.equal(r.location, null, "nie wolno przekierować do redirect_uri atakującego");
  assert.equal(r.issuedCode, null, "nie wolno wystawić kodu autoryzacyjnego");
});

test("ciasteczko z innej przeglądarki (niezgodna wartość) nie wystawia kodu", async () => {
  idTokenToServe = await googleIdToken({ nonce: "gn-1" });
  const r = await hitCallback(await stateFor("attacker-secret"), `${LOGIN_COOKIE}=inna-wartosc`);
  assert.equal(r.status, 400);
  assert.equal(r.issuedCode, null);
});

test("zduplikowane ciasteczko wiążące jest odrzucane (cookie tossing → fail closed)", async () => {
  idTokenToServe = await googleIdToken({ nonce: "gn-1" });
  const secret = "browser-secret-value";
  const r = await hitCallback(await stateFor(secret), `${LOGIN_COOKIE}=${secret}; ${LOGIN_COOKIE}=${secret}`);
  assert.equal(r.status, 400);
  assert.equal(r.issuedCode, null);
});

test("state bez pola browserBinding (stary format) jest odrzucany — fail closed", async () => {
  idTokenToServe = await googleIdToken({ nonce: "gn-1" });
  const r = await hitCallback(await stateFor(null), `${LOGIN_COOKIE}=cokolwiek`);
  assert.equal(r.status, 400);
  assert.equal(r.issuedCode, null);
});

test("ten sam state nie działa drugi raz w tej samej przeglądarce po wyczyszczeniu ciasteczka", async () => {
  idTokenToServe = await googleIdToken({ nonce: "gn-1" });
  const secret = "browser-secret-value";
  const state = await stateFor(secret);
  const first = await hitCallback(state, `${LOGIN_COOKIE}=${secret}`);
  assert.ok(first.issuedCode);
  // Przeglądarka usunęła ciasteczko zgodnie z Max-Age=0 → powtórka bez ciasteczka.
  const second = await hitCallback(state);
  assert.equal(second.status, 400);
  assert.equal(second.issuedCode, null);
});

test("id_token z niezgodnym nonce jest odrzucany (wstrzyknięcie cudzego id_token)", async () => {
  idTokenToServe = await googleIdToken({ nonce: "inny-nonce" });
  const secret = "browser-secret-value";
  const r = await hitCallback(await stateFor(secret, "gn-1"), `${LOGIN_COOKIE}=${secret}`);
  assert.equal(r.status, 400);
  assert.equal(r.issuedCode, null);
});

test("id_token bez nonce jest odrzucany", async () => {
  idTokenToServe = await googleIdToken({});
  const secret = "browser-secret-value";
  const r = await hitCallback(await stateFor(secret, "gn-1"), `${LOGIN_COOKIE}=${secret}`);
  assert.equal(r.status, 400);
  assert.equal(r.issuedCode, null);
});

test("obce konto Google jest odrzucane nawet przy poprawnym powiązaniu", async () => {
  idTokenToServe = await googleIdToken({ email: "attacker@example.com", nonce: "gn-1" });
  const secret = "browser-secret-value";
  const r = await hitCallback(await stateFor(secret), `${LOGIN_COOKIE}=${secret}`);
  assert.equal(r.status, 403);
  assert.equal(r.issuedCode, null);
});

test("email_verified=false jest odrzucane nawet przy poprawnym powiązaniu", async () => {
  idTokenToServe = await googleIdToken({ verified: false, nonce: "gn-1" });
  const secret = "browser-secret-value";
  const r = await hitCallback(await stateFor(secret), `${LOGIN_COOKIE}=${secret}`);
  assert.equal(r.status, 403);
  assert.equal(r.issuedCode, null);
});

test("każda ścieżka błędu czyści ciasteczko wiążące", async () => {
  idTokenToServe = await googleIdToken({ nonce: "gn-1" });
  const r = await hitCallback(await stateFor("x"));
  assert.match(r.setCookie, new RegExp(`${LOGIN_COOKIE}=;`));
  assert.match(r.setCookie, /Max-Age=0/);
});
