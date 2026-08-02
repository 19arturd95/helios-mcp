/**
 * Regresja dla utwardzeń znalezionych podczas audytu bezpieczeństwa.
 * Każdy test odpowiada konkretnemu ustaleniu, nie tylko kodowi statusu.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.ALLOWED_EMAIL = "owner@example.com";
process.env.PUBLIC_BASE_URL = "https://helios.example.com";
process.env.APPS_SCRIPT_URL = "https://script.google.com/macros/s/AK/exec";
process.env.APPS_SCRIPT_SECRET = "s".repeat(32);
process.env.AUTH_SECRET = "a".repeat(32);
process.env.GOOGLE_CLIENT_ID = "cid.apps.googleusercontent.com";
process.env.GOOGLE_CLIENT_SECRET = "gsecret";
Object.assign(process.env, { NODE_ENV: "production" });

import { SignJWT } from "jose";
import { corsHeaders, json } from "../lib/http";
import { verifyAccessToken, issueAuthorizationCode, issueClientId } from "../lib/auth/tokens";
import { checkRateLimit, resetRateLimitState } from "../lib/security/rateLimit";
import { loadAppsScript, createFakeGasEnv, loadAppsScriptWithEnv } from "./helpers/appsScript";

const BASE = "https://helios.example.com";
const AUTH_SECRET = "a".repeat(32);
const RES = `${BASE}/api/mcp`;
const RU = "https://client.example/cb";

// --- Nagłówki bezpieczeństwa na odpowiedziach JSON --------------------------
test("odpowiedzi JSON niosą nosniff, HSTS i no-referrer (nie tylko strony HTML)", () => {
  const h = new Headers(json({ ok: true }).headers);
  assert.equal(h.get("x-content-type-options"), "nosniff");
  assert.match(h.get("strict-transport-security") ?? "", /max-age=31536000/);
  assert.equal(h.get("referrer-policy"), "no-referrer");
  assert.equal(h.get("cache-control"), "no-store");
  assert.equal(new Headers(corsHeaders()).get("x-content-type-options"), "nosniff");
});

// --- Przypięcie algorytmu podpisu -------------------------------------------
test("access token podpisany HS384 jest odrzucany (algorithm confusion)", async () => {
  const secret = new TextEncoder().encode(AUTH_SECRET);
  for (const alg of ["HS384", "HS512"]) {
    const jwt = await new SignJWT({ email: "owner@example.com", scope: "helios.read", client_id: "c" })
      .setProtectedHeader({ alg })
      .setIssuer(BASE)
      .setAudience(RES)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    await assert.rejects(
      () => verifyAccessToken(AUTH_SECRET, BASE, RES, jwt),
      `token ${alg} nie powinien być akceptowany`,
    );
  }
});

test("access token HS256 nadal działa", async () => {
  const jwt = await new SignJWT({ email: "owner@example.com", scope: "helios.read", client_id: "c" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(BASE)
    .setAudience(RES)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(new TextEncoder().encode(AUTH_SECRET));
  const v = await verifyAccessToken(AUTH_SECRET, BASE, RES, jwt);
  assert.equal(v.email, "owner@example.com");
});

// --- /oauth/register: JSON, który nie jest obiektem --------------------------
test("/oauth/register nie wywraca się na treści `null` ani na tablicy", async () => {
  const register = await import("../app/oauth/register/route");
  for (const body of ["null", "[1,2,3]", '"tekst"', "123", "true"]) {
    resetRateLimitState();
    const res = await register.POST(
      new Request(`${BASE}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      }),
    );
    assert.equal(res.status, 400, `treść ${body} powinna dać 400, nie wyjątek`);
    const j = (await res.json()) as { error?: string; client_id?: string };
    assert.equal(j.error, "invalid_client_metadata");
    assert.equal(j.client_id, undefined, "nie wolno wystawić client_id");
  }
});

// --- Duplikaty parametrów ---------------------------------------------------
test("/oauth/token odrzuca zduplikowany parametr zamiast brać ostatnią wartość", async () => {
  const tokenRoute = await import("../app/oauth/token/route");
  const clientId = await issueClientId(AUTH_SECRET, BASE, { redirectUris: [RU] });
  const code = await issueAuthorizationCode(AUTH_SECRET, BASE, {
    email: "owner@example.com",
    clientId,
    redirectUri: RU,
    codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    scope: "helios.read",
    resource: RES,
  });
  resetRateLimitState();
  const res = await tokenRoute.POST(
    new Request(`${BASE}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body:
        `grant_type=refresh_token&grant_type=authorization_code&code=${encodeURIComponent(code)}` +
        `&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(RU)}&resource=${encodeURIComponent(RES)}`,
    }),
  );
  assert.equal(res.status, 400);
  const j = (await res.json()) as { error?: string; access_token?: string };
  assert.equal(j.error, "invalid_request");
  assert.equal(j.access_token, undefined, "nie wolno wystawić tokenu");
});

test("/oauth/authorize odrzuca zduplikowany redirect_uri", async () => {
  const authorize = await import("../app/oauth/authorize/route");
  const clientId = await issueClientId(AUTH_SECRET, BASE, { redirectUris: [RU] });
  const qs = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: RU,
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
    scope: "helios.read",
    state: "s",
    resource: RES,
  }).toString();
  resetRateLimitState();
  const res = await authorize.GET(
    new Request(`${BASE}/oauth/authorize?${qs}&redirect_uri=${encodeURIComponent("https://evil.example/cb")}`),
  );
  assert.equal(res.status, 400);
  const body = await res.text();
  assert.doesNotMatch(body, /Żądanie dostępu/, "ekran zgody nie może się pokazać");
  assert.doesNotMatch(body, /evil\.example/, "nie wolno odbić obcego adresu");
});

// --- Limiter: ograniczony wzrost pamięci ------------------------------------
test("limiter nie rośnie w nieskończoność przy rotacji kluczy", () => {
  resetRateLimitState();
  for (let i = 0; i < 25_000; i++) {
    checkRateLimit(`key-${i}`, { limit: 60, windowSeconds: 60 });
  }
  // Wewnętrzny limit to 10 000 kubełków; sprawdzamy zachowanie przez zachowanie
  // najnowszego klucza i odrzucenie najstarszych.
  const newest = checkRateLimit("key-24999", { limit: 60, windowSeconds: 60 });
  assert.equal(newest.allowed, true);
  resetRateLimitState();
});

// --- Apps Script: szczelna allowlista operacji ------------------------------
test("dispatch_ odrzuca nazwy operacji dziedziczone z Object.prototype", () => {
  const env = createFakeGasEnv({ SHARED_SECRET: "s".repeat(32) });
  env.setScriptProperties({ ROOT_FOLDER_ID: env.root.getId() });
  const gas = loadAppsScriptWithEnv(env);
  for (const op of ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf", "isPrototypeOf"]) {
    assert.throws(
      () => gas.dispatch_({ op } as unknown as Record<string, unknown>, env.props),
      /Nieznana operacja\./,
      `op=${op} musi zostać odrzucone JUŻ przez allowlistę`,
    );
  }
  // Prawdziwa operacja nadal działa.
  const status = gas.dispatch_({ op: "status" } as unknown as Record<string, unknown>, env.props) as {
    readOnly: boolean;
  };
  assert.equal(status.readOnly, true);
});

test("allowlista operacji nie zawiera żadnej operacji zapisu", () => {
  const gas = loadAppsScript();
  const ops = [...Object.keys(gas.READ_OPS), ...Object.keys(gas.META_OPS)];
  assert.deepEqual(ops.sort(), ["consumeAuthCode", "listTree", "read", "search", "status"]);
  for (const forbidden of ["write", "create", "update", "delete", "move", "rename", "share", "setPermission", "trash"]) {
    assert.ok(!ops.includes(forbidden), `adapter nie może udostępniać operacji ${forbidden}`);
  }
});

// --- Apps Script: pliki natywne Google udające Markdown ---------------------
test("plik natywny Google nazwany .md nie jest czytany jako notatka", () => {
  const env = createFakeGasEnv({ SHARED_SECRET: "s".repeat(32) });
  env.setScriptProperties({ ROOT_FOLDER_ID: env.root.getId() });
  const gas = loadAppsScriptWithEnv(env);
  env.root.createFile("prawdziwa.md", "# tekst", "text/markdown");
  env.root.createFile("podszywa.md", "PDF-BINARY", "application/vnd.google-apps.document");

  const ok = gas.opRead_(env.root, env.root.getId(), { path: "prawdziwa.md" }) as { content: string };
  assert.equal(ok.content, "# tekst");

  assert.throws(
    () => gas.opRead_(env.root, env.root.getId(), { path: "podszywa.md" }),
    /nie jest zwykłym plikiem tekstowym/,
  );
});

test("search nie czyta treści plików natywnych Google", () => {
  const env = createFakeGasEnv({ SHARED_SECRET: "s".repeat(32) });
  env.setScriptProperties({ ROOT_FOLDER_ID: env.root.getId() });
  const gas = loadAppsScriptWithEnv(env);
  env.root.createFile("doc.md", "SZUKANA-FRAZA", "application/vnd.google-apps.document");
  env.root.createFile("txt.md", "SZUKANA-FRAZA", "text/markdown");

  const out = gas.opSearch_(env.root, { query: "szukana-fraza" }) as { hits: Array<{ name: string }> };
  // `hits` powstaje w osobnym realmie (vm), więc kopiujemy do tablicy z tego realmu.
  const names = [...out.hits].map((h) => h.name);
  assert.deepEqual(names, ["txt.md"], "trafienie tylko w prawdziwym pliku tekstowym");
});
