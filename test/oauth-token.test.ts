import { test } from "node:test";
import assert from "node:assert/strict";

import { issueAuthorizationCode } from "../lib/auth/tokens";
import { resetRateLimitState } from "../lib/security/rateLimit";
import { createFakeGasEnv, loadAppsScriptWithEnv, makeDeps } from "./helpers/appsScript";
import { POST as tokenPost } from "../app/oauth/token/route";

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
const APPS_SCRIPT_SECRET = process.env.APPS_SCRIPT_SECRET!;
const ALLOWED_EMAIL = process.env.ALLOWED_EMAIL!;
const RESOURCE = `${BASE_URL}/api/mcp`;

// verifier -> challenge = base64url(sha256(verifier)) — również użyte w test/auth.test.ts.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const CLIENT_ID = "client-abc";
const REDIRECT_URI = "https://client.example.com/cb";

/** Montuje fałszywy Helios Drive Adapter na globalnym `fetch`, wykonujący REALNY dispatch_ z Code.gs. */
function mountFakeAppsScript() {
  const env = createFakeGasEnv({ SHARED_SECRET: APPS_SCRIPT_SECRET });
  const gas = loadAppsScriptWithEnv(env);
  const original = globalThis.fetch;
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    const envelope = JSON.parse(String(init?.body));
    const verified = gas.verifyEnvelope_(envelope, makeDeps(APPS_SCRIPT_SECRET));
    if (!verified.ok) {
      return new Response(JSON.stringify({ ok: false, error: verified.error, code: verified.code }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    const request = JSON.parse(verified.payload!);
    try {
      const result = gas.dispatch_(request, env.props);
      return new Response(JSON.stringify({ ok: true, result }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      return new Response(JSON.stringify({ ok: false, error: (err as Error).message, code: "error" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
  }) as typeof fetch;
  return { restore: () => void (globalThis.fetch = original) };
}

async function makeCode(overrides: Partial<{ email: string; clientId: string; redirectUri: string; now: number; ttl: number }> = {}) {
  return issueAuthorizationCode(
    AUTH_SECRET,
    BASE_URL,
    {
      email: overrides.email ?? ALLOWED_EMAIL,
      clientId: overrides.clientId ?? CLIENT_ID,
      redirectUri: overrides.redirectUri ?? REDIRECT_URI,
      codeChallenge: CHALLENGE,
      scope: "helios.read",
      resource: RESOURCE,
    },
    overrides.ttl ?? 60,
    overrides.now,
  );
}

function tokenReq(fields: Record<string, string>): Request {
  const form = new URLSearchParams(fields);
  return new Request("https://helios.example.com/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": "203.0.113.30" },
    body: form.toString(),
  });
}

test("wymiana poprawnego kodu na access token (pełna pętla, w tym realny Code.gs consumeAuthCode)", async () => {
  resetRateLimitState();
  const fake = mountFakeAppsScript();
  try {
    const code = await makeCode();
    const res = await tokenPost(
      tokenReq({
        grant_type: "authorization_code",
        code,
        code_verifier: VERIFIER,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
      }),
    );
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.ok(body.access_token);
    assert.equal(body.token_type, "Bearer");
    assert.equal(body.expires_in, 3600);
  } finally {
    fake.restore();
  }
});

test("jednorazowość: druga wymiana TEGO SAMEGO kodu jest odrzucana (replay)", async () => {
  resetRateLimitState();
  const fake = mountFakeAppsScript();
  try {
    const code = await makeCode();
    const req = () =>
      tokenReq({
        grant_type: "authorization_code",
        code,
        code_verifier: VERIFIER,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
      });
    const first = await tokenPost(req());
    assert.equal(first.status, 200);
    const second = await tokenPost(req());
    const secondBody = await second.json();
    assert.equal(second.status, 400);
    assert.equal(secondBody.error, "invalid_grant");
    assert.match(secondBody.error_description, /wykorzystany/);
  } finally {
    fake.restore();
  }
});

test("brak client_id jest odrzucany", async () => {
  resetRateLimitState();
  const code = await makeCode();
  const res = await tokenPost(
    tokenReq({ grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT_URI }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_request");
});

test("brak redirect_uri jest odrzucany", async () => {
  resetRateLimitState();
  const code = await makeCode();
  const res = await tokenPost(
    tokenReq({ grant_type: "authorization_code", code, code_verifier: VERIFIER, client_id: CLIENT_ID }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_request");
});

test("niedopasowany client_id jest odrzucany", async () => {
  resetRateLimitState();
  const code = await makeCode();
  const res = await tokenPost(
    tokenReq({
      grant_type: "authorization_code",
      code,
      code_verifier: VERIFIER,
      client_id: "inny-klient",
      redirect_uri: REDIRECT_URI,
    }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_grant");
});

test("niedopasowany redirect_uri jest odrzucany", async () => {
  resetRateLimitState();
  const code = await makeCode();
  const res = await tokenPost(
    tokenReq({
      grant_type: "authorization_code",
      code,
      code_verifier: VERIFIER,
      client_id: CLIENT_ID,
      redirect_uri: "https://inny-host.example.com/cb",
    }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_grant");
});

test("błędny code_verifier (PKCE) jest odrzucany", async () => {
  resetRateLimitState();
  const code = await makeCode();
  const res = await tokenPost(
    tokenReq({
      grant_type: "authorization_code",
      code,
      code_verifier: "zupelnie-zly-verifier-000000000000000000",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_grant");
});

test("błędny grant_type jest odrzucany", async () => {
  resetRateLimitState();
  const code = await makeCode();
  const res = await tokenPost(
    tokenReq({
      grant_type: "client_credentials",
      code,
      code_verifier: VERIFIER,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "unsupported_grant_type");
});

test("wygasły kod autoryzacyjny jest odrzucany", async () => {
  resetRateLimitState();
  const now = Math.floor(Date.now() / 1000);
  const code = await makeCode({ now: now - 1000, ttl: 5 });
  const res = await tokenPost(
    tokenReq({
      grant_type: "authorization_code",
      code,
      code_verifier: VERIFIER,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    }),
  );
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, "invalid_grant");
});

test("konto inne niż ALLOWED_EMAIL jest odrzucane (obrona w głąb, niezależnie od Apps Script)", async () => {
  resetRateLimitState();
  const code = await makeCode({ email: "ktos.inny@example.com" });
  const res = await tokenPost(
    tokenReq({
      grant_type: "authorization_code",
      code,
      code_verifier: VERIFIER,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    }),
  );
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, "access_denied");
});

test("niedostępność Helios Drive Adapter powoduje bezpieczną odmowę (fail-closed), nie wyciek sekretu", async () => {
  resetRateLimitState();
  const original = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new Error("ECONNREFUSED");
  }) as typeof fetch;
  try {
    const code = await makeCode();
    const res = await tokenPost(
      tokenReq({
        grant_type: "authorization_code",
        code,
        code_verifier: VERIFIER,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
      }),
    );
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.error, "temporarily_unavailable");
    assert.doesNotMatch(JSON.stringify(body), new RegExp(APPS_SCRIPT_SECRET));
  } finally {
    globalThis.fetch = original;
  }
});
