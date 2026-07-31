import { test } from "node:test";
import assert from "node:assert/strict";

import {
  issueClientId,
  verifyClientId,
  issueConsentToken,
  verifyConsentToken,
  issueAuthorizationCode,
  verifyAuthorizationCode,
} from "../lib/auth/tokens";
import { testConfig } from "./helpers/config";

const cfg = testConfig();

test("client_id (DCR) koduje redirect_uris i wygasa po TTL", async () => {
  const now = 1_720_000_000;
  const clientId = await issueClientId(
    cfg.authSecret,
    cfg.baseUrl,
    { redirectUris: ["https://client.example.com/cb"], clientName: "Test Client" },
    3600,
    now,
  );
  const meta = await verifyClientId(cfg.authSecret, cfg.baseUrl, clientId, now + 100);
  assert.deepEqual(meta.redirectUris, ["https://client.example.com/cb"]);
  assert.equal(meta.clientName, "Test Client");

  // Po wygaśnięciu (exp = now + 3600) weryfikacja musi rzucić.
  await assert.rejects(() => verifyClientId(cfg.authSecret, cfg.baseUrl, clientId, now + 3601));
});

test("client_id podpisany innym sekretem jest odrzucany", async () => {
  const clientId = await issueClientId(cfg.authSecret, cfg.baseUrl, { redirectUris: ["https://a.example/cb"] });
  await assert.rejects(() => verifyClientId("zupelnie-inny-sekret-0000000000", cfg.baseUrl, clientId));
});

test("token zgody (consent) niesie dane klienta i wygasa", async () => {
  const now = 1_720_000_000;
  const token = await issueConsentToken(
    cfg.authSecret,
    cfg.baseUrl,
    {
      clientId: "client-abc",
      clientName: "Demo App",
      redirectUri: "https://client.example.com/cb",
      codeChallenge: "challenge-xyz",
      scope: "helios.read",
      resource: `${cfg.baseUrl}/api/mcp`,
      state: "original-state",
    },
    300,
    now,
  );
  const claims = await verifyConsentToken(cfg.authSecret, cfg.baseUrl, token, now + 100);
  assert.equal(claims.clientId, "client-abc");
  assert.equal(claims.clientName, "Demo App");
  assert.equal(claims.redirectUri, "https://client.example.com/cb");
  assert.equal(claims.state, "original-state");

  await assert.rejects(() => verifyConsentToken(cfg.authSecret, cfg.baseUrl, token, now + 301));
});

test("token zgody nie może zostać zmodyfikowany bez unieważnienia podpisu", async () => {
  const now = 1_720_000_000;
  const token = await issueConsentToken(
    cfg.authSecret,
    cfg.baseUrl,
    {
      clientId: "client-abc",
      clientName: "Demo App",
      redirectUri: "https://client.example.com/cb",
      codeChallenge: "challenge-xyz",
      scope: "helios.read",
      resource: `${cfg.baseUrl}/api/mcp`,
      state: "original-state",
    },
    300,
    now,
  );
  // Podmiana środkowego segmentu (payload) JWT — musi unieważnić podpis.
  const parts = token.split(".");
  const tamperedPayload = Buffer.from(JSON.stringify({ clientId: "attacker-client", redirectUri: "https://evil.example/cb" }))
    .toString("base64url");
  const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
  await assert.rejects(() => verifyConsentToken(cfg.authSecret, cfg.baseUrl, tampered, now));
});

test("kod autoryzacyjny niesie jti i exp niezbędne do jednorazowości", async () => {
  const now = 1_720_000_000;
  const code = await issueAuthorizationCode(
    cfg.authSecret,
    cfg.baseUrl,
    {
      email: cfg.allowedEmail,
      clientId: "client-abc",
      redirectUri: "https://client.example.com/cb",
      codeChallenge: "challenge-xyz",
      scope: "helios.read",
      resource: `${cfg.baseUrl}/api/mcp`,
    },
    60,
    now,
  );
  const claims = await verifyAuthorizationCode(cfg.authSecret, cfg.baseUrl, code, now + 10);
  assert.ok(claims.jti, "jti powinien być obecny");
  assert.equal(claims.jti.length >= 16, true);
  assert.equal(claims.exp, now + 60);
});

test("dwa kody autoryzacyjne mają różne jti (losowość)", async () => {
  const now = 1_720_000_000;
  const claims = {
    email: cfg.allowedEmail,
    clientId: "client-abc",
    redirectUri: "https://client.example.com/cb",
    codeChallenge: "challenge-xyz",
    scope: "helios.read",
    resource: `${cfg.baseUrl}/api/mcp`,
  };
  const codeA = await issueAuthorizationCode(cfg.authSecret, cfg.baseUrl, claims, 60, now);
  const codeB = await issueAuthorizationCode(cfg.authSecret, cfg.baseUrl, claims, 60, now);
  const a = await verifyAuthorizationCode(cfg.authSecret, cfg.baseUrl, codeA, now);
  const b = await verifyAuthorizationCode(cfg.authSecret, cfg.baseUrl, codeB, now);
  assert.notEqual(a.jti, b.jti);
});

test("wygasły kod autoryzacyjny jest odrzucany", async () => {
  const now = 1_720_000_000;
  const code = await issueAuthorizationCode(
    cfg.authSecret,
    cfg.baseUrl,
    {
      email: cfg.allowedEmail,
      clientId: "client-abc",
      redirectUri: "https://client.example.com/cb",
      codeChallenge: "challenge-xyz",
      scope: "helios.read",
      resource: `${cfg.baseUrl}/api/mcp`,
    },
    60,
    now,
  );
  await assert.rejects(() => verifyAuthorizationCode(cfg.authSecret, cfg.baseUrl, code, now + 61));
});
