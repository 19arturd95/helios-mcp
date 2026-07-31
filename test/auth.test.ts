import { test } from "node:test";
import assert from "node:assert/strict";

import { mcpResourceUrl } from "../lib/config";
import { issueAccessToken, verifyPkceS256 } from "../lib/auth/tokens";
import { verifyMcpBearer } from "../lib/auth/verifyToken";
import { testConfig } from "./helpers/config";

const cfg = testConfig();
const audience = mcpResourceUrl(cfg.baseUrl);

async function tokenFor(email: string): Promise<string> {
  return issueAccessToken({
    authSecret: cfg.authSecret,
    issuer: cfg.baseUrl,
    audience,
    email,
    clientId: "client-xyz",
    scope: "helios.read",
  });
}

test("brak tokenu OAuth → odmowa (undefined)", async () => {
  assert.equal(await verifyMcpBearer(undefined, cfg), undefined);
  assert.equal(await verifyMcpBearer("", cfg), undefined);
});

test("błędny token → odmowa", async () => {
  assert.equal(await verifyMcpBearer("to.nie.jest.jwt", cfg), undefined);
});

test("dozwolony ALLOWED_EMAIL → dostęp", async () => {
  const token = await tokenFor(cfg.allowedEmail);
  const info = await verifyMcpBearer(token, cfg);
  assert.ok(info);
  assert.equal(info?.extra?.email, cfg.allowedEmail);
  assert.deepEqual(info?.scopes, ["helios.read"]);
});

test("inny adres e-mail → odmowa, nawet z ważnym podpisem", async () => {
  const token = await tokenFor("ktos.inny@example.com");
  assert.equal(await verifyMcpBearer(token, cfg), undefined);
});

test("token dla złego audience/issuer → odmowa", async () => {
  const wrongAud = await issueAccessToken({
    authSecret: cfg.authSecret,
    issuer: cfg.baseUrl,
    audience: "https://zly.example.com/api/mcp",
    email: cfg.allowedEmail,
    clientId: "c",
    scope: "helios.read",
  });
  assert.equal(await verifyMcpBearer(wrongAud, cfg), undefined);
});

test("token podpisany innym sekretem → odmowa", async () => {
  const forged = await issueAccessToken({
    authSecret: "zupelnie-inny-sekret-0000000000000000",
    issuer: cfg.baseUrl,
    audience,
    email: cfg.allowedEmail,
    clientId: "c",
    scope: "helios.read",
  });
  assert.equal(await verifyMcpBearer(forged, cfg), undefined);
});

test("token bez scope helios.read jest odrzucany", async () => {
  const wrongScope = await issueAccessToken({
    authSecret: cfg.authSecret,
    issuer: cfg.baseUrl,
    audience,
    email: cfg.allowedEmail,
    clientId: "c",
    scope: "helios.write",
  });
  assert.equal(await verifyMcpBearer(wrongScope, cfg), undefined);
});

test("PKCE S256 działa poprawnie", async () => {
  // verifier → challenge = base64url(sha256(verifier))
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  assert.equal(await verifyPkceS256(verifier, challenge), true);
  assert.equal(await verifyPkceS256(verifier, "zle-wyzwanie"), false);
  assert.equal(await verifyPkceS256("za-krotki", challenge), false);
});
