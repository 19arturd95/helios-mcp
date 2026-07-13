import { test } from "node:test";
import assert from "node:assert/strict";

import { signPayload, canonicalString, hmacSha256Base64 } from "../lib/security/signing.js";
import { loadAppsScript, makeDeps } from "./helpers/appsScript.js";

const gas = loadAppsScript();
const SECRET = "shared-secret-abcdefghijklmnop";

test("kanoniczna postać jest identyczna po obu stronach (MCP i adapter)", () => {
  const ts = 1_720_000_000;
  const nonce = "abc123";
  const payload = '{"op":"read","path":"index.md"}';
  assert.equal(canonicalString(ts, nonce, payload), gas.canonicalString_(ts, nonce, payload));
});

test("podpis WebCrypto = podpis Node crypto dla tej samej wiadomości", async () => {
  const msg = "1720000000\nnonce\n{\"op\":\"status\"}";
  const web = await hmacSha256Base64(SECRET, msg);
  const deps = makeDeps(SECRET);
  const node = deps.hmacBase64(SECRET, msg);
  assert.equal(web, node);
});

test("poprawnie podpisana koperta przechodzi weryfikację adaptera", async () => {
  const now = 1_720_000_000;
  const payload = '{"op":"read","path":"20 Wiki/temat.md"}';
  const env = await signPayload(SECRET, payload, { timestamp: now });
  const res = gas.verifyEnvelope_(env, makeDeps(SECRET, { now }));
  assert.equal(res.ok, true);
  assert.equal(res.payload, payload);
});

test("błędny HMAC jest odrzucany", async () => {
  const now = 1_720_000_000;
  const env = await signPayload(SECRET, '{"op":"status"}', { timestamp: now });
  // Manipulacja treścią po podpisaniu → podpis nie pasuje.
  const tampered = { ...env, payload: '{"op":"read","path":"secret.md"}' };
  const res = gas.verifyEnvelope_(tampered, makeDeps(SECRET, { now }));
  assert.equal(res.ok, false);
  assert.equal(res.code, "bad_signature");
});

test("zły sekret = błędny podpis", async () => {
  const now = 1_720_000_000;
  const env = await signPayload("inny-sekret-1234567890", '{"op":"status"}', { timestamp: now });
  const res = gas.verifyEnvelope_(env, makeDeps(SECRET, { now }));
  assert.equal(res.ok, false);
  assert.equal(res.code, "bad_signature");
});

test("stary timestamp (poza oknem 5 min) jest odrzucany", async () => {
  const signedAt = 1_720_000_000;
  const env = await signPayload(SECRET, '{"op":"status"}', { timestamp: signedAt });
  // Adapter widzi czas 301 s później.
  const res = gas.verifyEnvelope_(env, makeDeps(SECRET, { now: signedAt + 301 }));
  assert.equal(res.ok, false);
  assert.equal(res.code, "stale");
});

test("ponowne użycie nonce jest odrzucane (replay)", async () => {
  const now = 1_720_000_000;
  const env = await signPayload(SECRET, '{"op":"status"}', { timestamp: now });
  const deps = makeDeps(SECRET, { now });
  const first = gas.verifyEnvelope_(env, deps);
  assert.equal(first.ok, true);
  const second = gas.verifyEnvelope_(env, deps);
  assert.equal(second.ok, false);
  assert.equal(second.code, "replay");
});
