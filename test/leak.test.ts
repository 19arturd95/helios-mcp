import { test } from "node:test";
import assert from "node:assert/strict";

import { loadConfig } from "../lib/config";
import { callAdapter, DriveAdapterError } from "../lib/drive/client";
import { signPayload } from "../lib/security/signing";

const FULL_ENV = {
  ALLOWED_EMAIL: "me@example.com",
  PUBLIC_BASE_URL: "https://helios.example.com",
  APPS_SCRIPT_URL: "https://script.google.com/macros/s/AK/exec",
  APPS_SCRIPT_SECRET: "s".repeat(32),
  AUTH_SECRET: "a".repeat(32),
  GOOGLE_CLIENT_ID: "cid.apps.googleusercontent.com",
  GOOGLE_CLIENT_SECRET: "google-secret-value-xyz",
};

test("brak zmiennych → błąd wymienia NAZWY, nie wartości", () => {
  try {
    loadConfig({});
    assert.fail("powinno rzucić");
  } catch (err) {
    const msg = (err as Error).message;
    assert.match(msg, /ALLOWED_EMAIL/);
    assert.match(msg, /APPS_SCRIPT_SECRET/);
    assert.match(msg, /GOOGLE_CLIENT_SECRET/);
  }
});

test("zbyt krótki sekret → błąd nie ujawnia jego wartości", () => {
  const env = { ...FULL_ENV, APPS_SCRIPT_SECRET: "krotki" };
  try {
    loadConfig(env);
    assert.fail("powinno rzucić");
  } catch (err) {
    const msg = (err as Error).message;
    assert.doesNotMatch(msg, /krotki/);
  }
});

test("produkcyjny PUBLIC_BASE_URL bez HTTPS jest odrzucany", () => {
  assert.throws(
    () => loadConfig({ ...FULL_ENV, PUBLIC_BASE_URL: "http://helios.example.com", NODE_ENV: "production" }),
    /HTTPS/,
  );
});

test("APPS_SCRIPT_URL spoza oficjalnego hosta wdrożeń jest odrzucany", () => {
  assert.throws(
    () => loadConfig({ ...FULL_ENV, APPS_SCRIPT_URL: "https://evil.example.com/macros/s/AK/exec" }),
    /APPS_SCRIPT_URL/,
  );
});

test("błąd sieci klienta adaptera nie ujawnia sekretu", async () => {
  const secret = "super-tajny-sekret-do-nie-wycieku-123";
  const throwingFetch = (async () => {
    throw new Error(`ECONNREFUSED body contained ${secret}`);
  }) as unknown as typeof fetch;

  await assert.rejects(
    () =>
      callAdapter(
        { appsScriptUrl: "https://x/exec", appsScriptSecret: secret, fetchImpl: throwingFetch },
        "status",
      ),
    (err: unknown) => {
      assert.ok(err instanceof DriveAdapterError);
      assert.doesNotMatch((err as Error).message, new RegExp(secret));
      return true;
    },
  );
});

test("koperta na sieci zawiera podpis, ale nie sam sekret", async () => {
  const secret = "sekret-ktory-nie-moze-wyciec-abcdef";
  const env = await signPayload(secret, '{"op":"status"}');
  const wire = JSON.stringify(env);
  assert.doesNotMatch(wire, new RegExp(secret));
  assert.ok(env.signature.length > 0);
});
