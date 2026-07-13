import { test } from "node:test";
import assert from "node:assert/strict";

import { makeToolContext, handleReadNote, handleStatus } from "../lib/tools/handlers.js";
import type { ReadResult, StatusResult } from "../lib/drive/types.js";
import { loadAppsScript, makeDeps } from "./helpers/appsScript.js";
import { testConfig } from "./helpers/config.js";

const gas = loadAppsScript();

/**
 * Fałszywy Apps Script: weryfikuje podpisaną kopertę REALNĄ funkcją z Code.gs,
 * a następnie zwraca dane. Dzięki temu "poprawny odczyt" testuje pełną pętlę
 * podpis → weryfikacja → odpowiedź.
 */
function fakeAdapterFetch(secret: string): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    const envelope = JSON.parse(String(init.body));
    const verified = gas.verifyEnvelope_(envelope, makeDeps(secret));
    if (!verified.ok) {
      return new Response(JSON.stringify({ ok: false, error: verified.error, code: verified.code }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    const request = JSON.parse(verified.payload!);
    if (request.op === "status") {
      const result: StatusResult = {
        ok: true,
        rootId: "root-1",
        rootName: "helios",
        serverTime: "2026-07-13T10:00:00.000Z",
        writeEnabled: false,
      };
      return new Response(JSON.stringify({ ok: true, result }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (request.op === "read") {
      const result: ReadResult = {
        path: request.path,
        id: "file-1",
        name: "temat.md",
        modifiedTime: "2026-07-13T09:00:00.000Z",
        content: "# Temat\nTreść notatki.",
      };
      return new Response(JSON.stringify({ ok: true, result }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ ok: false, error: "unknown" }), { status: 200 });
  }) as unknown as typeof fetch;
}

test("poprawny odczyt: podpisane żądanie jest zaakceptowane i zwraca treść", async () => {
  const cfg = testConfig();
  const ctx = makeToolContext(cfg, fakeAdapterFetch(cfg.appsScriptSecret));
  const res = await handleReadNote(ctx, { path: "20 Wiki/temat.md" });
  assert.equal(res.path, "20 Wiki/temat.md");
  assert.match(res.content, /Treść notatki/);
  assert.equal(res.modifiedTime, "2026-07-13T09:00:00.000Z");
});

test("helios_status przechodzi przez podpisany kanał", async () => {
  const cfg = testConfig();
  const ctx = makeToolContext(cfg, fakeAdapterFetch(cfg.appsScriptSecret));
  const res = await handleStatus(ctx);
  assert.equal(res.ok, true);
  assert.equal(res.rootName, "helios");
  assert.equal(res.writeEnabled, false);
});

test("odczyt z niedozwoloną ścieżką jest odrzucany zanim wyjdzie w sieć", async () => {
  const cfg = testConfig();
  let called = false;
  const guardFetch = (async () => {
    called = true;
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  const ctx = makeToolContext(cfg, guardFetch);
  await assert.rejects(() => handleReadNote(ctx, { path: "../../secret.md" }));
  assert.equal(called, false, "żądanie nie powinno trafić do adaptera");
});
