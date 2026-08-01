import { test } from "node:test";
import assert from "node:assert/strict";

import { handleGetContext, handleInboxStatus, makeToolContext, handleReadNote, handleStatus } from "../lib/tools/handlers";
import { DriveAdapterError } from "../lib/drive/client";
import type { ReadResult, StatusResult } from "../lib/drive/types";
import { loadAppsScript, makeDeps } from "./helpers/appsScript";
import { testConfig } from "./helpers/config";

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
        readOnly: true,
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
  assert.equal("id" in res, false, "publiczny wynik MCP nie powinien ujawniać ID pliku Drive");
});

test("helios_status przechodzi przez podpisany kanał", async () => {
  const cfg = testConfig();
  const ctx = makeToolContext(cfg, fakeAdapterFetch(cfg.appsScriptSecret));
  const res = await handleStatus(ctx);
  assert.equal(res.ok, true);
  assert.equal(res.rootName, "helios");
  assert.equal(res.readOnly, true);
  assert.equal("rootId" in res, false, "status MCP nie powinien ujawniać ID folderu Drive");
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

test("awaria adaptera nie jest maskowana jako pusty Inbox lub brak plików systemowych", async () => {
  const cfg = testConfig();
  const ctx = {
    config: cfg,
    call: async () => {
      throw new DriveAdapterError("Nie udało się połączyć z Helios Drive Adapter.", "network");
    },
  };
  await assert.rejects(() => handleInboxStatus(ctx), /Nie udało się połączyć/);
  await assert.rejects(
    () => handleGetContext(ctx, { rawText: "test" }),
    /Nie udało się połączyć/,
  );
});

test("brak folderu Inbox nadal daje bezpieczny pusty wynik", async () => {
  const cfg = testConfig();
  const ctx = {
    config: cfg,
    call: async () => {
      throw new DriveAdapterError("Folder nie istnieje.", "error");
    },
  };
  const result = await handleInboxStatus(ctx);
  assert.equal(result.entryCount, 0);
  assert.deepEqual(result.entries, []);
});
