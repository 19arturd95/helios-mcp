import { test } from "node:test";
import assert from "node:assert/strict";

import {
  normalizePath,
  PathValidationError,
} from "../lib/security/paths";
import { loadAppsScript } from "./helpers/appsScript";

const gas = loadAppsScript();

test("poprawna ścieżka .md jest akceptowana i normalizowana", () => {
  assert.equal(normalizePath("20 Wiki/temat.md"), "20 Wiki/temat.md");
  assert.equal(normalizePath("./20 Wiki//temat.md"), "20 Wiki/temat.md");
  // Adapter (Code.gs) stosuje tę samą regułę.
  assert.equal(gas.pathSafe_("20 Wiki/temat.md"), "20 Wiki/temat.md");
});

test("path traversal jest odrzucany", () => {
  assert.throws(() => normalizePath("../secret.md"), PathValidationError);
  assert.throws(() => normalizePath("20 Wiki/../../etc/passwd.md"), PathValidationError);
  assert.throws(() => gas.pathSafe_("../secret.md"), /traversal/i);
});

test("zakodowany traversal (%2e%2e, podwójne kodowanie) jest odrzucany", () => {
  assert.throws(() => normalizePath("..%2f..%2fpasswd.md"), PathValidationError);
  assert.throws(() => normalizePath("%2e%2e/secret.md"), PathValidationError);
  assert.throws(() => normalizePath("%252e%252e/secret.md"), PathValidationError);
  assert.throws(() => gas.pathSafe_("..%2f..%2fpasswd.md"), /%/);
});

test("ścieżka absolutna = próba zapisu poza folderem — odrzucona", () => {
  assert.throws(() => normalizePath("/etc/passwd.md"), PathValidationError);
  assert.throws(() => normalizePath("C:\\Windows\\system.md"), PathValidationError);
  assert.throws(() => gas.pathSafe_("/etc/passwd.md"), /absolutne/i);
});

test("backslash i znaki sterujące są odrzucane", () => {
  assert.throws(() => normalizePath("20 Wiki\\temat.md"), PathValidationError);
  assert.throws(() => normalizePath("plik\u0000.md"), PathValidationError);
});

test("niedozwolone rozszerzenie jest odrzucane (domyślnie tylko .md)", () => {
  assert.throws(() => normalizePath("notatka.txt"), PathValidationError);
  assert.throws(() => normalizePath("skrypt.js"), PathValidationError);
  assert.throws(() => gas.pathSafe_("notatka.txt"), /rozszerzenie/i);
  // Foldery mogą nie mieć rozszerzenia, gdy requireExtension=false.
  assert.equal(normalizePath("00 Inbox", { requireExtension: false }), "00 Inbox");
});

test("Unicode jest normalizowany do NFC", () => {
  // 'é' jako U+0065 U+0301 (rozłożone) → NFC U+00E9
  const decomposed = "notatki/café.md";
  const out = normalizePath(decomposed);
  assert.equal(out, "notatki/café.md".normalize("NFC"));
});
