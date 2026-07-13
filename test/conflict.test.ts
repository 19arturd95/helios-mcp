import { test } from "node:test";
import assert from "node:assert/strict";

import { assertNoVersionConflict, VersionConflictError } from "../lib/security/conflict.js";

test("zgodny modifiedTime nie powoduje konfliktu", () => {
  const t = "2026-07-13T10:00:00.000Z";
  assert.doesNotThrow(() => assertNoVersionConflict("a.md", t, t));
  // Ten sam moment zapisany inaczej (offset) też jest OK.
  assert.doesNotThrow(() =>
    assertNoVersionConflict("a.md", "2026-07-13T12:00:00.000+02:00", "2026-07-13T10:00:00.000Z"),
  );
});

test("różny modifiedTime = konflikt wersji (przerwanie zapisu)", () => {
  assert.throws(
    () => assertNoVersionConflict("a.md", "2026-07-13T10:00:00.000Z", "2026-07-13T10:05:00.000Z"),
    VersionConflictError,
  );
});

test("brak expectedModifiedTime przy aktualizacji = konflikt", () => {
  assert.throws(
    () => assertNoVersionConflict("a.md", undefined, "2026-07-13T10:00:00.000Z"),
    VersionConflictError,
  );
});

test("nieparsowalny czas jest traktowany jak konflikt (bezpieczeństwo)", () => {
  assert.throws(
    () => assertNoVersionConflict("a.md", "not-a-date", "2026-07-13T10:00:00.000Z"),
    VersionConflictError,
  );
});
