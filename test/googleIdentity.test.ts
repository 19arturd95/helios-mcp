import { test } from "node:test";
import assert from "node:assert/strict";

import { evaluateGoogleIdentity } from "../lib/auth/googleIdentity";

const ALLOWED = "me@example.com";

test("konto z ALLOWED_EMAIL i email_verified=true jest dozwolone", () => {
  const res = evaluateGoogleIdentity({ email: "ME@example.com", email_verified: true }, ALLOWED);
  assert.equal(res.allowed, true);
  assert.equal(res.email, "me@example.com");
});

test("email_verified=false jest odrzucany, nawet dla ALLOWED_EMAIL", () => {
  const res = evaluateGoogleIdentity({ email: ALLOWED, email_verified: false }, ALLOWED);
  assert.equal(res.allowed, false);
});

test("brak pola email_verified (undefined) jest traktowany jak niezweryfikowany", () => {
  const res = evaluateGoogleIdentity({ email: ALLOWED }, ALLOWED);
  assert.equal(res.allowed, false);
});

test("konto inne niż ALLOWED_EMAIL jest odrzucane", () => {
  const res = evaluateGoogleIdentity({ email: "ktos.inny@example.com", email_verified: true }, ALLOWED);
  assert.equal(res.allowed, false);
});

test("brak pola email jest odrzucany", () => {
  const res = evaluateGoogleIdentity({ email_verified: true }, ALLOWED);
  assert.equal(res.allowed, false);
});
