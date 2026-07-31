import { test } from "node:test";
import assert from "node:assert/strict";

import { checkRateLimit, hashRateLimitKey, enforceRateLimit, resetRateLimitState } from "../lib/security/rateLimit";

test("checkRateLimit dopuszcza żądania do limitu, potem blokuje", () => {
  resetRateLimitState();
  const key = "test-key-1";
  for (let i = 0; i < 3; i++) {
    const r = checkRateLimit(key, { limit: 3, windowSeconds: 60 });
    assert.equal(r.allowed, true, `żądanie ${i + 1} powinno przejść`);
  }
  const blocked = checkRateLimit(key, { limit: 3, windowSeconds: 60 });
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterSeconds > 0);
});

test("hashRateLimitKey nigdy nie zawiera surowych identyfikatorów w postaci jawnej", async () => {
  const email = "sekretny.adres@example.com";
  const ip = "203.0.113.7";
  const key = await hashRateLimitKey("api_mcp", ip, email);
  assert.doesNotMatch(key, /sekretny/);
  assert.doesNotMatch(key, new RegExp(ip.replace(/\./g, "\\.")));
  assert.match(key, /^[0-9a-f]{32}$/);
});

test("hashRateLimitKey jest deterministyczny i zależny od wszystkich części", async () => {
  const a = await hashRateLimitKey("route", "1.2.3.4", "extra");
  const b = await hashRateLimitKey("route", "1.2.3.4", "extra");
  const c = await hashRateLimitKey("route", "1.2.3.4", "inny");
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test("enforceRateLimit zwraca 429 z Retry-After po przekroczeniu limitu", async () => {
  resetRateLimitState();
  const req = new Request("https://helios.example.com/oauth/register", {
    method: "POST",
    headers: { "x-forwarded-for": "198.51.100.9" },
  });
  for (let i = 0; i < 2; i++) {
    const res = await enforceRateLimit(req, { name: "smoke_test_route", limit: 2, windowSeconds: 60 });
    assert.equal(res, null, `żądanie ${i + 1} powinno przejść`);
  }
  const limited = await enforceRateLimit(req, { name: "smoke_test_route", limit: 2, windowSeconds: 60 });
  assert.ok(limited, "trzecie żądanie powinno zostać zablokowane");
  assert.equal(limited!.status, 429);
  assert.ok(Number(limited!.headers.get("retry-after")) > 0);
  const body = await limited!.json();
  assert.equal(body.error, "rate_limited");
});

test("różne adresy IP mają niezależne liczniki", async () => {
  resetRateLimitState();
  const reqA = new Request("https://helios.example.com/oauth/register", {
    method: "POST",
    headers: { "x-forwarded-for": "10.0.0.1" },
  });
  const reqB = new Request("https://helios.example.com/oauth/register", {
    method: "POST",
    headers: { "x-forwarded-for": "10.0.0.2" },
  });
  const r1 = await enforceRateLimit(reqA, { name: "independent_route", limit: 1, windowSeconds: 60 });
  const r2 = await enforceRateLimit(reqB, { name: "independent_route", limit: 1, windowSeconds: 60 });
  assert.equal(r1, null);
  assert.equal(r2, null);
});
