import { test } from "node:test";
import assert from "node:assert/strict";

import { isAllowedRedirectUri, parseRedirectAllowlist } from "../lib/security/redirect";

test("https jest zawsze dozwolone (bez allowlisty)", () => {
  assert.equal(isAllowedRedirectUri("https://client.example.com/cb", { allowLocalhost: false }), true);
});

test("http jest odrzucany poza localhost/127.0.0.1", () => {
  assert.equal(isAllowedRedirectUri("http://evil.example.com/cb", { allowLocalhost: true }), false);
  assert.equal(isAllowedRedirectUri("http://evil.example.com/cb", { allowLocalhost: false }), false);
});

test("http://localhost jest dozwolony TYLKO gdy allowLocalhost=true (development)", () => {
  assert.equal(isAllowedRedirectUri("http://localhost:3000/cb", { allowLocalhost: true }), true);
  assert.equal(isAllowedRedirectUri("http://127.0.0.1:3000/cb", { allowLocalhost: true }), true);
  assert.equal(isAllowedRedirectUri("http://localhost:3000/cb", { allowLocalhost: false }), false);
});

test("nieprawidłowy URL jest odrzucany", () => {
  assert.equal(isAllowedRedirectUri("nie-jest-to-url", { allowLocalhost: false }), false);
  assert.equal(isAllowedRedirectUri("", { allowLocalhost: false }), false);
});

test("redirect_uri z fragmentem lub danymi logowania jest odrzucany", () => {
  assert.equal(isAllowedRedirectUri("https://client.example.com/cb#fragment", { allowLocalhost: false }), false);
  assert.equal(isAllowedRedirectUri("https://user:pass@client.example.com/cb", { allowLocalhost: false }), false);
});

test("allowlista: dokładne dopasowanie przechodzi, wszystko inne jest odrzucane (fail-closed)", () => {
  const policy = {
    allowLocalhost: false,
    allowedRedirectUris: ["https://good.example.com/callback"],
  };
  assert.equal(isAllowedRedirectUri("https://good.example.com/callback", policy), true);
  // Inny, choć "podobny" redirect_uri (inny host) — odrzucony (ochrona przed open redirect).
  assert.equal(isAllowedRedirectUri("https://evil.example.com/callback", policy), false);
  // Inny path na tym samym hoście — odrzucony (brak dopasowania prefiksowego).
  assert.equal(isAllowedRedirectUri("https://good.example.com/callback/extra", policy), false);
  // Subdomena atakującego zawierająca dozwolony host jako prefiks — odrzucona.
  assert.equal(isAllowedRedirectUri("https://good.example.com.evil.com/callback", policy), false);
  // Dokładnie ten sam URI z innym query stringiem — odrzucony (dokładne dopasowanie stringów).
  assert.equal(isAllowedRedirectUri("https://good.example.com/callback?x=1", policy), false);
});

test("allowlista pusta/nieustawiona nie blokuje (ekran zgody jest wtedy główną obroną)", () => {
  assert.equal(
    isAllowedRedirectUri("https://any-https-client.example/cb", { allowLocalhost: false, allowedRedirectUris: undefined }),
    true,
  );
});

test("parseRedirectAllowlist: parsuje listę rozdzieloną przecinkami, przycina spacje, ignoruje puste", () => {
  assert.deepEqual(
    parseRedirectAllowlist("https://a.example/cb, https://b.example/cb ,,"),
    ["https://a.example/cb", "https://b.example/cb"],
  );
  assert.equal(parseRedirectAllowlist(undefined), undefined);
  assert.equal(parseRedirectAllowlist(""), undefined);
  assert.equal(parseRedirectAllowlist("   ,, "), undefined);
});
