import { test } from "node:test";
import assert from "node:assert/strict";

import { createFakeGasEnv, loadAppsScriptWithEnv } from "./helpers/appsScript.js";

function makeEnv(scriptProps: Record<string, string> = {}) {
  const env = createFakeGasEnv(scriptProps);
  const gas = loadAppsScriptWithEnv(env);
  env.setScriptProperties({ ROOT_FOLDER_ID: env.root.getId() });
  return { env, gas };
}

test("nieznana operacja jest odrzucana", () => {
  const { env, gas } = makeEnv();
  assert.throws(() => gas.dispatch_({ op: "haxx0r" }, env.props), /Nieznana operacja/);
  assert.throws(() => gas.dispatch_({}, env.props), /Nieznana operacja/);
});

test("każda operacja zapisu jest odrzucana, gdy WRITE_ENABLED=false (domyślnie)", () => {
  const { env, gas } = makeEnv({ WRITE_ENABLED: "false" });
  const wiki = env.root.createFolder("20 Wiki");
  wiki.createFile("a.md", "tresc", "text/markdown");

  const writeRequests: Array<Record<string, unknown>> = [
    { op: "create", path: "20 Wiki/nowy.md", content: "x" },
    { op: "update", path: "20 Wiki/a.md", content: "y", expectedModifiedTime: new Date().toISOString() },
    { op: "append", path: "20 Wiki/a.md", text: "z" },
    { op: "backup", path: "20 Wiki/a.md" },
    { op: "moveToArchive", path: "20 Wiki/a.md" },
  ];
  for (const req of writeRequests) {
    assert.throws(
      () => gas.dispatch_(req, env.props),
      /wyłączone/,
      `operacja ${req.op} powinna być zablokowana`,
    );
  }
});

test("operacje zapisu przechodzą, gdy WRITE_ENABLED=true (weryfikacja samego mechanizmu przełącznika)", () => {
  const { env, gas } = makeEnv({ WRITE_ENABLED: "true" });
  const result = gas.dispatch_({ op: "create", path: "nowy.md", content: "tresc" }, env.props) as { path: string };
  assert.equal(result.path, "nowy.md");
});

test("brak ROOT_FOLDER_ID nie blokuje operacji meta (consumeAuthCode) — nie dotyczą Drive", () => {
  const env = createFakeGasEnv({});
  const gas = loadAppsScriptWithEnv(env);
  // Celowo NIE ustawiamy ROOT_FOLDER_ID.
  const result = gas.dispatch_(
    { op: "consumeAuthCode", jti: "abc", exp: Math.floor(Date.now() / 1000) + 60 },
    env.props,
  ) as { consumed: boolean };
  assert.equal(result.consumed, true);
});

test("assertDescendant_ akceptuje plik będący potomkiem ROOT_FOLDER_ID", () => {
  const { env, gas } = makeEnv();
  const wiki = env.root.createFolder("20 Wiki");
  const file = wiki.createFile("a.md", "x", "text/markdown");
  assert.equal(gas.assertDescendant_(file, env.root.getId()), true);
});

test("assertDescendant_ odrzuca plik spoza ROOT_FOLDER_ID (osierocony/inne drzewo)", () => {
  const { env, gas } = makeEnv();
  const orphan = env.createDetachedFile("orphan.md", "tajne dane");
  assert.throws(() => gas.assertDescendant_(orphan, env.root.getId()), /poza ROOT_FOLDER_ID/);
});

test("read: notatka spoza folderu nie jest osiągalna przez path (brak operacji po ID)", () => {
  const { env, gas } = makeEnv();
  // Plik istnieje, ale nie jest zaczepiony w drzewie — resolveByPath_ go nie znajdzie.
  env.createDetachedFile("secret.md", "tajne");
  assert.throws(() => gas.dispatch_({ op: "read", path: "secret.md" }, env.props), /nie istnieje/);
});

test("consumeAuthCode_: pierwsza wymiana się udaje, druga (replay) jest odrzucana", () => {
  const { env, gas } = makeEnv();
  const exp = Math.floor(Date.now() / 1000) + 60;
  const first = gas.consumeAuthCode_(env.props, "jti-unique-1", exp);
  const second = gas.consumeAuthCode_(env.props, "jti-unique-1", exp);
  assert.equal(first.consumed, true);
  assert.equal(second.consumed, false);
});

test("consumeAuthCode_: różne jti są niezależne", () => {
  const { env, gas } = makeEnv();
  const exp = Math.floor(Date.now() / 1000) + 60;
  assert.equal(gas.consumeAuthCode_(env.props, "jti-a", exp).consumed, true);
  assert.equal(gas.consumeAuthCode_(env.props, "jti-b", exp).consumed, true);
});

test("consumeAuthCode_: odrzuca brakujący/nietekstowy jti", () => {
  const { env, gas } = makeEnv();
  assert.throws(() => gas.consumeAuthCode_(env.props, "", 123));
  assert.throws(() => gas.consumeAuthCode_(env.props, undefined, 123));
});

test("cleanupExpiredAuthCodes_ usuwa wygasłe wpisy, zachowuje aktywne", () => {
  const { env, gas } = makeEnv();
  const now = Math.floor(Date.now() / 1000);
  env.props.setProperty("authcode:stale-jti", String(now - 10)); // już wygasł
  env.props.setProperty("authcode:fresh-jti", String(now + 120)); // wciąż ważny
  gas.cleanupExpiredAuthCodes_(env.props, now);
  assert.equal(env.props.getProperty("authcode:stale-jti"), null);
  assert.equal(env.props.getProperty("authcode:fresh-jti"), String(now + 120));
});

test("listTree: drzewo jest obcinane po przekroczeniu MAX_TREE_NODES, truncated=true", () => {
  const { env, gas } = makeEnv();
  const wiki = env.root.createFolder("20 Wiki");
  const total = gas.MAX_TREE_NODES + 50;
  for (let i = 0; i < total; i++) wiki.createFile(`f${i}.md`, "x", "text/markdown");

  const result = gas.opListTree_(env.root, { maxDepth: 4 });
  assert.equal(result.truncated, true);

  function countNodes(node: any): number {
    let count = 1;
    for (const child of node.children ?? []) count += countNodes(child);
    return count;
  }
  assert.ok(countNodes(result.root) <= gas.MAX_TREE_NODES + 1);
});

test("listTree: drzewo małe nie jest obcinane, truncated=false", () => {
  const { env, gas } = makeEnv();
  const wiki = env.root.createFolder("20 Wiki");
  wiki.createFile("a.md", "x", "text/markdown");
  wiki.createFile("b.md", "x", "text/markdown");
  const result = gas.opListTree_(env.root, { maxDepth: 4 });
  assert.equal(result.truncated, false);
});

test("search: limit liczby odczytów treści (MAX_SEARCH_CONTENT_READS) obcina wynik, truncated=true", () => {
  const { env, gas } = makeEnv();
  const wiki = env.root.createFolder("20 Wiki");
  const total = gas.MAX_SEARCH_CONTENT_READS + 20;
  // Nazwy plików NIE zawierają frazy — wymusza odczyt treści każdego pliku.
  for (let i = 0; i < total; i++) wiki.createFile(`note-${i}.md`, "brak dopasowania w tresci", "text/markdown");

  const result = gas.opSearch_(env.root, { query: "nigdzieniewystepujacafraza", limit: 50 });
  assert.equal(result.truncated, true);
  assert.equal(result.hits.length, 0);
});

test("search: dopasowanie po nazwie pliku nie zużywa budżetu odczytu treści", () => {
  const { env, gas } = makeEnv();
  const wiki = env.root.createFolder("20 Wiki");
  wiki.createFile("temat-szukany.md", "cokolwiek", "text/markdown");
  const result = gas.opSearch_(env.root, { query: "szukany", limit: 10 });
  assert.equal(result.truncated, false);
  assert.equal(result.hits.length, 1);
  assert.equal((result.hits[0] as { path: string }).path, "20 Wiki/temat-szukany.md");
});

test("search: pusta fraza zwraca pusty wynik bez skanowania", () => {
  const { env, gas } = makeEnv();
  env.root.createFolder("20 Wiki").createFile("a.md", "x", "text/markdown");
  const result = gas.opSearch_(env.root, { query: "", limit: 10 });
  assert.equal(result.hits.length, 0);
  assert.equal(result.truncated, false);
});

test("doPost/doGet nie ujawniają sekretów ani stack trace w błędach", () => {
  const { gas } = makeEnv({ SHARED_SECRET: "top-secret-value-xyz" });
  const res = gas.doPost({ postData: { contents: "{ nieprawidlowy json" } });
  const body = JSON.parse(res.getContent());
  assert.equal(body.ok, false);
  assert.doesNotMatch(body.error, /top-secret-value-xyz/);

  const getRes = gas.doGet();
  const getBody = JSON.parse(getRes.getContent());
  assert.equal(getBody.ok, true);
  assert.doesNotMatch(JSON.stringify(getBody), /top-secret-value-xyz/);
});
