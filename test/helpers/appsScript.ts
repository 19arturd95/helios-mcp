/** Ładuje pure-funkcje z apps-script/Code.gs do Node (przez vm) i dostarcza
 *  zależności (crypto/cache/czas) zgodne z tym, co robi realny Apps Script.
 *
 *  `createFakeGasEnv` buduje w pełni podstawiony, w-pamięci odpowiednik
 *  DriveApp/PropertiesService/CacheService/LockService/Utilities/ContentService,
 *  wystarczający, by REALNY kod z Code.gs (dispatch_, buildTree_, opSearch_,
 *  assertDescendant_, consumeAuthCode_, doGet/doPost) mógł zostać wykonany
 *  w testach bez kopiowania jego logiki. */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runInNewContext } from "node:vm";
import { createHmac } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const CODE_GS = join(here, "..", "..", "apps-script", "Code.gs");

export interface VerifyResult {
  ok: boolean;
  payload?: string;
  error?: string;
  code?: string;
}

export interface AppsScriptExports {
  verifyEnvelope_(envelope: unknown, deps: AdapterDeps): VerifyResult;
  canonicalString_(t: unknown, n: unknown, p: unknown): string;
  constantTimeEqual_(a: string, b: string): boolean;
  pathSafe_(raw: string, opts?: { requireExtension?: boolean }): string;
  dispatch_(request: Record<string, unknown>, props: FakePropertiesStore): unknown;
  doPost(e: { postData?: { contents?: string } }): { getContent(): string };
  doGet(): { getContent(): string };
  opStatus_(root: FakeFolder): unknown;
  opListTree_(root: FakeFolder, request: Record<string, unknown>): { root: unknown; truncated: boolean };
  opSearch_(root: FakeFolder, request: Record<string, unknown>): { query: string; hits: unknown[]; truncated: boolean };
  opRead_(root: FakeFolder, rootId: string, request: Record<string, unknown>): unknown;
  assertDescendant_(file: FakeFile | FakeFolder, rootId: string): boolean;
  getRoot_(props: FakePropertiesStore): FakeFolder;
  consumeAuthCode_(props: FakePropertiesStore, jti: unknown, exp: unknown): { consumed: boolean };
  cleanupExpiredAuthCodes_(props: FakePropertiesStore, now: number): void;
  MAX_TREE_NODES: number;
  MAX_SEARCH_SCAN: number;
  MAX_SEARCH_CONTENT_READS: number;
  READ_OPS: Record<string, boolean>;
  META_OPS: Record<string, boolean>;
}

export interface AdapterDeps {
  secret: string;
  now(): number;
  hmacBase64(secret: string, message: string): string;
  cacheGet(key: string): string | null;
  cachePut(key: string, value: string, ttlSeconds: number): void;
  maxSkewSeconds: number;
}

/** Ładuje moduł z pustym środowiskiem GAS (dla testów podpisu/ścieżek/nonce). */
export function loadAppsScript(): AppsScriptExports {
  return loadAppsScriptWithEnv(createFakeGasEnv());
}

/** Ładuje moduł z pełnym podstawionym środowiskiem GAS (Drive/Properties/Lock/...). */
export function loadAppsScriptWithEnv(env: FakeGasEnv): AppsScriptExports {
  const src = readFileSync(CODE_GS, "utf8");
  const sandbox: Record<string, unknown> = {
    module: { exports: {} },
    console,
    DriveApp: env.DriveApp,
    PropertiesService: env.PropertiesService,
    CacheService: env.CacheService,
    LockService: env.LockService,
    Utilities: env.Utilities,
    ContentService: env.ContentService,
  };
  runInNewContext(src, sandbox, { filename: "Code.gs" });
  return (sandbox.module as { exports: AppsScriptExports }).exports;
}

/** Zależności odzwierciedlające zachowanie Apps Script (HMAC/base64, cache, czas). */
export function makeDeps(secret: string, opts: { now?: number } = {}): AdapterDeps & { _cache: Map<string, string> } {
  const cache = new Map<string, string>();
  return {
    secret,
    now: () => (opts.now ?? Math.floor(Date.now() / 1000)),
    hmacBase64: (s: string, m: string) => createHmac("sha256", s).update(m, "utf8").digest("base64"),
    cacheGet: (k: string) => cache.get(k) ?? null,
    cachePut: (k: string, v: string) => void cache.set(k, v),
    maxSkewSeconds: 300,
    _cache: cache,
  };
}

// ---------------------------------------------------------------------------
// Fałszywe środowisko Google Apps Script (DriveApp/PropertiesService/...)
// ---------------------------------------------------------------------------

function makeIterator<T>(items: T[]) {
  let i = 0;
  return {
    hasNext: () => i < items.length,
    next: () => items[i++]!,
  };
}

export interface FakeFile {
  getId(): string;
  getName(): string;
  getMimeType(): string;
  getLastUpdated(): Date;
  getBlob(): { getDataAsString(): string; getBytes(): { length: number } };
  getParents(): { hasNext(): boolean; next(): FakeFolder };
  _isFile: true;
}

export interface FakeFolder {
  getId(): string;
  getName(): string;
  getFoldersByName(name: string): { hasNext(): boolean; next(): FakeFolder };
  getFilesByName(name: string): { hasNext(): boolean; next(): FakeFile };
  getFolders(): { hasNext(): boolean; next(): FakeFolder };
  getFiles(): { hasNext(): boolean; next(): FakeFile };
  getParents(): { hasNext(): boolean; next(): FakeFolder };
  createFolder(name: string): FakeFolder;
  createFile(name: string, content: string, mimeType: string): FakeFile;
  _addFile(f: FakeFile): void;
  _removeFile(f: FakeFile): void;
  _isFile: false;
}

export interface FakePropertiesStore {
  getProperty(key: string): string | null;
  setProperty(key: string, value: string): void;
  deleteProperty(key: string): void;
  getProperties(): Record<string, string>;
}

export interface FakeGasEnv {
  DriveApp: { getFolderById(id: string): FakeFolder };
  PropertiesService: { getScriptProperties(): FakePropertiesStore };
  CacheService: { getScriptCache(): { get(k: string): string | null; put(k: string, v: string, ttl: number): void } };
  LockService: { getScriptLock(): { waitLock(ms: number): void; releaseLock(): void } };
  Utilities: {
    computeHmacSha256Signature(message: string, secret: string): number[];
    base64Encode(bytes: number[]): string;
    Charset: { UTF_8: string };
  };
  ContentService: {
    createTextOutput(text: string): { getContent(): string; setMimeType(m: unknown): unknown };
    MimeType: { JSON: string };
  };
  root: FakeFolder;
  registry: Map<string, FakeFile | FakeFolder>;
  /** Plik BEZ powiązania z żadnym folderem — symuluje plik spoza ROOT_FOLDER_ID. */
  createDetachedFile(name: string, content: string): FakeFile;
  props: FakePropertiesStore;
  /** Ustawia właściwości skryptu na sztywno (ROOT_FOLDER_ID, SHARED_SECRET...). */
  setScriptProperties(values: Record<string, string>): void;
}

/**
 * Buduje w pełni podstawione środowisko GAS z jednym folderem głównym
 * (`root`) zarejestrowanym jako `ROOT_FOLDER_ID`, jeśli podano `scriptProps`.
 */
export function createFakeGasEnv(scriptProps: Record<string, string> = {}): FakeGasEnv {
  let idCounter = 0;
  const registry = new Map<string, FakeFile | FakeFolder>();
  const genId = () => `id-${++idCounter}`;

  function createFile(name: string, content: string, mimeType: string, parent?: FakeFolder): FakeFile {
    const id = genId();
    const state = { id, name, content, mimeType, lastUpdated: new Date(), parents: parent ? [parent] : ([] as FakeFolder[]) };
    const handle: FakeFile = {
      getId: () => state.id,
      getName: () => state.name,
      getMimeType: () => state.mimeType,
      getLastUpdated: () => state.lastUpdated,
      getBlob: () => ({
        getDataAsString: () => state.content,
        getBytes: () => ({ length: Buffer.byteLength(state.content, "utf8") }),
      }),
      getParents: () => makeIterator(state.parents.slice()),
      _isFile: true,
    };
    registry.set(id, handle);
    return handle;
  }

  function createFolder(name: string, parent?: FakeFolder): FakeFolder {
    const id = genId();
    const state = {
      id,
      name,
      parents: parent ? [parent] : ([] as FakeFolder[]),
      folders: [] as FakeFolder[],
      files: [] as FakeFile[],
    };
    const handle: FakeFolder = {
      getId: () => state.id,
      getName: () => state.name,
      getFoldersByName: (n: string) => makeIterator(state.folders.filter((f) => f.getName() === n)),
      getFilesByName: (n: string) => makeIterator(state.files.filter((f) => f.getName() === n)),
      getFolders: () => makeIterator(state.folders.slice()),
      getFiles: () => makeIterator(state.files.slice()),
      getParents: () => makeIterator(state.parents.slice()),
      createFolder: (n: string) => {
        const f = createFolder(n, handle);
        state.folders.push(f);
        return f;
      },
      createFile: (n: string, content: string, mimeType: string) => {
        const f = createFile(n, content, mimeType, handle);
        state.files.push(f);
        return f;
      },
      _addFile: (f: FakeFile) => state.files.push(f),
      _removeFile: (f: FakeFile) => {
        state.files = state.files.filter((x) => x !== f);
      },
      _isFile: false,
    };
    registry.set(id, handle);
    return handle;
  }

  const root = createFolder("helios");

  const DriveApp = {
    getFolderById(id: string): FakeFolder {
      const node = registry.get(id);
      if (!node || node._isFile) throw new Error("Folder nie istnieje: " + id);
      return node;
    },
  };

  const propsStore = new Map<string, string>(Object.entries(scriptProps));
  const props: FakePropertiesStore = {
    getProperty: (k: string) => (propsStore.has(k) ? propsStore.get(k)! : null),
    setProperty: (k: string, v: string) => void propsStore.set(k, v),
    deleteProperty: (k: string) => void propsStore.delete(k),
    getProperties: () => Object.fromEntries(propsStore.entries()),
  };
  const PropertiesService = { getScriptProperties: () => props };

  const cacheStore = new Map<string, string>();
  const CacheService = {
    getScriptCache: () => ({
      get: (k: string) => cacheStore.get(k) ?? null,
      put: (k: string, v: string, _ttl: number) => void cacheStore.set(k, v),
    }),
  };

  const LockService = {
    getScriptLock: () => ({
      waitLock: (_ms: number) => {
        /* pojedynczy wątek w testach — brak realnej rywalizacji do symulowania */
      },
      releaseLock: () => {},
    }),
  };

  const Utilities = {
    computeHmacSha256Signature: (message: string, secret: string): number[] =>
      Array.from(createHmac("sha256", secret).update(message, "utf8").digest()),
    base64Encode: (bytes: number[]): string => Buffer.from(bytes).toString("base64"),
    Charset: { UTF_8: "UTF-8" },
  };

  const ContentService = {
    createTextOutput: (text: string) => ({
      getContent: () => text,
      setMimeType: function (this: unknown) {
        return this;
      },
    }),
    MimeType: { JSON: "JSON" },
  };

  return {
    DriveApp,
    PropertiesService,
    CacheService,
    LockService,
    Utilities,
    ContentService,
    root,
    registry,
    props,
    createDetachedFile: (name: string, content: string) => createFile(name, content, "text/markdown"),
    setScriptProperties: (values: Record<string, string>) => {
      for (const [k, v] of Object.entries(values)) propsStore.set(k, v);
    },
  };
}
