/** Ładuje pure-funkcje z apps-script/Code.gs do Node (przez vm) i dostarcza
 *  zależności (crypto/cache/czas) zgodne z tym, co robi realny Apps Script. */

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
}

export interface AdapterDeps {
  secret: string;
  now(): number;
  hmacBase64(secret: string, message: string): string;
  cacheGet(key: string): string | null;
  cachePut(key: string, value: string, ttlSeconds: number): void;
  maxSkewSeconds: number;
}

export function loadAppsScript(): AppsScriptExports {
  const src = readFileSync(CODE_GS, "utf8");
  const sandbox: Record<string, unknown> = { module: { exports: {} }, console };
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
