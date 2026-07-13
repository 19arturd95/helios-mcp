/**
 * Walidacja redirect_uri klientów OAuth (DCR + /oauth/authorize).
 *
 * Zasady (fail-closed):
 *  - wymagane https, chyba że host to localhost/127.0.0.1 ORAZ tryb development,
 *  - jeśli skonfigurowano allowlistę (ALLOWED_OAUTH_REDIRECT_URIS), dozwolone
 *    są WYŁĄCZNIE dokładne dopasowania z tej listy (bez wildcardów, bez
 *    dopasowania po prefiksie/hoście),
 *  - brak allowlisty nie blokuje działania — ekran zgody (/oauth/authorize)
 *    jest wtedy głównym mechanizmem obronnym przed nadużyciem DCR.
 */

export interface RedirectPolicy {
  /** Dokładna allowlista redirect_uri (opcjonalna). Gdy ustawiona — fail-closed. */
  allowedRedirectUris?: string[];
  /** Czy zezwolić na http://localhost / http://127.0.0.1 (wyłącznie development). */
  allowLocalhost: boolean;
}

export function isAllowedRedirectUri(uri: string, policy: RedirectPolicy): boolean {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }

  const isHttps = u.protocol === "https:";
  const isLocalDev =
    policy.allowLocalhost &&
    u.protocol === "http:" &&
    (u.hostname === "localhost" || u.hostname === "127.0.0.1");

  if (!isHttps && !isLocalDev) return false;

  if (policy.allowedRedirectUris && policy.allowedRedirectUris.length > 0) {
    return policy.allowedRedirectUris.includes(uri);
  }
  return true;
}

/** Parsuje `ALLOWED_OAUTH_REDIRECT_URIS` (lista rozdzielona przecinkami). */
export function parseRedirectAllowlist(raw: string | undefined): string[] | undefined {
  if (!raw) return undefined;
  const list = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length > 0 ? list : undefined;
}
