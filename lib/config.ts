/**
 * Odczyt i walidacja konfiguracji ze zmiennych środowiskowych.
 *
 * Zasady bezpieczeństwa:
 *  - Sekrety pochodzą wyłącznie ze zmiennych środowiskowych (Vercel/`.env.local`).
 *  - Komunikaty błędów NIGDY nie zawierają wartości sekretów — tylko ich nazwy.
 */

import { parseRedirectAllowlist } from "./security/redirect";

export interface HeliosConfig {
  /** Jedyny dozwolony adres e-mail (Google). */
  allowedEmail: string;
  /** Publiczny URL wdrożenia, bez ukośnika na końcu. Pełni rolę OAuth issuer. */
  baseUrl: string;
  /** URL aplikacji internetowej Apps Script (Helios Drive Adapter). */
  appsScriptUrl: string;
  /** Wspólny sekret HMAC do podpisu żądań do Apps Script. */
  appsScriptSecret: string;
  /** Sekret do podpisu tokenów OAuth (JWT). */
  authSecret: string;
  /** Google OAuth Client ID (logowanie użytkownika). */
  googleClientId: string;
  /** Google OAuth Client Secret. */
  googleClientSecret: string;
  /**
   * Opcjonalna, dokładna allowlista redirect_uri klientów OAuth
   * (`ALLOWED_OAUTH_REDIRECT_URIS`, rozdzielona przecinkami). Gdy ustawiona,
   * DCR i /oauth/authorize odrzucają każdy redirect_uri spoza tej listy
   * (fail-closed, bez wildcardów). Główną obroną przed nadużyciem otwartego
   * DCR pozostaje ekran zgody — ta allowlista to dodatkowa warstwa.
   */
  allowedRedirectUris?: string[];
  /**
   * Czy zezwolić na `http://localhost` / `http://127.0.0.1` jako redirect_uri.
   * Prawda tylko poza `NODE_ENV=production` (Vercel zawsze ustawia
   * `production` — zarówno dla Preview, jak i Production).
   */
  allowLocalhostRedirect: boolean;
}

/** Kanoniczny identyfikator zasobu MCP (audience tokenów OAuth). */
export function mcpResourceUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/api/mcp`;
}

/**
 * Porównuje parametr OAuth `resource` z kanonicznym adresem Helios MCP.
 * URL normalizuje wielkość liter schematu/hosta, ale ścieżka i pozostałe
 * elementy nadal muszą odpowiadać dokładnie zasobowi z metadanych RFC 9728.
 */
export function isMcpResourceUrl(value: string, baseUrl: string): boolean {
  try {
    const actual = new URL(value);
    const expected = new URL(mcpResourceUrl(baseUrl));
    return actual.hash === "" && actual.toString() === expected.toString();
  } catch {
    return false;
  }
}

const REQUIRED_KEYS = [
  "ALLOWED_EMAIL",
  "PUBLIC_BASE_URL",
  "APPS_SCRIPT_URL",
  "APPS_SCRIPT_SECRET",
  "AUTH_SECRET",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
] as const;

/**
 * Wczytuje konfigurację z podanego źródła (domyślnie `process.env`).
 * Rzuca błąd wymieniający BRAKUJĄCE nazwy zmiennych — nigdy ich wartości.
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): HeliosConfig {
  const missing = REQUIRED_KEYS.filter((k) => {
    const v = env[k];
    return v === undefined || v.trim() === "";
  });
  if (missing.length > 0) {
    throw new Error(`Brak wymaganych zmiennych środowiskowych: ${missing.join(", ")}`);
  }

  const authSecret = env.AUTH_SECRET!.trim();
  const appsScriptSecret = env.APPS_SCRIPT_SECRET!.trim();
  if (authSecret.length < 32 || appsScriptSecret.length < 32) {
    throw new Error(
      "Sekrety AUTH_SECRET i APPS_SCRIPT_SECRET muszą mieć co najmniej 32 znaki.",
    );
  }

  const allowedEmail = env.ALLOWED_EMAIL!.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(allowedEmail)) {
    throw new Error("ALLOWED_EMAIL nie jest prawidłowym adresem e-mail.");
  }

  let baseUrl: URL;
  let appsScriptUrl: URL;
  try {
    baseUrl = new URL(env.PUBLIC_BASE_URL!.trim());
    appsScriptUrl = new URL(env.APPS_SCRIPT_URL!.trim());
  } catch {
    throw new Error("PUBLIC_BASE_URL i APPS_SCRIPT_URL muszą być prawidłowymi adresami URL.");
  }
  const isProduction = (env.NODE_ENV ?? "development") === "production";
  const isLocalBase =
    baseUrl.protocol === "http:" &&
    (baseUrl.hostname === "localhost" || baseUrl.hostname === "127.0.0.1");
  if ((isProduction && baseUrl.protocol !== "https:") || (!isProduction && baseUrl.protocol !== "https:" && !isLocalBase)) {
    throw new Error("PUBLIC_BASE_URL musi używać HTTPS (HTTP jest dozwolone tylko lokalnie poza produkcją).");
  }
  if (
    baseUrl.username ||
    baseUrl.password ||
    baseUrl.pathname !== "/" ||
    baseUrl.search ||
    baseUrl.hash
  ) {
    throw new Error("PUBLIC_BASE_URL musi być samym originem, bez ścieżki, danych logowania, query ani fragmentu.");
  }
  if (
    appsScriptUrl.protocol !== "https:" ||
    appsScriptUrl.hostname !== "script.google.com" ||
    !/^\/macros\/s\/[^/]+\/exec$/.test(appsScriptUrl.pathname) ||
    appsScriptUrl.search ||
    appsScriptUrl.hash
  ) {
    throw new Error("APPS_SCRIPT_URL musi być adresem wdrożenia Apps Script zakończonym /exec.");
  }

  return {
    allowedEmail,
    baseUrl: baseUrl.origin,
    appsScriptUrl: appsScriptUrl.toString(),
    appsScriptSecret,
    authSecret,
    googleClientId: env.GOOGLE_CLIENT_ID!.trim(),
    googleClientSecret: env.GOOGLE_CLIENT_SECRET!.trim(),
    allowedRedirectUris: parseRedirectAllowlist(env.ALLOWED_OAUTH_REDIRECT_URIS),
    allowLocalhostRedirect: !isProduction,
  };
}

/**
 * Zestaw wartości sekretów do redagowania z komunikatów błędów.
 * Zwraca listę ciągów, które nie powinny nigdy wyciec w odpowiedzi/log.
 */
export function secretValues(config: HeliosConfig): string[] {
  return [config.appsScriptSecret, config.authSecret, config.googleClientSecret].filter(
    (s) => s.length > 0,
  );
}
