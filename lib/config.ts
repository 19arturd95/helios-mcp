/**
 * Odczyt i walidacja konfiguracji ze zmiennych środowiskowych.
 *
 * Zasady bezpieczeństwa:
 *  - Sekrety pochodzą wyłącznie ze zmiennych środowiskowych (Vercel/`.env.local`).
 *  - Komunikaty błędów NIGDY nie zawierają wartości sekretów — tylko ich nazwy.
 */

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
  /** Czy Faza 2 (zapis) jest włączona. Domyślnie false. */
  writeEnabled: boolean;
}

/** Kanoniczny identyfikator zasobu MCP (audience tokenów OAuth). */
export function mcpResourceUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/api/mcp`;
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
  if (authSecret.length < 16 || appsScriptSecret.length < 16) {
    throw new Error(
      "Sekrety AUTH_SECRET i APPS_SCRIPT_SECRET muszą mieć co najmniej 16 znaków (zalecane 32+).",
    );
  }

  return {
    allowedEmail: env.ALLOWED_EMAIL!.trim().toLowerCase(),
    baseUrl: env.PUBLIC_BASE_URL!.trim().replace(/\/+$/, ""),
    appsScriptUrl: env.APPS_SCRIPT_URL!.trim(),
    appsScriptSecret,
    authSecret,
    googleClientId: env.GOOGLE_CLIENT_ID!.trim(),
    googleClientSecret: env.GOOGLE_CLIENT_SECRET!.trim(),
    writeEnabled: (env.HELIOS_WRITE_ENABLED ?? "false").trim().toLowerCase() === "true",
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
