/**
 * Obsługa decyzji użytkownika z ekranu zgody (`/oauth/authorize`).
 *
 * Wyłącznie POST — świadome zatwierdzenie formularza, nigdy automatyczny
 * redirect z GET. Chronione przed CSRF wzorcem "double submit cookie":
 * token w ciasteczku `helios_csrf` (HttpOnly, ustawiony przy renderowaniu
 * ekranu zgody) musi być identyczny z tokenem w ukrytym polu formularza.
 *
 *  - „Zezwól” → rozpoczyna logowanie Google (dopiero teraz, po świadomej
 *    zgodzie — nigdy wcześniej).
 *  - „Odrzuć” lub nieprawidłowa/wygasła zgoda → powrót do klienta z
 *    `error=access_denied`, BEZ wydania kodu autoryzacyjnego.
 */

import { loadConfig } from "@/lib/config";
import { issueOAuthState, verifyConsentToken } from "@/lib/auth/tokens";
import { enforceRateLimit } from "@/lib/security/rateLimit";
import { htmlError } from "@/lib/http";

export const dynamic = "force-dynamic";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const CSRF_COOKIE = "helios_csrf";

function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return undefined;
}

/** Ciasteczko CSRF jest jednorazowe — czyścimy je niezależnie od decyzji. */
function expireCsrfCookieHeader(isHttps: boolean): string {
  return `${CSRF_COOKIE}=; Path=/oauth/consent; Max-Age=0; HttpOnly; SameSite=Lax${isHttps ? "; Secure" : ""}`;
}

export async function POST(req: Request) {
  const limited = await enforceRateLimit(req, { name: "oauth_consent", limit: 20, windowSeconds: 300 });
  if (limited) return limited;

  const cfg = loadConfig();
  const isHttps = new URL(req.url).protocol === "https:";
  const clearCsrf = expireCsrfCookieHeader(isHttps);

  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return htmlError("Błąd", "Nieprawidłowe żądanie.", 400, { "set-cookie": clearCsrf });
  }

  const consentToken = String(form.get("consent_token") ?? "");
  const csrfBody = String(form.get("csrf_token") ?? "");
  const decision = String(form.get("decision") ?? "");

  const csrfCookie = readCookie(req, CSRF_COOKIE);
  if (!csrfCookie || !csrfBody || csrfCookie !== csrfBody) {
    return htmlError(
      "Błąd bezpieczeństwa",
      "Nieprawidłowy token CSRF (lub wygasła sesja przeglądarki). Rozpocznij logowanie ponownie.",
      400,
      { "set-cookie": clearCsrf },
    );
  }

  let claims;
  try {
    claims = await verifyConsentToken(cfg.authSecret, cfg.baseUrl, consentToken);
  } catch {
    return htmlError(
      "Zgoda wygasła",
      "Ekran zgody wygasł lub jest nieprawidłowy. Rozpocznij logowanie ponownie od klienta MCP.",
      400,
      { "set-cookie": clearCsrf },
    );
  }

  // Walidacja redirect_uri wykonana już w /oauth/authorize; tu tylko musi
  // parsować się jako URL, aby bezpiecznie dołączyć parametry błędu/kodu.
  let redirectBase: URL;
  try {
    redirectBase = new URL(claims.redirectUri);
  } catch {
    return htmlError("Błąd", "Nieprawidłowy redirect_uri w zgodzie.", 400, { "set-cookie": clearCsrf });
  }

  if (decision !== "allow") {
    // Odrzucenie kończy proces — standardowy powrót OAuth z błędem, bez kodu.
    redirectBase.searchParams.set("error", "access_denied");
    redirectBase.searchParams.set("error_description", "Użytkownik odrzucił żądanie dostępu.");
    if (claims.state) redirectBase.searchParams.set("state", claims.state);
    redirectBase.searchParams.set("iss", cfg.baseUrl);
    return new Response(null, {
      status: 302,
      headers: { location: redirectBase.toString(), "set-cookie": clearCsrf, "cache-control": "no-store" },
    });
  }

  const oauthState = await issueOAuthState(cfg.authSecret, cfg.baseUrl, {
    clientId: claims.clientId,
    redirectUri: claims.redirectUri,
    codeChallenge: claims.codeChallenge,
    scope: claims.scope,
    resource: claims.resource,
    state: claims.state,
  });

  const googleUrl = new URL(GOOGLE_AUTH_URL);
  googleUrl.searchParams.set("client_id", cfg.googleClientId);
  googleUrl.searchParams.set("redirect_uri", `${cfg.baseUrl}/oauth/callback`);
  googleUrl.searchParams.set("response_type", "code");
  googleUrl.searchParams.set("scope", "openid email");
  googleUrl.searchParams.set("state", oauthState);
  googleUrl.searchParams.set("access_type", "online");
  googleUrl.searchParams.set("prompt", "select_account");

  return new Response(null, {
    status: 302,
    headers: { location: googleUrl.toString(), "set-cookie": clearCsrf, "cache-control": "no-store" },
  });
}
