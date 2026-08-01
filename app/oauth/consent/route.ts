/**
 * Obsługa decyzji użytkownika z ekranu zgody (`/oauth/authorize`).
 *
 * Wyłącznie POST — świadome zatwierdzenie formularza, nigdy automatyczny
 * redirect z GET. Ochrona CSRF wymaga zgodności tokenu z formularza i
 * double-submit cookie. Nagłówki `Origin` / `Sec-Fetch-Site` zapewniają
 * dodatkową kontrolę źródła.
 *
 * Okno OAuth uruchomione z izolowanego kontekstu może wysłać `Origin: null`
 * mimo `Sec-Fetch-Site: same-origin`. Taki przypadek akceptujemy wyłącznie
 * przy prawidłowym cookie. Cross-site POST pozostaje odrzucany.
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

type BrowserSubmissionSignal = "trusted" | "invalid" | "absent";

/**
 * Nowoczesne przeglądarki wysyłają `Origin` dla formularza POST oraz
 * `Sec-Fetch-Site`, którego skrypt strony nie może podrobić. Jawnie obcy
 * origin lub inny kontekst niż same-origin jest twardą odmową nawet przy
 * poprawnym cookie. `Origin: null` może pochodzić z izolowanego popupu OAuth,
 * dlatego ufamy mu tylko razem z `Sec-Fetch-Site: same-origin`.
 */
function browserSubmissionSignal(req: Request, expectedOrigin: string): BrowserSubmissionSignal {
  const origin = req.headers.get("origin");
  const fetchSite = req.headers.get("sec-fetch-site");

  if (origin === "null") return fetchSite === "same-origin" ? "trusted" : "invalid";
  if (origin !== null && origin !== expectedOrigin) return "invalid";
  if (fetchSite !== null && fetchSite !== "same-origin") return "invalid";
  if (origin === expectedOrigin || fetchSite === "same-origin") return "trusted";
  return "absent";
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
  const cookieMatches = Boolean(csrfCookie && csrfBody && csrfCookie === csrfBody);
  const browserSignal = browserSubmissionSignal(req, cfg.baseUrl);
  if (!cookieMatches || browserSignal === "invalid") {
    return htmlError(
      "Błąd bezpieczeństwa",
      "Nieprawidłowe źródło żądania lub token CSRF. Rozpocznij logowanie ponownie.",
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
