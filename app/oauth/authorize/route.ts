/**
 * Endpoint autoryzacji (OAuth authorization_code + PKCE).
 *
 * Waliduje żądanie klienta MCP, a następnie renderuje EKRAN ZGODY (ta strona,
 * GET). Dopiero świadome kliknięcie „Zezwól” (POST /oauth/consent) uruchamia
 * przekierowanie do logowania Google — patrz `app/oauth/consent/route.ts`.
 *
 * Nigdy nie przekierowujemy automatycznie do Google z samego GET: to właśnie
 * ten automatyzm pozwalał wcześniej ukryć przed użytkownikiem, do jakiego
 * (potencjalnie obcego) redirect_uri trafi kod autoryzacyjny.
 */

import { loadConfig } from "@/lib/config";
import { issueConsentToken, verifyClientId } from "@/lib/auth/tokens";
import { isAllowedRedirectUri } from "@/lib/security/redirect";
import { enforceRateLimit } from "@/lib/security/rateLimit";
import { randomNonce } from "@/lib/security/signing";
import { escapeHtml, htmlError, htmlSecurityHeaders } from "@/lib/http";

export const dynamic = "force-dynamic";

/** Nazwa i ścieżka ciasteczka CSRF dla formularza zgody. TTL musi pasować do TTL tokenu zgody. */
const CSRF_COOKIE = "helios_csrf";
const CSRF_TTL_SECONDS = 300;

function renderConsentPage(params: {
  clientName: string;
  redirectHost: string;
  consentToken: string;
  csrfToken: string;
}): string {
  const clientName = escapeHtml(params.clientName || "Nieznana aplikacja");
  const redirectHost = escapeHtml(params.redirectHost);
  const consentToken = escapeHtml(params.consentToken);
  const csrfToken = escapeHtml(params.csrfToken);
  return `<!doctype html>
<meta charset="utf-8">
<title>Zezwolić na dostęp do Helios?</title>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">
  <h1>Żądanie dostępu</h1>
  <p><strong>${clientName}</strong> prosi o dostęp do odczytu Twojej prywatnej bazy wiedzy Helios
     (tylko odczyt: wyszukiwanie i czytanie notatek).</p>
  <p>Po zalogowaniu zostaniesz przekierowany z powrotem do:
     <code>${redirectHost}</code></p>
  <p>Zezwalaj tylko, jeśli sam(a) zainicjowałeś(aś) to logowanie w zaufanej aplikacji.</p>
  <form method="POST" action="/oauth/consent" style="display:inline-block;margin-right:1rem">
    <input type="hidden" name="consent_token" value="${consentToken}">
    <input type="hidden" name="csrf_token" value="${csrfToken}">
    <input type="hidden" name="decision" value="allow">
    <button type="submit" style="padding:0.5rem 1.5rem">Zezwól</button>
  </form>
  <form method="POST" action="/oauth/consent" style="display:inline-block">
    <input type="hidden" name="consent_token" value="${consentToken}">
    <input type="hidden" name="csrf_token" value="${csrfToken}">
    <input type="hidden" name="decision" value="deny">
    <button type="submit" style="padding:0.5rem 1.5rem">Odrzuć</button>
  </form>
</body>`;
}

export async function GET(req: Request) {
  const limited = await enforceRateLimit(req, { name: "oauth_authorize", limit: 20, windowSeconds: 300 });
  if (limited) return limited;

  const cfg = loadConfig();
  const url = new URL(req.url);
  const q = url.searchParams;

  const responseType = q.get("response_type");
  const clientId = q.get("client_id") ?? "";
  const redirectUri = q.get("redirect_uri") ?? "";
  const codeChallenge = q.get("code_challenge") ?? "";
  const codeChallengeMethod = q.get("code_challenge_method") ?? "";
  const scope = q.get("scope") ?? "helios.read";
  const state = q.get("state") ?? "";

  if (responseType !== "code") {
    return htmlError("Błąd autoryzacji", "Obsługiwany jest wyłącznie response_type=code.");
  }
  if (!codeChallenge || codeChallengeMethod !== "S256") {
    return htmlError("Błąd autoryzacji", "Wymagane PKCE (code_challenge_method=S256).");
  }

  // Weryfikacja client_id (odrzuca też wygasłe rejestracje — `exp` w JWT)
  // i dopasowanie redirect_uri (bez zaufania do wejścia).
  let allowedRedirects: string[];
  let clientName: string | undefined;
  try {
    const meta = await verifyClientId(cfg.authSecret, cfg.baseUrl, clientId);
    allowedRedirects = meta.redirectUris;
    clientName = meta.clientName;
  } catch {
    return htmlError("Błąd autoryzacji", "Nieznany, nieprawidłowy lub wygasły client_id. Zarejestruj klienta ponownie.");
  }
  if (!allowedRedirects.includes(redirectUri)) {
    return htmlError("Błąd autoryzacji", "redirect_uri nie pasuje do zarejestrowanego klienta.");
  }
  // Obrona w głąb: allowlista mogła zostać zaostrzona po rejestracji klienta.
  const policy = { allowedRedirectUris: cfg.allowedRedirectUris, allowLocalhost: cfg.allowLocalhostRedirect };
  if (!isAllowedRedirectUri(redirectUri, policy)) {
    return htmlError("Błąd autoryzacji", "redirect_uri nie spełnia bieżącej polityki bezpieczeństwa serwera.");
  }

  const resource = q.get("resource") ?? `${cfg.baseUrl}/api/mcp`;
  let redirectHost: string;
  try {
    redirectHost = new URL(redirectUri).host;
  } catch {
    return htmlError("Błąd autoryzacji", "redirect_uri jest nieprawidłowy.");
  }

  const consentToken = await issueConsentToken(cfg.authSecret, cfg.baseUrl, {
    clientId,
    clientName: clientName ?? "Nieznana aplikacja",
    redirectUri,
    codeChallenge,
    scope,
    resource,
    state,
  });

  const csrfToken = randomNonce();
  const html = renderConsentPage({ clientName: clientName ?? "Nieznana aplikacja", redirectHost, consentToken, csrfToken });
  const isHttps = url.protocol === "https:";

  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...htmlSecurityHeaders(),
      "set-cookie": `${CSRF_COOKIE}=${csrfToken}; Path=/oauth/consent; Max-Age=${CSRF_TTL_SECONDS}; HttpOnly; SameSite=Lax${isHttps ? "; Secure" : ""}`,
    },
  });
}
