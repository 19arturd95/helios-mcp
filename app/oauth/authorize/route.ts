/**
 * Endpoint autoryzacji (OAuth authorization_code + PKCE).
 *
 * Waliduje żądanie klienta MCP, a następnie przekierowuje UŻYTKOWNIKA do
 * logowania Google. Oryginalne parametry przenosimy w podpisanym `state`.
 * Faktyczne sprawdzenie ALLOWED_EMAIL następuje w /oauth/callback.
 */

import { loadConfig } from "@/lib/config";
import { issueOAuthState, verifyClientId } from "@/lib/auth/tokens";
import { htmlError } from "@/lib/http";

export const dynamic = "force-dynamic";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";

export async function GET(req: Request) {
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

  // Weryfikacja client_id i dopasowanie redirect_uri (bez zaufania do wejścia).
  let allowedRedirects: string[];
  try {
    const meta = await verifyClientId(cfg.authSecret, cfg.baseUrl, clientId);
    allowedRedirects = meta.redirectUris;
  } catch {
    return htmlError("Błąd autoryzacji", "Nieznany lub nieprawidłowy client_id. Zarejestruj klienta ponownie.");
  }
  if (!allowedRedirects.includes(redirectUri)) {
    return htmlError("Błąd autoryzacji", "redirect_uri nie pasuje do zarejestrowanego klienta.");
  }

  const resource = q.get("resource") ?? `${cfg.baseUrl}/api/mcp`;

  const oauthState = await issueOAuthState(cfg.authSecret, cfg.baseUrl, {
    clientId,
    redirectUri,
    codeChallenge,
    scope,
    resource,
    state,
  });

  const googleUrl = new URL(GOOGLE_AUTH_URL);
  googleUrl.searchParams.set("client_id", cfg.googleClientId);
  googleUrl.searchParams.set("redirect_uri", `${cfg.baseUrl}/oauth/callback`);
  googleUrl.searchParams.set("response_type", "code");
  googleUrl.searchParams.set("scope", "openid email");
  googleUrl.searchParams.set("state", oauthState);
  googleUrl.searchParams.set("access_type", "online");
  googleUrl.searchParams.set("prompt", "select_account");

  return Response.redirect(googleUrl.toString(), 302);
}
