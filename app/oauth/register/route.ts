/**
 * Dynamic Client Registration (RFC 7591).
 *
 * Klient MCP (Claude/ChatGPT) rejestruje się, podając swoje redirect_uris.
 * Zwracamy stateless `client_id` (podpisany JWT kodujący te redirect_uris,
 * z `exp` — patrz `issueClientId`), dzięki czemu nie potrzebujemy bazy
 * danych. Klient publiczny + PKCE (brak client_secret).
 *
 * Ochrona przed nadużyciem otwartego DCR: główną warstwą jest obowiązkowy
 * ekran zgody na /oauth/authorize (użytkownik zawsze widzi nazwę klienta
 * i host redirect_uri przed zalogowaniem). Dodatkowo, jeśli skonfigurowano
 * `ALLOWED_OAUTH_REDIRECT_URIS`, redirect_uris spoza tej listy są odrzucane
 * już tutaj (fail-closed).
 */

import { loadConfig } from "@/lib/config";
import { issueClientId } from "@/lib/auth/tokens";
import { isAllowedRedirectUri } from "@/lib/security/redirect";
import { enforceRateLimit } from "@/lib/security/rateLimit";
import { corsHeaders, json, oauthError } from "@/lib/http";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const limited = await enforceRateLimit(req, { name: "oauth_register", limit: 10, windowSeconds: 300 });
  if (limited) return limited;

  const cfg = loadConfig();
  let body: Record<string, unknown>;
  try {
    const parsed: unknown = await req.json();
    // `JSON.parse("null")` zwraca null, a tablice/liczby też są poprawnym JSON-em.
    // Bez tego sprawdzenia `body.redirect_uris` rzucało TypeError → 500.
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return oauthError("invalid_client_metadata", "Treść żądania musi być obiektem JSON.");
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return oauthError("invalid_client_metadata", "Treść żądania musi być JSON-em.");
  }

  const rawRedirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  if (
    rawRedirectUris.length === 0 ||
    rawRedirectUris.length > 10 ||
    !rawRedirectUris.every((uri) => typeof uri === "string" && uri.length > 0 && uri.length <= 2048)
  ) {
    return oauthError(
      "invalid_client_metadata",
      "redirect_uris musi zawierać od 1 do 10 poprawnych adresów tekstowych (maks. 2048 znaków każdy).",
    );
  }
  const redirectUris = [...new Set(rawRedirectUris as string[])];
  if (redirectUris.join("").length > 4096) {
    return oauthError("invalid_client_metadata", "Łączna długość redirect_uris przekracza limit.");
  }
  const policy = { allowedRedirectUris: cfg.allowedRedirectUris, allowLocalhost: cfg.allowLocalhostRedirect };
  if (!redirectUris.every((uri) => isAllowedRedirectUri(uri, policy))) {
    return oauthError(
      "invalid_redirect_uri",
      "redirect_uris muszą używać https (lub http://localhost w trybie development) i — jeśli skonfigurowano allowlistę — być na niej wymienione dokładnie.",
    );
  }

  const clientName = typeof body.client_name === "string" ? body.client_name.trim() : undefined;
  if (clientName && clientName.length > 128) {
    return oauthError("invalid_client_metadata", "client_name może mieć maksymalnie 128 znaków.");
  }
  const clientId = await issueClientId(cfg.authSecret, cfg.baseUrl, { redirectUris, clientName });

  return json(
    {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      client_name: clientName ?? "MCP Client",
    },
    201,
  );
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}
