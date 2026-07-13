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
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return oauthError("invalid_client_metadata", "Treść żądania musi być JSON-em.");
  }

  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.map(String) : [];
  if (redirectUris.length === 0) {
    return oauthError("invalid_client_metadata", "Wymagane pole redirect_uris.");
  }
  const policy = { allowedRedirectUris: cfg.allowedRedirectUris, allowLocalhost: cfg.allowLocalhostRedirect };
  if (!redirectUris.every((uri) => isAllowedRedirectUri(uri, policy))) {
    return oauthError(
      "invalid_redirect_uri",
      "redirect_uris muszą używać https (lub http://localhost w trybie development) i — jeśli skonfigurowano allowlistę — być na niej wymienione dokładnie.",
    );
  }

  const clientName = typeof body.client_name === "string" ? body.client_name : undefined;
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
