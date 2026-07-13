/**
 * Dynamic Client Registration (RFC 7591).
 *
 * Klient MCP (Claude/ChatGPT) rejestruje się, podając swoje redirect_uris.
 * Zwracamy stateless `client_id` (podpisany JWT kodujący te redirect_uris),
 * dzięki czemu nie potrzebujemy bazy danych. Klient publiczny + PKCE
 * (brak client_secret).
 */

import { loadConfig } from "@/lib/config";
import { issueClientId } from "@/lib/auth/tokens";
import { corsHeaders, json, oauthError } from "@/lib/http";

export const dynamic = "force-dynamic";

function isAllowedRedirect(uri: string): boolean {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  // Dozwolone http tylko dla lokalnego rozwoju.
  if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
  return false;
}

export async function POST(req: Request) {
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
  if (!redirectUris.every(isAllowedRedirect)) {
    return oauthError("invalid_redirect_uri", "redirect_uris muszą używać https (lub http://localhost).");
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
