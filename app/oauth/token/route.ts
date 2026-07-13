/**
 * Endpoint tokenu (grant_type=authorization_code + PKCE).
 *
 * Weryfikuje nasz kod autoryzacyjny, sprawdza PKCE i wystawia access token
 * (JWT) z audience = zasób /api/mcp. Bez refresh tokenu (krótki TTL).
 */

import { loadConfig, mcpResourceUrl } from "@/lib/config";
import { issueAccessToken, verifyAuthorizationCode, verifyPkceS256 } from "@/lib/auth/tokens";
import { corsHeaders, json, oauthError } from "@/lib/http";

export const dynamic = "force-dynamic";

async function parseBody(req: Request): Promise<Record<string, string>> {
  const contentType = req.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const obj = (await req.json()) as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(obj)) out[k] = String(v);
    return out;
  }
  const form = await req.formData();
  const out: Record<string, string> = {};
  for (const [k, v] of form.entries()) out[k] = String(v);
  return out;
}

export async function POST(req: Request) {
  const cfg = loadConfig();
  const body = await parseBody(req).catch(() => null);
  if (!body) return oauthError("invalid_request", "Nie udało się odczytać treści żądania.");

  if (body.grant_type !== "authorization_code") {
    return oauthError("unsupported_grant_type", "Obsługiwany jest tylko authorization_code.");
  }

  const code = body.code ?? "";
  const codeVerifier = body.code_verifier ?? "";
  const clientId = body.client_id ?? "";
  const redirectUri = body.redirect_uri ?? "";

  let claims;
  try {
    claims = await verifyAuthorizationCode(cfg.authSecret, cfg.baseUrl, code);
  } catch {
    return oauthError("invalid_grant", "Kod autoryzacyjny jest nieprawidłowy lub wygasł.");
  }

  if (clientId && clientId !== claims.clientId) {
    return oauthError("invalid_grant", "client_id nie pasuje do kodu.");
  }
  if (redirectUri && redirectUri !== claims.redirectUri) {
    return oauthError("invalid_grant", "redirect_uri nie pasuje do kodu.");
  }

  const pkceOk = await verifyPkceS256(codeVerifier, claims.codeChallenge);
  if (!pkceOk) {
    return oauthError("invalid_grant", "Weryfikacja PKCE nie powiodła się.");
  }

  // Obrona w głąb: e-mail nadal musi być dozwolony.
  if (claims.email.trim().toLowerCase() !== cfg.allowedEmail) {
    return oauthError("access_denied", "Konto nie ma uprawnień.", 403);
  }

  const accessToken = await issueAccessToken({
    authSecret: cfg.authSecret,
    issuer: cfg.baseUrl,
    audience: mcpResourceUrl(cfg.baseUrl),
    email: claims.email,
    clientId: claims.clientId,
    scope: claims.scope || "helios.read",
    ttlSeconds: 3600,
  });

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: claims.scope || "helios.read",
  });
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}
