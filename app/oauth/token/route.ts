/**
 * Endpoint tokenu (grant_type=authorization_code + PKCE).
 *
 * Weryfikuje nasz kod autoryzacyjny, wymaga zgodności client_id/redirect_uri,
 * sprawdza PKCE, a następnie ATOMOWO zużywa kod (jednorazowość — patrz
 * `consumeAuthCode` w Helios Drive Adapter / Code.gs) zanim wystawi access
 * token (JWT) z audience = zasób /api/mcp. Bez refresh tokenu (krótki TTL).
 */

import { isMcpResourceUrl, loadConfig, mcpResourceUrl } from "@/lib/config";
import { HELIOS_READ_SCOPE, isExactReadScope } from "@/lib/auth/constants";
import { issueAccessToken, verifyAuthorizationCode, verifyPkceS256 } from "@/lib/auth/tokens";
import { callAdapter, DriveAdapterError } from "@/lib/drive/client";
import type { ConsumeAuthCodeResult } from "@/lib/drive/types";
import { enforceRateLimit } from "@/lib/security/rateLimit";
import { corsHeaders, json, oauthError } from "@/lib/http";

export const dynamic = "force-dynamic";

/**
 * RFC 6749 §3.2: parametr żądania NIE MOŻE wystąpić więcej niż raz.
 * Wcześniej wygrywała ostatnia wartość, przez co `grant_type=refresh_token&
 * grant_type=authorization_code` było akceptowane. Teraz duplikat = odmowa
 * (fail closed), co zamyka też furtkę na parameter smuggling przez pośredniki.
 */
class DuplicateParameterError extends Error {}

async function parseBody(req: Request): Promise<Record<string, string>> {
  const contentType = req.headers.get("content-type") ?? "";
  const out: Record<string, string> = Object.create(null);
  const put = (k: string, v: unknown) => {
    if (Object.prototype.hasOwnProperty.call(out, k)) throw new DuplicateParameterError(k);
    out[k] = String(v);
  };

  if (contentType.includes("application/json")) {
    const parsed: unknown = await req.json();
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("body must be a JSON object");
    }
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) put(k, v);
    return out;
  }
  for (const [k, v] of (await req.formData()).entries()) put(k, v);
  return out;
}

export async function POST(req: Request) {
  const limited = await enforceRateLimit(req, { name: "oauth_token", limit: 30, windowSeconds: 300 });
  if (limited) return limited;

  const cfg = loadConfig();
  let body: Record<string, string>;
  try {
    body = await parseBody(req);
  } catch (err) {
    return oauthError(
      "invalid_request",
      err instanceof DuplicateParameterError
        ? "Parametr żądania nie może wystąpić więcej niż raz."
        : "Nie udało się odczytać treści żądania.",
    );
  }

  if (body.grant_type !== "authorization_code") {
    return oauthError("unsupported_grant_type", "Obsługiwany jest tylko authorization_code.");
  }

  const code = body.code ?? "";
  const codeVerifier = body.code_verifier ?? "";
  const clientId = body.client_id ?? "";
  const redirectUri = body.redirect_uri ?? "";
  const resource = body.resource ?? "";

  // client_id i redirect_uri są obowiązkowe (RFC 6749 §4.1.3 dla klienta
  // publicznego, który podawał redirect_uri w /oauth/authorize).
  if (!clientId) {
    return oauthError("invalid_request", "Wymagane pole client_id.");
  }
  if (!redirectUri) {
    return oauthError("invalid_request", "Wymagane pole redirect_uri.");
  }
  if (!resource) {
    return oauthError("invalid_request", "Wymagane pole resource.");
  }
  if (!isMcpResourceUrl(resource, cfg.baseUrl)) {
    return oauthError("invalid_target", "Parametr resource nie wskazuje tego serwera MCP.");
  }

  let claims;
  try {
    claims = await verifyAuthorizationCode(cfg.authSecret, cfg.baseUrl, code);
  } catch {
    return oauthError("invalid_grant", "Kod autoryzacyjny jest nieprawidłowy lub wygasł.");
  }

  if (clientId !== claims.clientId) {
    return oauthError("invalid_grant", "client_id nie pasuje do kodu.");
  }
  if (redirectUri !== claims.redirectUri) {
    return oauthError("invalid_grant", "redirect_uri nie pasuje do kodu.");
  }
  if (!isMcpResourceUrl(claims.resource, cfg.baseUrl) || resource !== claims.resource) {
    return oauthError("invalid_grant", "resource nie pasuje do kodu.");
  }
  if (!isExactReadScope(claims.scope)) {
    return oauthError("invalid_scope", `Kod nie zawiera wymaganego scope ${HELIOS_READ_SCOPE}.`);
  }
  if (!claims.jti) {
    // Kod bez jti (nie powinno się zdarzyć dla kodów wystawionych przez ten
    // serwer) — odrzucamy fail-closed, nie potrafimy zagwarantować jednorazowości.
    return oauthError("invalid_grant", "Kod autoryzacyjny jest nieprawidłowy.");
  }

  const pkceOk = await verifyPkceS256(codeVerifier, claims.codeChallenge);
  if (!pkceOk) {
    return oauthError("invalid_grant", "Weryfikacja PKCE nie powiodła się.");
  }

  // Obrona w głąb: e-mail nadal musi być dozwolony.
  if (claims.email.trim().toLowerCase() !== cfg.allowedEmail) {
    return oauthError("access_denied", "Konto nie ma uprawnień.", 403);
  }

  // Jednorazowość kodu: atomowe zużycie `jti` przez Helios Drive Adapter
  // (Apps Script LockService + PropertiesService). Awaria adaptera → odmowa
  // (nie możemy zagwarantować braku powtórnego użycia, więc bezpieczniej
  // odrzucić niż zaryzykować replay).
  try {
    const consumed = await callAdapter<ConsumeAuthCodeResult>(
      { appsScriptUrl: cfg.appsScriptUrl, appsScriptSecret: cfg.appsScriptSecret },
      "consumeAuthCode",
      { jti: claims.jti, exp: claims.exp },
    );
    if (!consumed.consumed) {
      return oauthError("invalid_grant", "Kod autoryzacyjny został już wykorzystany.");
    }
  } catch (err) {
    const detail = err instanceof DriveAdapterError ? err.message : "Błąd wewnętrzny.";
    return json(
      { error: "temporarily_unavailable", error_description: `Nie udało się zweryfikować jednorazowości kodu (${detail}). Spróbuj ponownie.` },
      503,
    );
  }

  const accessToken = await issueAccessToken({
    authSecret: cfg.authSecret,
    issuer: cfg.baseUrl,
    audience: mcpResourceUrl(cfg.baseUrl),
    email: claims.email,
    clientId: claims.clientId,
    scope: HELIOS_READ_SCOPE,
    ttlSeconds: 3600,
  });

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: HELIOS_READ_SCOPE,
  });
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}
