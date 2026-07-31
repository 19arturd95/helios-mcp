/**
 * Callback logowania Google.
 *
 * Wymienia kod Google na id_token, weryfikuje go przez JWKS Google,
 * sprawdza e-mail względem ALLOWED_EMAIL, a następnie wystawia NASZ kod
 * autoryzacyjny i przekierowuje z powrotem do klienta MCP.
 */

import { createRemoteJWKSet, jwtVerify } from "jose";
import { loadConfig } from "@/lib/config";
import { issueAuthorizationCode, verifyOAuthState } from "@/lib/auth/tokens";
import { evaluateGoogleIdentity } from "@/lib/auth/googleIdentity";
import { enforceRateLimit } from "@/lib/security/rateLimit";
import { htmlError } from "@/lib/http";

export const dynamic = "force-dynamic";

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));

export async function GET(req: Request) {
  const limited = await enforceRateLimit(req, { name: "oauth_callback", limit: 20, windowSeconds: 300 });
  if (limited) return limited;

  const cfg = loadConfig();
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const stateToken = url.searchParams.get("state");
  const googleError = url.searchParams.get("error");

  if (googleError) {
    return htmlError("Logowanie przerwane", `Google zwrócił błąd: ${googleError}.`);
  }
  if (!code || !stateToken) {
    return htmlError("Błąd logowania", "Brak parametru code lub state.");
  }

  // Odtwórz oryginalne żądanie klienta MCP z podpisanego state.
  let st;
  try {
    st = await verifyOAuthState(cfg.authSecret, cfg.baseUrl, stateToken);
  } catch {
    return htmlError("Błąd logowania", "Nieprawidłowy lub wygasły state.");
  }

  // Wymiana kodu Google na tokeny.
  let idToken: string | undefined;
  try {
    const res = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: cfg.googleClientId,
        client_secret: cfg.googleClientSecret,
        redirect_uri: `${cfg.baseUrl}/oauth/callback`,
        grant_type: "authorization_code",
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return htmlError("Błąd logowania", "Nie udało się wymienić kodu Google.");
    const tok = (await res.json()) as { id_token?: string };
    idToken = tok.id_token;
  } catch {
    return htmlError("Błąd logowania", "Błąd połączenia z Google.");
  }
  if (!idToken) {
    return htmlError("Błąd logowania", "Brak id_token w odpowiedzi Google.");
  }

  // Weryfikacja id_token (podpis/issuer/audience przez JWKS Google).
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(idToken, GOOGLE_JWKS, {
      issuer: ["https://accounts.google.com", "accounts.google.com"],
      audience: cfg.googleClientId,
    });
    payload = verified.payload;
  } catch {
    return htmlError("Błąd logowania", "Nie udało się zweryfikować tożsamości Google.");
  }

  // Ocena tożsamości (e-mail zweryfikowany + zgodny z ALLOWED_EMAIL) — logika
  // wydzielona do lib/auth/googleIdentity.ts, testowalna bez sieci/JWKS.
  const identity = evaluateGoogleIdentity(payload, cfg.allowedEmail);
  if (!identity.allowed) {
    // Odmowa dla każdego innego konta (lub email_verified=false).
    return htmlError(
      "Brak dostępu",
      "To konto Google nie ma uprawnień do tego serwera Helios.",
      403,
    );
  }

  // Wystaw NASZ kod autoryzacyjny i wróć do klienta MCP.
  const authCode = await issueAuthorizationCode(cfg.authSecret, cfg.baseUrl, {
    email: identity.email,
    clientId: st.clientId,
    redirectUri: st.redirectUri,
    codeChallenge: st.codeChallenge,
    scope: st.scope,
    resource: st.resource,
  });

  const redirect = new URL(st.redirectUri);
  redirect.searchParams.set("code", authCode);
  if (st.state) redirect.searchParams.set("state", st.state);
  // RFC 9207. Jawna identyfikacja wystawcy ogranicza ryzyko OAuth mix-up.
  redirect.searchParams.set("iss", cfg.baseUrl);
  // Kod autoryzacyjny trafia do query string przekierowania — no-store
  // zapobiega jego zapisaniu przez pośredniczące cache'e/proxy.
  return new Response(null, {
    status: 302,
    headers: { location: redirect.toString(), "cache-control": "no-store" },
  });
}
