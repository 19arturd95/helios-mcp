/**
 * Prymitywy OAuth naszego serwera autoryzacji (stateless, `jose`).
 *
 * Wszystko jest podpisane HS256 sekretem AUTH_SECRET, dzięki czemu nie
 * potrzebujemy bazy danych ani Redisa:
 *  - client_id            → podpisany JWT kodujący redirect_uris (DCR),
 *  - kod autoryzacyjny    → krótkożyciowy podpisany JWT (~60 s),
 *  - access token         → podpisany JWT (audience = zasób /api/mcp).
 *
 * Każdy typ tokenu ma odrębny `audience`, co blokuje pomylenie tokenów.
 */

import { SignJWT, jwtVerify } from "jose";
import { randomNonce } from "../security/signing";

/**
 * Jedyny dopuszczony algorytm podpisu naszych tokenów. Jawna lista w
 * `jwtVerify` zamyka klasę błędów "algorithm confusion": bez niej weryfikacja
 * akceptowała także HS384/HS512, a przy ewentualnej zmianie typu klucza
 * (np. na parę RSA) rozszerzyłaby się na algorytmy asymetryczne.
 */
const ALG = "HS256";

const AUD_CLIENT = "helios:client";
const AUD_CODE = "helios:auth_code";
const AUD_STATE = "helios:oauth_state";
const AUD_CONSENT = "helios:consent";

function key(authSecret: string): Uint8Array {
  return new TextEncoder().encode(authSecret);
}

function nowSeconds(now?: number): number {
  return now ?? Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// base64url + PKCE (S256)
// ---------------------------------------------------------------------------

function base64UrlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const PKCE_S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

/** Weryfikacja PKCE S256: base64url(SHA-256(verifier)) === challenge. */
export async function verifyPkceS256(codeVerifier: string, codeChallenge: string): Promise<boolean> {
  if (!PKCE_VERIFIER.test(codeVerifier) || !PKCE_S256_CHALLENGE.test(codeChallenge)) return false;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  return base64UrlFromBytes(new Uint8Array(digest)) === codeChallenge;
}

/** Sprawdza format wyzwania PKCE S256 przed rozpoczęciem logowania. */
export function isValidPkceS256Challenge(codeChallenge: string): boolean {
  return PKCE_S256_CHALLENGE.test(codeChallenge);
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (stateless client_id)
// ---------------------------------------------------------------------------

export interface ClientMetadata {
  redirectUris: string[];
  clientName?: string;
}

/** TTL domyślny rejestracji DCR (client_id). Po tym czasie klient musi się zarejestrować ponownie. */
export const CLIENT_ID_TTL_SECONDS = 30 * 24 * 3600; // 30 dni

/** Tworzy client_id (podpisany JWT) kodujący dozwolone redirect_uris. Ma `exp` — wygasłe rejestracje są odrzucane. */
export async function issueClientId(
  authSecret: string,
  issuer: string,
  meta: ClientMetadata,
  ttlSeconds = CLIENT_ID_TTL_SECONDS,
  now?: number,
): Promise<string> {
  const iat = nowSeconds(now);
  return await new SignJWT({ redirect_uris: meta.redirectUris, client_name: meta.clientName ?? "" })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(issuer)
    .setAudience(AUD_CLIENT)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttlSeconds)
    .sign(key(authSecret));
}

export async function verifyClientId(
  authSecret: string,
  issuer: string,
  clientId: string,
  now?: number,
): Promise<ClientMetadata> {
  const { payload } = await jwtVerify(clientId, key(authSecret), {
    algorithms: [ALG],
    issuer,
    audience: AUD_CLIENT,
    currentDate: now !== undefined ? new Date(now * 1000) : undefined,
  });
  const redirectUris = Array.isArray(payload.redirect_uris)
    ? (payload.redirect_uris as unknown[]).map(String)
    : [];
  return { redirectUris, clientName: typeof payload.client_name === "string" ? payload.client_name : undefined };
}

// ---------------------------------------------------------------------------
// Kod autoryzacyjny
// ---------------------------------------------------------------------------

export interface AuthCodeClaims {
  email: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  resource: string;
}

/**
 * Kod autoryzacyjny zweryfikowany + jego `jti` (jednorazowy identyfikator)
 * i `exp`. `jti` jest przekazywany do Helios Drive Adapter (Apps Script),
 * który atomowo (LockService) oznacza go jako zużyty — dzięki temu ten sam
 * kod nie może zostać wymieniony dwukrotnie (patrz `/oauth/token`).
 */
export interface VerifiedAuthCodeClaims extends AuthCodeClaims {
  jti: string;
  exp: number;
}

export async function issueAuthorizationCode(
  authSecret: string,
  issuer: string,
  claims: AuthCodeClaims,
  ttlSeconds = 60,
  now?: number,
): Promise<string> {
  const iat = nowSeconds(now);
  return await new SignJWT({
    email: claims.email,
    client_id: claims.clientId,
    redirect_uri: claims.redirectUri,
    code_challenge: claims.codeChallenge,
    scope: claims.scope,
    resource: claims.resource,
  })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(issuer)
    .setAudience(AUD_CODE)
    .setJti(randomNonce())
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttlSeconds)
    .sign(key(authSecret));
}

export async function verifyAuthorizationCode(
  authSecret: string,
  issuer: string,
  code: string,
  now?: number,
): Promise<VerifiedAuthCodeClaims> {
  const { payload } = await jwtVerify(code, key(authSecret), {
    algorithms: [ALG],
    issuer,
    audience: AUD_CODE,
    currentDate: now !== undefined ? new Date(now * 1000) : undefined,
  });
  return {
    email: String(payload.email ?? ""),
    clientId: String(payload.client_id ?? ""),
    redirectUri: String(payload.redirect_uri ?? ""),
    codeChallenge: String(payload.code_challenge ?? ""),
    scope: String(payload.scope ?? ""),
    resource: String(payload.resource ?? ""),
    jti: String(payload.jti ?? ""),
    exp: typeof payload.exp === "number" ? payload.exp : 0,
  };
}

// ---------------------------------------------------------------------------
// Stan OAuth przenoszony przez Google (podpisany, krótkożyciowy)
// ---------------------------------------------------------------------------

export interface OAuthStateClaims {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  resource: string;
  state: string; // oryginalny `state` klienta MCP
  /**
   * SHA-256 wartości ciasteczka `helios_login`, ustawionego w tej samej
   * przeglądarce, która kliknęła „Zezwól". `/oauth/callback` wymaga zgodności —
   * bez tego atakujący mógłby przygotować własny link do Google i podstawić
   * go ofierze, otrzymując kod autoryzacyjny wystawiony na jej konto
   * (OAuth Security BCP / RFC 9700 §4.7 — powiązanie z user agentem).
   * Trzymamy WYŁĄCZNIE skrót: payload JWT jest jawnie czytelny.
   */
  browserBinding: string;
  /** OIDC `nonce` wysłany do Google i weryfikowany w `id_token` (RFC 9700 §4.4). */
  googleNonce: string;
}

export async function issueOAuthState(
  authSecret: string,
  issuer: string,
  claims: OAuthStateClaims,
  ttlSeconds = 600,
  now?: number,
): Promise<string> {
  const iat = nowSeconds(now);
  return await new SignJWT({ ...claims })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(issuer)
    .setAudience(AUD_STATE)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttlSeconds)
    .sign(key(authSecret));
}

export async function verifyOAuthState(
  authSecret: string,
  issuer: string,
  token: string,
  now?: number,
): Promise<OAuthStateClaims> {
  const { payload } = await jwtVerify(token, key(authSecret), {
    algorithms: [ALG],
    issuer,
    audience: AUD_STATE,
    currentDate: now !== undefined ? new Date(now * 1000) : undefined,
  });
  return {
    clientId: String(payload.clientId ?? ""),
    redirectUri: String(payload.redirectUri ?? ""),
    codeChallenge: String(payload.codeChallenge ?? ""),
    scope: String(payload.scope ?? ""),
    resource: String(payload.resource ?? ""),
    state: String(payload.state ?? ""),
    browserBinding: String(payload.browserBinding ?? ""),
    googleNonce: String(payload.googleNonce ?? ""),
  };
}

// ---------------------------------------------------------------------------
// Stan zgody użytkownika (ekran /oauth/authorize → POST /oauth/consent)
// ---------------------------------------------------------------------------

/**
 * Krótkożyciowy, podpisany token niosący dane potrzebne do wyrenderowania
 * ekranu zgody i — po kliknięciu „Zezwól” — do rozpoczęcia logowania Google.
 * Podpis (`AUD_CONSENT`) uniemożliwia modyfikację (np. podmianę redirect_uri
 * czy nazwy klienta) bez unieważnienia tokenu.
 */
export interface ConsentClaims {
  clientId: string;
  clientName: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  resource: string;
  state: string;
}

export async function issueConsentToken(
  authSecret: string,
  issuer: string,
  claims: ConsentClaims,
  ttlSeconds = 300,
  now?: number,
): Promise<string> {
  const iat = nowSeconds(now);
  return await new SignJWT({ ...claims })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(issuer)
    .setAudience(AUD_CONSENT)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttlSeconds)
    .sign(key(authSecret));
}

export async function verifyConsentToken(
  authSecret: string,
  issuer: string,
  token: string,
  now?: number,
): Promise<ConsentClaims> {
  const { payload } = await jwtVerify(token, key(authSecret), {
    algorithms: [ALG],
    issuer,
    audience: AUD_CONSENT,
    currentDate: now !== undefined ? new Date(now * 1000) : undefined,
  });
  return {
    clientId: String(payload.clientId ?? ""),
    clientName: String(payload.clientName ?? ""),
    redirectUri: String(payload.redirectUri ?? ""),
    codeChallenge: String(payload.codeChallenge ?? ""),
    scope: String(payload.scope ?? ""),
    resource: String(payload.resource ?? ""),
    state: String(payload.state ?? ""),
  };
}

// ---------------------------------------------------------------------------
// Access token
// ---------------------------------------------------------------------------

export interface AccessTokenParams {
  authSecret: string;
  issuer: string;
  audience: string; // zasób /api/mcp
  email: string;
  clientId: string;
  scope: string;
  ttlSeconds?: number;
  now?: number;
}

export async function issueAccessToken(params: AccessTokenParams): Promise<string> {
  const iat = nowSeconds(params.now);
  const ttl = params.ttlSeconds ?? 3600;
  return await new SignJWT({
    email: params.email,
    scope: params.scope,
    client_id: params.clientId,
    token_type: "access",
  })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(params.issuer)
    .setAudience(params.audience)
    .setSubject(params.email)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ttl)
    .sign(key(params.authSecret));
}

export interface VerifiedAccessToken {
  email: string;
  clientId: string;
  scope: string;
  exp?: number;
}

export async function verifyAccessToken(
  authSecret: string,
  issuer: string,
  audience: string,
  token: string,
  now?: number,
): Promise<VerifiedAccessToken> {
  const { payload } = await jwtVerify(token, key(authSecret), {
    algorithms: [ALG],
    issuer,
    audience,
    currentDate: now !== undefined ? new Date(now * 1000) : undefined,
  });
  return {
    email: String(payload.email ?? ""),
    clientId: String(payload.client_id ?? ""),
    scope: String(payload.scope ?? ""),
    exp: typeof payload.exp === "number" ? payload.exp : undefined,
  };
}
