/**
 * Ocena tożsamości Google (po weryfikacji podpisu/issuer/audience id_token
 * przez JWKS — patrz `app/oauth/callback/route.ts`). Wydzielona jako czysta
 * funkcja, żeby dało się ją testować bez sieci/JWKS.
 */

export interface GoogleIdentityResult {
  allowed: boolean;
  email: string;
}

export function evaluateGoogleIdentity(
  payload: Record<string, unknown>,
  allowedEmail: string,
): GoogleIdentityResult {
  const email = String(payload.email ?? "").toLowerCase();
  const emailVerified = payload.email_verified === true;
  const allowed = Boolean(email) && emailVerified && email === allowedEmail;
  return { allowed, email };
}
