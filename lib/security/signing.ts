/**
 * Podpisywanie żądań do Apps Script (HMAC-SHA256).
 *
 * Koperta przesyłana do adaptera:
 *   { timestamp, nonce, payload, signature }
 * gdzie:
 *   - `timestamp` — czas uniksowy w SEKUNDACH,
 *   - `nonce` — losowy, jednorazowy identyfikator (hex),
 *   - `payload` — DOKŁADNY ciąg JSON operacji (podpisywany bajt w bajt),
 *   - `signature` — base64(HMAC-SHA256(secret, canonical)).
 *
 * Postać kanoniczna (identyczna po stronie Apps Script):
 *   `${timestamp}\n${nonce}\n${payload}`
 * Rozdzielenie znakiem nowej linii zapobiega atakom przez sklejanie pól
 * (np. "12"+"3" vs "1"+"23").
 */

export interface SignedEnvelope {
  timestamp: number;
  nonce: string;
  payload: string;
  signature: string;
}

export function canonicalString(timestamp: number, nonce: string, payload: string): string {
  return `${timestamp}\n${nonce}\n${payload}`;
}

function base64FromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  // btoa istnieje w Edge/Workers oraz w Node 18+.
  return btoa(binary);
}

/** Zwraca base64(HMAC-SHA256(secret, message)) przy użyciu Web Crypto. */
export async function hmacSha256Base64(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return base64FromBytes(new Uint8Array(sig));
}

/** Losowy nonce (16 bajtów jako hex). */
export function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export interface SignOptions {
  timestamp?: number;
  nonce?: string;
}

/** Buduje podpisaną kopertę dla danego ciągu payload. */
export async function signPayload(
  secret: string,
  payload: string,
  opts: SignOptions = {},
): Promise<SignedEnvelope> {
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? randomNonce();
  const signature = await hmacSha256Base64(secret, canonicalString(timestamp, nonce, payload));
  return { timestamp, nonce, payload, signature };
}

/** Porównanie ciągów w czasie stałym (ochrona przed atakami czasowymi). */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
