/**
 * Rate limiting w pamięci procesu (best effort, bez płatnej infrastruktury).
 *
 * OGRANICZENIE: Vercel Hobby uruchamia funkcje serverless bezstanowo między
 * instancjami (brak gwarancji, że kolejne żądanie trafi do tej samej "ciepłej"
 * instancji). Ten limiter chroni więc wyłącznie w obrębie jednej instancji —
 * nie jest globalnym licznikiem i resetuje się przy cold-startach/redeployach.
 * To świadomy kompromis (brak Redis/KV): warstwa odstraszająca, nie twarda
 * gwarancja. Patrz README → „Ograniczenia rate limitingu”.
 *
 * Klucz limitu nigdy nie zawiera surowego e-maila ani tokenu — wyłącznie hash.
 */

interface Bucket {
  count: number;
  windowStart: number;
}

const buckets = new Map<string, Bucket>();
let lastSweep = Date.now();

/**
 * Twardy limit liczby kubełków. Klucz zawiera adres IP z `x-forwarded-for`,
 * więc klient rotujący ten nagłówek tworzył nowy wpis przy każdym żądaniu,
 * a `sweepExpired` czyści mapę najwyżej raz na 60 s — mapa mogła więc rosnąć
 * bez ograniczeń między zamiataniami (zmierzone: 50 tys. kluczy ≈ 19 MB sterty).
 * Po przekroczeniu limitu usuwamy najstarsze wpisy (Map zachowuje kolejność
 * wstawiania), co ogranicza zużycie pamięci kosztem wcześniejszego resetu
 * licznika — limiter i tak jest best-effort (patrz nagłówek pliku).
 */
const MAX_BUCKETS = 10_000;

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

export interface RateLimitOptions {
  name: string;
  limit: number;
  windowSeconds: number;
}

/** Sprawdza i aktualizuje licznik dla danego klucza (już zahaszowanego). */
export function checkRateLimit(key: string, opts: { limit: number; windowSeconds: number }): RateLimitResult {
  const now = Date.now();
  const existing = buckets.get(key);
  if (!existing || now - existing.windowStart >= opts.windowSeconds * 1000) {
    if (!existing && buckets.size >= MAX_BUCKETS) {
      // Usuń najstarsze wpisy (kolejność wstawiania), żeby mapa nie rosła bez końca.
      const overflow = buckets.size - MAX_BUCKETS + 1;
      let removed = 0;
      for (const k of buckets.keys()) {
        buckets.delete(k);
        if (++removed >= overflow) break;
      }
    }
    buckets.set(key, { count: 1, windowStart: now });
    return { allowed: true, retryAfterSeconds: 0 };
  }
  if (existing.count < opts.limit) {
    existing.count += 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }
  const retryAfterSeconds = Math.ceil((opts.windowSeconds * 1000 - (now - existing.windowStart)) / 1000);
  return { allowed: false, retryAfterSeconds };
}

/** Usuwa stare wpisy, aby mapa nie rosła bez końca. Rzadziej niż raz/min. */
export function sweepExpired(maxAgeSeconds: number): void {
  const now = Date.now();
  if (now - lastSweep < 60_000) return;
  lastSweep = now;
  for (const [k, v] of buckets) {
    if (now - v.windowStart > maxAgeSeconds * 1000) buckets.delete(k);
  }
}

/** Tylko do testów: czyści cały stan limitera. */
export function resetRateLimitState(): void {
  buckets.clear();
  lastSweep = Date.now();
}

/**
 * Najlepszy dostępny identyfikator klienta z nagłówków żądania.
 * UWAGA: `x-forwarded-for` może być spreparowany przez klienta, jeśli
 * wdrożenie nie znajduje się bezpośrednio za zaufaną krawędzią Vercela.
 * Traktuj to pole jako podpowiedź, nie twarde uwierzytelnienie.
 */
export function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const first = xff.split(",")[0]?.trim();
    if (first) return first;
  }
  return "unknown";
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Hashuje dowolne identyfikatory (IP, e-mail, itp.) do klucza limitu — nigdy w jawnej postaci. */
export async function hashRateLimitKey(...parts: string[]): Promise<string> {
  const full = await sha256Hex(parts.join("|"));
  return full.slice(0, 32);
}

function tooManyRequestsResponse(retryAfterSeconds: number): Response {
  return new Response(
    JSON.stringify({ error: "rate_limited", error_description: "Zbyt wiele żądań. Spróbuj ponownie później." }),
    {
      status: 429,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "retry-after": String(Math.max(1, retryAfterSeconds)),
        "cache-control": "no-store",
      },
    },
  );
}

/**
 * Sprawdza limit dla żądania. Zwraca `Response` (429) gdy limit przekroczony,
 * albo `null` gdy żądanie może być obsłużone dalej.
 */
export async function enforceRateLimit(
  req: Request,
  opts: RateLimitOptions,
  extraKeyPart = "",
): Promise<Response | null> {
  sweepExpired(Math.max(opts.windowSeconds * 2, 600));
  const key = await hashRateLimitKey(opts.name, clientIp(req), extraKeyPart);
  const result = checkRateLimit(key, opts);
  if (result.allowed) return null;
  return tooManyRequestsResponse(result.retryAfterSeconds);
}
