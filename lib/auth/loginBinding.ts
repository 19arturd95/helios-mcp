/**
 * Powiązanie logowania Google z konkretną przeglądarką.
 *
 * PROBLEM (bez tego mechanizmu): `/oauth/consent` przekierowywał do Google
 * z podpisanym `state`, a `/oauth/callback` akceptował ten `state` od
 * DOWOLNEJ przeglądarki. Atakujący mógł więc:
 *   1. zarejestrować własnego klienta (otwarty DCR) z własnym redirect_uri,
 *   2. samodzielnie przejść ekran zgody i przechwycić gotowy adres
 *      `accounts.google.com/...?state=...`,
 *   3. podesłać ten adres ofierze (adres jest autentycznie Google!),
 *   4. odebrać na własnym redirect_uri kod autoryzacyjny wystawiony na
 *      konto OFIARY i wymienić go na access token.
 *
 * ROZWIĄZANIE: przy kliknięciu „Zezwól" ustawiamy losowe, jednorazowe
 * ciasteczko `helios_login` i zapisujemy jego SHA-256 w podpisanym `state`.
 * `/oauth/callback` wymaga, aby przeglądarka przedstawiła ciasteczko zgodne
 * ze skrótem ze `state`. Link przygotowany przez atakującego nie zadziała
 * w przeglądarce ofiary, bo ta nie ma jego ciasteczka.
 *
 * W `state` trzymamy WYŁĄCZNIE skrót — payload JWT jest jawnie czytelny po
 * zdekodowaniu base64, więc surowa wartość ciasteczka nie może tam trafić.
 *
 * Ciasteczko ma `SameSite=Lax`, co jest konieczne i wystarczające: powrót
 * z Google to nawigacja najwyższego poziomu metodą GET, dla której
 * przeglądarki wysyłają ciasteczka Lax.
 */

/** Nazwa ciasteczka wiążącego logowanie z przeglądarką. */
export const LOGIN_COOKIE = "helios_login";

/** TTL ciasteczka. Musi pokrywać TTL `state` (600 s) z zapasem na logowanie. */
export const LOGIN_TTL_SECONDS = 900;

/** Buduje nagłówek `set-cookie` ustawiający lub czyszczący ciasteczko wiążące. */
export function loginCookieHeader(value: string | null, isHttps: boolean): string {
  const secure = isHttps ? "; Secure" : "";
  return value === null
    ? `${LOGIN_COOKIE}=; Path=/oauth/callback; Max-Age=0; HttpOnly; SameSite=Lax${secure}`
    : `${LOGIN_COOKIE}=${value}; Path=/oauth/callback; Max-Age=${LOGIN_TTL_SECONDS}; HttpOnly; SameSite=Lax${secure}`;
}

/**
 * Odczytuje dokładnie jedno ciasteczko o danej nazwie. Duplikaty (np. wstrzyknięte
 * przez cookie tossing z innej ścieżki/domeny) są niejednoznaczne — fail closed.
 */
export function readSingleCookie(cookieHeader: string | null, name: string): string | undefined {
  const values: string[] = [];
  for (const part of (cookieHeader ?? "").split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) values.push(rest.join("="));
  }
  return values.length === 1 ? values[0] : undefined;
}
