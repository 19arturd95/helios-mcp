# Helios MCP — plan architektury i decyzje

Dokument techniczny towarzyszący `README.md`. Opisuje architekturę, wybór
OAuth (i jego ryzyka), strukturę plików, koszty oraz podział na fazy.

## 1. Architektura

```
ChatGPT / Claude / klient MCP
        │  OAuth Bearer token (Streamable HTTP)
        ▼
Helios MCP  =  Next.js (App Router), hosting jeszcze niewybrany   →  /api/mcp
        │  JSON: { timestamp, nonce, payload, signature }  (HMAC-SHA256)
        ▼
Helios Drive Adapter  =  Google Apps Script Web App
        │  Drive API, wyłącznie wewnątrz ROOT_FOLDER_ID
        ▼
Google Drive / folder „helios" (pliki .md)
```

Granice zaufania:
- **Klient ↔ MCP**: chroniony OAuth-em. Tylko `ALLOWED_EMAIL`.
- **MCP ↔ Apps Script**: chroniony podpisem HMAC + nonce + oknem czasu.
- **Notatki**: żyją tylko na Drive. Serwer MCP i repozytorium nie przechowują treści.

## 2. OAuth — wybór i ryzyka

Wybrano **Opcję A: własny serwer autoryzacji, Google jako logowanie**.

Dlaczego nie „po prostu Google": zdalni klienci MCP wymagają serwera
autoryzacji z **Dynamic Client Registration** i tokenami, których *audience*
to nasz zasób `/api/mcp`. Google tego nie zapewnia, więc Google pełni rolę
wyłącznie **upstream login**, a rolę serwera autoryzacji pełni nasza aplikacja.

Przepływ:
1. Klient MCP odkrywa `/.well-known/oauth-protected-resource` → wskazuje nasz
   serwer autoryzacji (`/.well-known/oauth-authorization-server`).
2. Klient rejestruje się w `/oauth/register` (DCR). `client_id` to **podpisany
   JWT** kodujący `redirect_uris`, z `exp` (domyślnie 30 dni) — brak bazy
   danych. Redirect_uris muszą być `https` (lub `http://localhost` wyłącznie
   w trybie development) i — jeśli skonfigurowano `ALLOWED_OAUTH_REDIRECT_URIS`
   — dokładnie wymienione na tej allowliście (fail-closed, bez wildcardów).
3. `/oauth/authorize` wymaga kanonicznego `resource`, wyłącznie scope
   `helios.read` oraz prawidłowego PKCE S256, po czym renderuje **ekran
   zgody** (HTML, GET) — pokazuje nazwę klienta i host redirect_uri.
   NIE przekierowuje automatycznie do Google.
4. Użytkownik świadomie klika „Zezwól" → `POST /oauth/consent` (chronione
   przed CSRF przez wymagany double-submit cookie i dodatkową walidację
   `Origin` / `Sec-Fetch-Site`; `Origin: null` z izolowanego popupu jest
   akceptowany tylko przy `Sec-Fetch-Site: same-origin`, stan zgody to
   podpisany, krótkożyciowy JWT — `AUD_CONSENT`, TTL 5 min). Dopiero **teraz** następuje
   przekierowanie do logowania Google; oryginalne parametry klienta przenosi podpisany
   `state` (`AUD_STATE`). „Odrzuć" (lub nieprawidłowa/wygasła zgoda) kończy
   proces przekierowaniem do klienta z `error=access_denied`, bez logowania
   do Google i bez wydania kodu.
5. `/oauth/callback` wymienia kod Google, weryfikuje `id_token` przez JWKS
   Google (issuer/audience), sprawdza `email_verified` i `ALLOWED_EMAIL`
   (wydzielone do `lib/auth/googleIdentity.ts`), a następnie wystawia
   **nasz** krótki kod autoryzacyjny (z losowym `jti`).
6. `/oauth/token` wymaga `client_id`/`redirect_uri`/`resource` (dokładna
   zgodność z kodem i zasobem `/api/mcp`), weryfikuje PKCE i scope
   `helios.read`, sprawdza e-mail (obrona w głąb), a następnie
   **atomowo zużywa `jti`** przez Helios Drive Adapter
   (`consumeAuthCode` — Apps Script `LockService` + `PropertiesService`,
   przechowuje wyłącznie `jti` + `exp`, nigdy kod/token) — druga wymiana
   tego samego kodu jest odrzucana (`invalid_grant`). Awaria adaptera →
   odmowa (fail-closed), nie ryzykujemy powtórnego użycia. Dopiero wtedy
   wystawiany jest **access token** (JWT, audience = `/api/mcp`, TTL 1 h).
7. `/api/mcp` (`withMcpAuth`) weryfikuje token, audience, scope i e-mail.
   Challenge 401 wskazuje stałe `resource_metadata` z `PUBLIC_BASE_URL` oraz
   scope `helios.read`; pełne CORS obejmuje również 401/403 i preflight.

Stan jest w większości **bezstanowy** (wszystko podpisane `AUTH_SECRET`);
jedynym stanem serwerowym jest zbiór zużytych `jti` kodów autoryzacyjnych
(Apps Script `PropertiesService`, z auto-czyszczeniem wygasłych wpisów) —
nadal bez Redisa i bez bazy danych, zgodnie z planem Hobby.

**Ryzyka:**
- *Interoperacyjność*: różne klienty MCP bywają wybredne wobec DCR/metadanych.
  Dlatego **prace nad zapisem w Fazie 2 zaczynamy dopiero po realnym teście z
  Claude i ChatGPT** (Krok 8–9 w README).
- *Unieważnianie tokenu*: przy modelu bezstanowym trudniejsze → krótki TTL
  (1 h) i rotacja `AUTH_SECRET` (natychmiast unieważnia wszystkie tokeny).
- *Brak testu E2E offline*: pełny handshake (w tym weryfikacja `id_token`
  przez prawdziwe JWKS Google) testujemy dopiero po wdrożeniu testowym — `jose` na
  Node pobiera JWKS przez `node:https` bezpośrednio, z pominięciem globalnego
  `fetch`, więc nie da się tego sensownie zamockować w testach jednostkowych.
  Logika decyzyjna PO weryfikacji podpisu (email/email_verified/ALLOWED_EMAIL)
  jest wydzielona do `lib/auth/googleIdentity.ts` i w pełni testowana.
- *Rate limiting jest best-effort*: licznik działa w pamięci pojedynczej
  instancji serverless — typowy hosting serverless nie gwarantuje współdzielenia
  stanu między instancjami/cold-startami. To warstwa odstraszająca, nie
  twarda gwarancja globalnego limitu (patrz README).
- *Otwarty DCR*: złagodzony obowiązkowym ekranem zgody (użytkownik zawsze
  widzi, do jakiego klienta/hosta trafi) oraz opcjonalną allowlistą
  `ALLOWED_OAUTH_REDIRECT_URIS`.

## 3. Struktura plików

```
app/
  api/mcp/route.ts                                  # MCP (7 narzędzi read-only) + withMcpAuth + rate limit
  .well-known/oauth-protected-resource/route.ts     # RFC 9728
  .well-known/oauth-authorization-server/route.ts   # RFC 8414
  oauth/register/route.ts                           # Dynamic Client Registration
  oauth/authorize/route.ts                          # waliduje żądanie, renderuje EKRAN ZGODY (nie redirectuje do Google)
  oauth/consent/route.ts                             # decyzja użytkownika (POST, CSRF) → dopiero teraz Google
  oauth/callback/route.ts                           # weryfikacja Google + ALLOWED_EMAIL
  oauth/token/route.ts                              # wymiana kodu na access token + jednorazowe zużycie jti
  layout.tsx, page.tsx                              # minimalna strona (bez danych)
lib/
  config.ts               # odczyt env, redakcja sekretów, allowlista redirect, tryb dev
  http.ts                 # odpowiedzi + CORS + nagłówki bezpieczeństwa HTML
  security/paths.ts       # traversal, absolutne, %, \, Unicode NFC, .md
  security/signing.ts     # postać kanoniczna + HMAC (Web Crypto)
  security/redirect.ts    # allowlista redirect_uri (fail-closed, dokładne dopasowanie)
  security/rateLimit.ts   # rate limiting w pamięci procesu (best effort)
  drive/client.ts         # podpisane żądanie do Apps Script (bez wycieku sekretów)
  drive/types.ts
  auth/tokens.ts          # JWT: client_id / kod (z jti) / state / zgoda / access token + PKCE
  auth/constants.ts       # jedyny scope Fazy 1
  auth/verifyToken.ts     # Resource Server: Bearer → e-mail → ALLOWED_EMAIL
  auth/googleIdentity.ts  # ocena tożsamości Google (email/email_verified) — czysta funkcja
  auth/metadata.ts        # metadane OAuth
  tools/handlers.ts       # logika 7 narzędzi (czyste funkcje)
  tools/schemas.ts        # walidacja Zod
  tools/constants.ts      # ścieżki struktury Helios
apps-script/Code.gs       # adapter tylko do odczytu; limity listTree/search,
                          # consumeAuthCode (jednorazowość kodu OAuth)
.github/workflows/ci.yml  # Node 20: npm ci, testy, typechecki, build
test/                     # testy bezpieczeństwa (node:test + tsx), w tym testy
                          # endpointów OAuth przez bezpośrednie wywołanie route handlerów
```

## 4. Zewnętrzne usługi i koszty

| Usługa | Rola | Koszt | Karta |
|---|---|---|---|
| Vercel Hobby (opcjonalnie) | możliwy hosting `/api/*` | 0 zł | nie |
| Google Cloud OAuth Client | logowanie | 0 zł | nie |
| Google Apps Script | adapter Drive | 0 zł (limity dzienne) | nie |
| Google Drive | notatki | konto | nie |
| next / mcp-handler / jose / zod | biblioteki OSS | 0 zł | nie |
| Redis / storage / AI Gateway | **nie używane** | — | — |

## 5. Fazy

- **Faza 1 (ten kod): tylko odczyt.** Narzędzia: `helios_status`,
  `helios_get_context`, `helios_search`, `helios_read_note`, `helios_list_tree`,
  `helios_inbox_status`, `helios_review_inbox`.
- **Faza 2 (osobny PR, po testach OAuth): zapis.** Planowane narzędzia:
  `helios_commit_memory`, `helios_capture_raw`, `helios_apply_inbox_plan`,
  `helios_create_backup`, `helios_move_to_archive`. Faza 1 nie zawiera ich
  handlerów, typów ani operacji Apps Script. Nie istnieje przełącznik, który
  może włączyć zapis. Faza 2 musi osobno wprowadzić backup, kontrolę
  `expectedModifiedTime`, limity rozmiaru oraz trwałą idempotencję, aby retry
  sieciowy nie zastosował tej samej zmiany dwukrotnie.

## 6. Testy bezpieczeństwa (uruchamiane: `npm test`)

Pokryte kategorie: poprawny odczyt, path traversal, zakodowany traversal,
ścieżka absolutna, błędny HMAC, stary timestamp, ponowny nonce,
niedozwolone rozszerzenie, brak
tokenu OAuth, błędny token, dozwolony `ALLOWED_EMAIL`, odrzucenie innego
adresu, brak wycieku sekretów — oraz (po audycie bezpieczeństwa): ekran
zgody (renderowanie, CSRF, odrzucenie, wygasły/podrobiony stan), allowlista
i walidacja redirect_uri (w tym ochrona przed open redirect), DCR (wygasły
`client_id`), PKCE (brak, zła metoda, format i zły `code_verifier`), wymagany
`client_id`/`redirect_uri`/`resource` w `/oauth/token`, jednorazowość kodu
autoryzacyjnego (replay odrzucony przez `consumeAuthCode`), wygasły kod,
`email_verified`/`ALLOWED_EMAIL` (`googleIdentity`), limity `listTree`/
`search` (`truncated`, limity liczby i bajtów), limit 200 KiB pojedynczej
notatki, CORS MCP dla preflight/401/403, scope `helios.read`, brak operacji i
eksportów zapisu w Code.gs niezależnie
od właściwości skryptu, nieznana operacja Apps Script, `assertDescendant_`
dla pliku spoza `ROOT_FOLDER_ID`, rate limiting (`429` + `Retry-After`).

Zasada kluczowa: testy weryfikują **realne** funkcje `apps-script/Code.gs`
(ładowane do Node przez `vm`, z w pełni podstawionym fałszywym
DriveApp/PropertiesService/CacheService/LockService/Utilities — patrz
`test/helpers/appsScript.ts`) oraz **realne** handlery Next.js (importowane
bezpośrednio i wywoływane z prawdziwym obiektem `Request`) — nie ich kopie.
Wyjątek: pełna weryfikacja `id_token` przez JWKS Google w `/oauth/callback`
nie jest testowana na poziomie HTTP (jose na Node pobiera JWKS przez
`node:https`, z pominięciem globalnego `fetch`, więc nie da się tego
sensownie zamockować) — logika PO weryfikacji podpisu jest wydzielona do
`lib/auth/googleIdentity.ts` i tam w pełni testowana.

Aktualny wynik: 117 testów, 117 zaliczonych, 0 pominiętych. Oba typechecki i
produkcyjny build Next.js przechodzą. Build nie wymaga sekretów. Pełny E2E
OAuth z prawdziwym Google JWKS oraz klientami Claude i ChatGPT nie został
wykonany, ponieważ nie ma jeszcze wybranego ani skonfigurowanego hostingu.

## 7. Zależności i audyt

Kontrolowane aktualizacje w Fazie 1:

- `next` 15.5.20 → 15.5.22,
- `fast-uri` 3.1.3 → 3.1.5,
- `@hono/node-server` 1.19.14 → 1.19.17,
- `postcss` 8.4.31 → 8.5.25 przez override zgodny z major wersją.

Usunęły one podatności bezpośrednie Next.js, `fast-uri` i PostCSS. Aktualny
`npm audit --omit=dev` raportuje te same 5 wpisów pakietów. npm 10.9.4
(CI/Node 20) grupuje je jako 2 umiarkowane i 3 wysokie, a npm 11.9.0 jako 3
umiarkowane i 2 wysokie. Zmienia się wyłącznie agregacja wpisu `mcp-handler`;
źródłem pozostają te same 2 advisory opisane poniżej.

1. `@hono/node-server` i wynikowy wpis `@modelcontextprotocol/sdk` to 2
   umiarkowane pozycje opisujące jeden traversal w `serve-static` na Windows.
   CI i lokalny build kontrolny działają na Linuxie, Helios nie wywołuje
   `serve-static`, a pakiet nie trafia do trace tras builda. Osiągalność jest
   więc niska, lecz nie zerowa z gwarancją. Hosting na Windows wymagałby
   ponownej oceny. Poprawka wymaga migracji `mcp-handler` 1.x → 2.x i osobnej
   walidacji kompatybilności.
2. `sharp`, wynikowy wpis `next` oraz agregujący ich zależności wpis
   `mcp-handler` to 3 wysokie pozycje obejmujące libvips. `mcp-handler` nie
   opisuje trzeciej niezależnej podatności źródłowej; jest klasyfikowany jako
   wysoki, bo zależy jednocześnie od `next` i podatnego łańcucha SDK. Helios
   nie ma obrazów ani `next/image`, lecz `sharp` jest obecny w ogólnym trace
   serwera Next.js. Poprawiona linia `sharp@0.35.x` leży poza zakresem
   wspieranym przez `next@15.5.22` (`^0.34.3`). Nie wymuszono nieobsługiwanej
   wersji.

Nie użyto `npm audit fix --force`. Pozostałe ryzyka muszą zostać ponownie
ocenione przed Production lub przy migracji głównych zależności.
