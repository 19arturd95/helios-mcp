# Helios MCP

Prywatny, zdalny serwer **MCP** dla osobistej bazy wiedzy **Helios**.
Faza 1 pozwala klientom MCP czytać i przeszukiwać notatki. Nie zawiera
narzędzi ani operacji zapisu notatek. Notatki **pozostają wyłącznie na Google
Drive**. Serwer nie przechowuje ich treści ani kopii.

```
ChatGPT / Claude  →  Helios MCP (Next.js, jeszcze niewdrożony)  →  Helios Drive Adapter (Apps Script)  →  Google Drive
```

- **Faza 1 (ten PR): tylko odczyt.** 7 narzędzi do czytania i przeszukiwania.
- **Faza 2 (osobny, przyszły PR): zapis.** Kod zapisu nie istnieje w Fazie 1.

## Stan weryfikacji Fazy 1

- produkcyjny build Next.js przechodzi bez sekretów i zmiennych środowiskowych,
- testy lokalne: 117/117, bez pominiętych testów,
- oba typechecki przechodzą,
- CI dla pull requestów wykonuje `npm ci`, testy, oba typechecki i build,
- `npm audit --omit=dev`: 5 wpisów pakietów wynikających z 2 źródłowych
  advisory. Agregacja poziomów zależy od wersji npm; szczegóły znajdują się
  w sekcji „Pozostałe ryzyka zależności”,
- nie wykonano wdrożenia ani pełnych testów E2E OAuth z Google, Claude lub
  ChatGPT. Nie istnieje jeszcze projekt hostingowy ani projekt Vercel. Wybór
  hostingu i ewentualny Preview są osobnym, przyszłym etapem.

> Ten dokument jest napisany dla osoby nietechnicznej. Wykonuj kroki po kolei.
> Wszędzie, gdzie widzisz `TWOJE-...`, wstaw własną wartość.

---

## Zanim zaczniesz — co jest darmowe

| Usługa | Do czego | Koszt | Karta? |
|---|---|---|---|
| Vercel (plan **Hobby**, jeśli zostanie wybrany) | możliwy hosting kodu serwera | 0 zł | nie |
| Google Cloud — OAuth Client | logowanie przez Google | 0 zł | nie |
| Google Apps Script | dostęp do Drive | 0 zł | nie |
| Google Drive | Twoje notatki | w ramach konta | nie |

Nie używamy płatnego magazynu, Redisa ani AI Gateway. Nic nie wymaga karty.

---

## Część A. Google Drive + Helios Drive Adapter (Apps Script)

1. Na Google Drive przygotuj folder główny bazy (np. `helios`). Otwórz go i
   skopiuj z adresu przeglądarki jego **ID** (długi ciąg po `/folders/`).
2. Wejdź na <https://script.google.com> → **Nowy projekt**.
3. Usuń domyślny kod i wklej całą zawartość pliku `apps-script/Code.gs` z tego
   repozytorium.
4. W projekcie Apps Script: **Ustawienia projektu (⚙) → Właściwości skryptu →
   Dodaj właściwość** i ustaw:
   - `ROOT_FOLDER_ID` = ID folderu z kroku 1,
   - `SHARED_SECRET` = długi losowy ciąg (np. wygeneruj poleceniem
     `openssl rand -hex 32`; **zapisz go — przyda się w Kroku 3**).
5. Kliknij **Wdróż → Nowe wdrożenie → Aplikacja internetowa**:
   - „Wykonaj jako": **Ja**,
   - „Kto ma dostęp": **Każdy** (dostęp i tak chroni podpis HMAC).
6. Skopiuj **URL aplikacji internetowej** (kończy się na `/exec`). To będzie
   `APPS_SCRIPT_URL`.

> Adapter Fazy 1 nie implementuje `create`, `update`, `append`, `backup` ani
> `moveToArchive`. Właściwość `WRITE_ENABLED` nie jest obsługiwana i nie może
> włączyć zapisu. `consumeAuthCode` zapisuje wyłącznie stan jednorazowości kodu
> OAuth w Script Properties. Nie modyfikuje vaulta Helios.

---

## Część B. Krok 1 — Utworzenie Google OAuth Client

1. Wejdź na <https://console.cloud.google.com> → utwórz (lub wybierz) projekt.
2. **APIs & Services → OAuth consent screen**: wybierz „External", wpisz nazwę
   aplikacji i swój e-mail. W „Test users" dodaj swój adres Google.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**:
   - typ aplikacji: **Web application**.
4. Zapisz **Client ID** i **Client secret** — to `GOOGLE_CLIENT_ID`
   i `GOOGLE_CLIENT_SECRET`.

## Krok 2 — Redirect URI

W ustawieniach OAuth Client, w polu **Authorized redirect URIs**, dodaj dwa
adresy (drugi dodasz, gdy poznasz prawdziwy adres produkcyjny z Vercela):

```
http://localhost:3000/oauth/callback
https://TWOJ-PROJEKT.vercel.app/oauth/callback
```

> Ważne: adres musi kończyć się dokładnie na `/oauth/callback`.

## Opcjonalny przyszły etap — wdrożenie na Vercelu

> Ten etap nie został rozpoczęty. Helios nie ma obecnie projektu na Vercelu.
> Instrukcja pozostaje wariantem do użycia dopiero po osobnej decyzji o hostingu.

### Krok 3 — Zmienne środowiskowe Vercela

W Vercelu: **Project → Settings → Environment Variables**. Dodaj poniższe do
**Preview** i **Production**. Wzór (bez sekretów) jest w pliku `.env.example`.

| Nazwa | Wartość |
|---|---|
| `ALLOWED_EMAIL` | Twój adres Google — **jedyny** z dostępem |
| `PUBLIC_BASE_URL` | adres wdrożenia, np. `https://TWOJ-PROJEKT.vercel.app` |
| `APPS_SCRIPT_URL` | URL z Części A, krok 6 |
| `APPS_SCRIPT_SECRET` | ten sam `SHARED_SECRET` co w Apps Script |
| `AUTH_SECRET` | nowy losowy ciąg (`openssl rand -hex 32`) |
| `GOOGLE_CLIENT_ID` | z Kroku 1 |
| `GOOGLE_CLIENT_SECRET` | z Kroku 1 |

**Opcjonalnie** (obrona w głąb): `ALLOWED_OAUTH_REDIRECT_URIS` — dokładna
allowlista redirect_uri klientów OAuth, rozdzielona przecinkami. Zostaw
puste, dopóki nie znasz rzeczywistego redirect_uri Twojego klienta MCP —
zobaczysz go w praktyce dopiero przy pierwszym logowaniu (Krok 8/9). Główną
obroną jest i tak obowiązkowy **ekran zgody** (patrz Krok 8 poniżej). Po
poznaniu realnego redirect_uri możesz go dopisać do tej listy, żeby zawęzić
akceptowane rejestracje DCR — patrz `.env.example` po szczegóły formatu.

### Krok 4 — Import repozytorium GitHub

1. Wejdź na <https://vercel.com/new> i zaloguj się przez GitHub.
2. Wybierz repozytorium `helios-mcp` i kliknij **Import**.
3. Framework wykryje się automatycznie jako **Next.js**. Nic nie zmieniaj.
4. Upewnij się, że zmienne z Kroku 3 są dodane, i kliknij **Deploy**.

### Krok 5 — Preview deployment

Każda gałąź inna niż główna tworzy wdrożenie **Preview**. Po pierwszym
imporcie Vercel poda adres. Zaktualizuj `PUBLIC_BASE_URL` i **Redirect URI**
(Krok 2) o realny adres, jeśli się różni, i wdróż ponownie.

### Krok 6 — Test odczytu

Sprawdź, że publiczne metadane odpowiadają (w przeglądarce lub `curl`):

```
https://TWOJ-PROJEKT.vercel.app/.well-known/oauth-protected-resource
https://TWOJ-PROJEKT.vercel.app/.well-known/oauth-authorization-server
```

Powinny zwrócić JSON. Endpoint `/api/mcp` bez logowania musi zwracać **401**
(to poprawne — wymaga tokenu). To potwierdza, że serwer nie jest publiczny.

### Krok 7 — Production deployment

Gdy Preview działa: w Vercelu ustaw gałąź główną jako produkcyjną (domyślnie
`main`) — scalenie do niej tworzy wdrożenie **Production**. Uzupełnij Redirect
URI o adres produkcyjny.

### Krok 8 — Test w Claude

1. W Claude: **Settings → Connectors → Add custom connector** (lub „Add MCP
   server").
2. Podaj adres: `https://TWOJ-PROJEKT.vercel.app/api/mcp`.
3. Zobaczysz nasz **ekran zgody** („Żądanie dostępu") — pokazuje nazwę
   klienta i host, do którego wrócisz po zalogowaniu. Kliknij **Zezwól**
   tylko jeśli sam(a) zainicjowałeś(aś) to logowanie w zaufanej aplikacji.
4. Dopiero po kliknięciu „Zezwól" nastąpi przekierowanie do logowania Google.
   Zaloguj się kontem z `ALLOWED_EMAIL`.
5. Zapytaj: „Jaki jest status Heliosa?" — powinno zadziałać `helios_status`.
6. Sprawdź, że **inne** konto Google zostaje odrzucone.
7. Kliknij **Odrzuć** na ekranie zgody przy kolejnej próbie i sprawdź, że
   logowanie kończy się bez dostępu (bez przekierowania do Google).

### Krok 9 — Test w ChatGPT

1. W ChatGPT (tryb z obsługą konektorów MCP): dodaj serwer o adresie
   `https://TWOJ-PROJEKT.vercel.app/api/mcp`.
2. Przejdź logowanie Google tym samym kontem.
3. Poproś o wyszukanie notatki, aby sprawdzić `helios_search` / `helios_read_note`.

> **Warunek rozpoczęcia Fazy 2:** logowanie i odczyt muszą działać w **Claude
> ORAZ ChatGPT**. Dopiero wtedy projektujemy zapis w osobnym PR.

### Krok 10 — Faza 2

Faza 2 wymaga osobnego projektu zmian i osobnego pull requesta. Musi ponownie
wprowadzić operacje zapisu wraz z backupem, kontrolą `expectedModifiedTime`,
idempotencją oraz osobnymi testami bezpieczeństwa. Nie da się jej włączyć
zmienną środowiskową lub właściwością Apps Script w kodzie Fazy 1.

### Krok 11 — Rollback (cofnięcie zmian)

- **Kod / wdrożenie:** w Vercelu otwórz **Deployments**, znajdź poprzednie
  działające wdrożenie i kliknij **Promote to Production** (albo **Rollback**).
- **Notatki:** Faza 1 ich nie modyfikuje, więc nie tworzy kopii zapasowych i
  nie wymaga rollbacku danych.

### Krok 12 — Rotacja sekretów

Rób to okresowo lub przy podejrzeniu wycieku:

1. `APPS_SCRIPT_SECRET` / `SHARED_SECRET`: wygeneruj nowy ciąg i zmień go
   **jednocześnie** w Vercelu i w Apps Script (muszą być identyczne).
2. `AUTH_SECRET`: zmień w Vercelu — spowoduje to wylogowanie i konieczność
   ponownego zalogowania w Claude/ChatGPT (to normalne).
3. `GOOGLE_CLIENT_SECRET`: wygeneruj nowy w Google Cloud i zaktualizuj w Vercelu.

Po każdej zmianie wdróż ponownie i wykonaj Krok 8–9.

---

## Dla programisty (opcjonalnie)

```bash
npm ci
npm test              # testy bezpieczeństwa (node:test + tsx)
npm run typecheck     # kontrola typów lib + testów + endpointów API
npm run typecheck:app # kontrola typów całej aplikacji Next.js
npm run build         # produkcyjny build Next.js, działa bez sekretów
npm run dev           # uruchomienie lokalne (wymaga .env.local)
```

## Pozostałe ryzyka zależności

Po aktualizacji do `next@15.5.22`, `fast-uri@3.1.5`,
`@hono/node-server@1.19.17` i bezpiecznego `postcss@8.5.25`, wynik
`npm audit --omit=dev` zawiera te same 5 wpisów pakietów. npm 10.9.4
(wersja odpowiadająca CI na Node 20) agreguje je jako 2 umiarkowane i 3
wysokie, a npm 11.9.0 jako 3 umiarkowane i 2 wysokie. Różnica dotyczy
wyłącznie agregującego wpisu `mcp-handler`, nie zestawu advisory ani kodu.

- `@hono/node-server` i wynikowy wpis `@modelcontextprotocol/sdk`, 2
  umiarkowane pozycje, dotyczą tego samego traversalu w `serve-static` na
  Windows. CI i lokalny build kontrolny działają na Linuxie, a Helios nie
  używa API `serve-static`; pakiet nie występuje w trace żadnej trasy
  aplikacji. To
  istotnie ogranicza osiągalność, ale nie jest gwarancją braku ryzyka.
  Poprawka wskazana przez npm wymaga migracji z `mcp-handler@1.1.0` do 2.x,
  czyli zmiany major i nowego pakietu serwera MCP. Nie została wykonana bez
  osobnego testu kompatybilności protokołu.
- `sharp@0.34.5`, wynikowy wpis `next` oraz agregujący ich zależności wpis
  `mcp-handler`, 3 wysokie pozycje, obejmują podatności libvips. Wpis
  `mcp-handler` nie jest trzecią niezależną podatnością źródłową; ma poziom
  wysoki, ponieważ zależy jednocześnie od `next` i podatnego łańcucha SDK.
  Helios nie używa `next/image` ani nie przetwarza obrazów, ale
  `sharp` znajduje się w ogólnym trace serwera Next.js, więc nie deklarujemy
  go jako całkowicie nieosiągalnego. Stabilna poprawka wymaga `sharp@0.35.x`,
  poza zakresem `^0.34.3` deklarowanym przez Next.js 15.5.22. Wymuszenie
  nieobsługiwanej wersji albo downgrade Next.js nie zostały zastosowane.

Szczegóły architektury i decyzji: [`docs/PLAN.md`](docs/PLAN.md).

## Bezpieczeństwo w skrócie

- Dostęp tylko dla `ALLOWED_EMAIL`; inne konta odrzucane.
- OAuth przyjmuje wyłącznie scope `helios.read`, wymaga kanonicznego parametru
  `resource` w obu etapach i ponownie sprawdza audience po stronie MCP.
- PKCE S256 ma walidowany format 43-znakowego challenge oraz verifiera o
  długości 43–128 znaków. Odpowiedzi autoryzacyjne zawierają `iss` (RFC 9207).
- **Ekran zgody** na `/oauth/authorize` — zawsze pokazuje nazwę klienta OAuth
  i host redirect_uri, zanim rozpocznie się logowanie Google. Kod
  autoryzacyjny NIGDY nie jest wydawany bez świadomego kliknięcia „Zezwól".
  Formularz zgody chroniony przed CSRF przez wymagany double-submit cookie
  oraz dodatkową walidację `Origin` / `Sec-Fetch-Site`. Izolowany popup OAuth
  może wysłać `Origin: null`, ale jest akceptowany tylko przy
  `Sec-Fetch-Site: same-origin` i prawidłowym cookie.
- Opcjonalna allowlista `ALLOWED_OAUTH_REDIRECT_URIS` (dokładne dopasowanie,
  fail-closed) jako dodatkowa warstwa obok ekranu zgody.
- Kod autoryzacyjny jest **jednorazowy**: atomowe zużycie `jti` przez Helios
  Drive Adapter (Apps Script `LockService` + `PropertiesService`) — druga
  próba wymiany tego samego kodu jest odrzucana.
- Każde żądanie do Drive podpisane HMAC-SHA256; ochrona przed powtórzeniem
  (nonce, check-and-set atomowy przez `LockService`) i starym znacznikiem
  czasu (±5 min).
- Blokada traversalu, ścieżek absolutnych, `%`, `\`, znaków sterujących.
- Odczyt pojedynczej notatki jest ograniczony do ścieżek względnych `.md`
  i maksymalnie 200 KiB treści.
- **Limity `listTree`/`search`** chronią przed DoS przez wyliczanie całego
  Drive: maks. 500 węzłów drzewa (`MAX_TREE_NODES`), maks. 800 przejrzanych
  plików (`MAX_SEARCH_SCAN`), maks. 200 odczytów treści pliku
  (`MAX_SEARCH_CONTENT_READS`) oraz łącznie 2 MiB skanowanej treści
  (`MAX_SEARCH_CONTENT_BYTES`) — stałe zdefiniowane w `apps-script/Code.gs`.
  Obcięty wynik ma `truncated: true`.
- `/api/mcp` zwraca kompletne CORS także dla preflight, 401 i 403; klient
  webowy może odczytać `WWW-Authenticate` i wskazany scope `helios.read`.
- **Rate limiting** (best effort, bez płatnej infrastruktury) na
  `/oauth/register`, `/oauth/authorize`, `/oauth/callback`, `/oauth/token` i
  `/api/mcp` — zwraca
  `429` + `Retry-After` po przekroczeniu limitu. Ogranicznik działa w pamięci
  procesu pojedynczej instancji serverless (typowy hosting serverless, w tym
  ewentualny Vercel Hobby, nie gwarantuje
  współdzielenia stanu między instancjami) — to warstwa odstraszająca, nie
  twarda gwarancja globalnego limitu. Klucz limitu to hash (IP + trasa),
  nigdy jawny e-mail/token; nagłówek `x-forwarded-for` traktowany jako
  podpowiedź, nie uwierzytelniony fakt.
- Adapter nie zawiera funkcji zapisu, przenoszenia, usuwania ani zmiany
  uprawnień plików Helios.
- Sekrety wyłącznie w zmiennych środowiskowych; nigdy w repozytorium ani w błędach.
