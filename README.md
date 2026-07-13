# Helios MCP

Prywatny, zdalny serwer **MCP** dla Twojej osobistej bazy wiedzy **Helios**.
Pozwala asystentom (Claude, ChatGPT) czytać Twoje notatki i — w Fazie 2 —
zapisywać nowe. Notatki **pozostają wyłącznie na Twoim Google Drive**. Ten
serwer niczego nie przechowuje: ani treści notatek, ani ich kopii.

```
ChatGPT / Claude  →  Helios MCP (Vercel)  →  Helios Drive Adapter (Apps Script)  →  Google Drive
```

- **Faza 1 (teraz): tylko odczyt.** 7 narzędzi do czytania i przeszukiwania.
- **Faza 2 (osobny pull request, po testach): zapis.** Włączana świadomie.

> Ten dokument jest napisany dla osoby nietechnicznej. Wykonuj kroki po kolei.
> Wszędzie, gdzie widzisz `TWOJE-...`, wstaw własną wartość.

---

## Zanim zaczniesz — co jest darmowe

| Usługa | Do czego | Koszt | Karta? |
|---|---|---|---|
| Vercel (plan **Hobby**) | hosting kodu serwera | 0 zł | nie |
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

> Zapis w adapterze jest domyślnie **wyłączony**. Dopóki nie ustawisz
> właściwości `WRITE_ENABLED = true`, adapter odmawia wszelkich zmian na Drive.

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

## Krok 3 — Zmienne środowiskowe Vercela

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

Nie ustawiaj `HELIOS_WRITE_ENABLED` (albo zostaw `false`) — zapis włączymy
później.

## Krok 4 — Import repozytorium GitHub

1. Wejdź na <https://vercel.com/new> i zaloguj się przez GitHub.
2. Wybierz repozytorium `helios-mcp` i kliknij **Import**.
3. Framework wykryje się automatycznie jako **Next.js**. Nic nie zmieniaj.
4. Upewnij się, że zmienne z Kroku 3 są dodane, i kliknij **Deploy**.

## Krok 5 — Preview deployment

Każda gałąź inna niż główna tworzy wdrożenie **Preview**. Po pierwszym
imporcie Vercel poda adres. Zaktualizuj `PUBLIC_BASE_URL` i **Redirect URI**
(Krok 2) o realny adres, jeśli się różni, i wdróż ponownie.

## Krok 6 — Test odczytu

Sprawdź, że publiczne metadane odpowiadają (w przeglądarce lub `curl`):

```
https://TWOJ-PROJEKT.vercel.app/.well-known/oauth-protected-resource
https://TWOJ-PROJEKT.vercel.app/.well-known/oauth-authorization-server
```

Powinny zwrócić JSON. Endpoint `/api/mcp` bez logowania musi zwracać **401**
(to poprawne — wymaga tokenu). To potwierdza, że serwer nie jest publiczny.

## Krok 7 — Production deployment

Gdy Preview działa: w Vercelu ustaw gałąź główną jako produkcyjną (domyślnie
`main`) — scalenie do niej tworzy wdrożenie **Production**. Uzupełnij Redirect
URI o adres produkcyjny.

## Krok 8 — Test w Claude

1. W Claude: **Settings → Connectors → Add custom connector** (lub „Add MCP
   server").
2. Podaj adres: `https://TWOJ-PROJEKT.vercel.app/api/mcp`.
3. Claude przeprowadzi logowanie Google. Zaloguj się kontem z `ALLOWED_EMAIL`.
4. Zapytaj: „Jaki jest status Heliosa?" — powinno zadziałać `helios_status`.
5. Sprawdź, że **inne** konto Google zostaje odrzucone.

## Krok 9 — Test w ChatGPT

1. W ChatGPT (tryb z obsługą konektorów MCP): dodaj serwer o adresie
   `https://TWOJ-PROJEKT.vercel.app/api/mcp`.
2. Przejdź logowanie Google tym samym kontem.
3. Poproś o wyszukanie notatki, aby sprawdzić `helios_search` / `helios_read_note`.

> **Warunek włączenia zapisu:** logowanie i odczyt muszą działać w **Claude
> ORAZ ChatGPT**. Dopiero wtedy przechodzimy do Fazy 2.

## Krok 10 — Włączenie zapisu (Faza 2)

Zapis dodajemy **osobnym pull requestem** i włączamy w dwóch miejscach:

1. W Apps Script: właściwość skryptu `WRITE_ENABLED = true`.
2. W Vercelu: zmienna `HELIOS_WRITE_ENABLED = true`.

Zacznij od niewielkiej notatki testowej i sprawdź, że powstaje kopia
zapasowa w `90 System/Backups`.

## Krok 11 — Rollback (cofnięcie zmian)

- **Kod / wdrożenie:** w Vercelu otwórz **Deployments**, znajdź poprzednie
  działające wdrożenie i kliknij **Promote to Production** (albo **Rollback**).
- **Notatka:** każda aktualizacja zostawia kopię w `90 System/Backups`.
  Skopiuj potrzebną wersję z powrotem na miejsce. **Nic nie jest trwale
  usuwane.**
- **Awaryjne wyłączenie zapisu:** ustaw `WRITE_ENABLED = false` w Apps Script.

## Krok 12 — Rotacja sekretów

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
npm install
npm test          # testy bezpieczeństwa (node:test + tsx)
npm run typecheck # kontrola typów lib + testów
npm run dev       # uruchomienie lokalne (wymaga .env.local)
```

Szczegóły architektury i decyzji: [`docs/PLAN.md`](docs/PLAN.md).

## Bezpieczeństwo w skrócie

- Dostęp tylko dla `ALLOWED_EMAIL`; inne konta odrzucane.
- Każde żądanie do Drive podpisane HMAC-SHA256; ochrona przed powtórzeniem
  (nonce) i starym znacznikiem czasu (±5 min).
- Blokada traversalu, ścieżek absolutnych, `%`, `\`, znaków sterujących.
- Tylko pliki `.md`, maksymalny zapis 1 MB, obowiązkowy `expectedModifiedTime`.
- Kopia zapasowa przed każdą zmianą; brak trwałego usuwania i zmian uprawnień.
- Sekrety wyłącznie w zmiennych środowiskowych; nigdy w repozytorium ani w błędach.
