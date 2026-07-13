# Helios MCP — plan architektury i decyzje

Dokument techniczny towarzyszący `README.md`. Opisuje architekturę, wybór
OAuth (i jego ryzyka), strukturę plików, koszty oraz podział na fazy.

## 1. Architektura

```
ChatGPT / Claude / klient MCP
        │  OAuth Bearer token (Streamable HTTP)
        ▼
Helios MCP  =  Next.js (App Router) na Vercel Hobby   →  /api/mcp
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
- **Notatki**: żyją tylko na Drive. Vercel i repozytorium nie przechowują treści.

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
   JWT** kodujący `redirect_uris` — brak bazy danych.
3. `/oauth/authorize` (PKCE S256) waliduje żądanie i przekierowuje użytkownika
   do logowania Google; oryginalne parametry przenosi podpisany `state`.
4. `/oauth/callback` wymienia kod Google, weryfikuje `id_token` przez JWKS
   Google, sprawdza `ALLOWED_EMAIL`, a następnie wystawia **nasz** krótki kod.
5. `/oauth/token` weryfikuje kod + PKCE i wystawia **access token** (JWT,
   audience = `/api/mcp`, TTL 1 h).
6. `/api/mcp` (`withMcpAuth`) weryfikuje token i ponownie sprawdza e-mail.

Stan jest **bezstanowy** (wszystko podpisane `AUTH_SECRET`), więc nie
potrzebujemy Redisa ani bazy — zgodnie z planem Hobby.

**Ryzyka:**
- *Interoperacyjność*: różne klienty MCP bywają wybredne wobec DCR/metadanych.
  Dlatego **zapis (Faza 2) włączamy dopiero po realnym teście z Claude i
  ChatGPT** (Krok 8–9 w README).
- *Unieważnianie tokenu*: przy modelu bezstanowym trudniejsze → krótki TTL
  (1 h) i rotacja `AUTH_SECRET` (natychmiast unieważnia wszystkie tokeny).
- *Brak testu E2E offline*: pełny handshake testujemy dopiero na Preview.
  Testy jednostkowe pokrywają logikę kryptograficzną (PKCE, JWT, e-mail).

## 3. Struktura plików

```
app/
  api/mcp/route.ts                                  # MCP (7 narzędzi read-only) + withMcpAuth
  .well-known/oauth-protected-resource/route.ts     # RFC 9728
  .well-known/oauth-authorization-server/route.ts   # RFC 8414
  oauth/register/route.ts                           # Dynamic Client Registration
  oauth/authorize/route.ts                          # authorization_code + PKCE → Google
  oauth/callback/route.ts                           # weryfikacja Google + ALLOWED_EMAIL
  oauth/token/route.ts                              # wymiana kodu na access token
  layout.tsx, page.tsx                              # minimalna strona (bez danych)
lib/
  config.ts             # odczyt env, redakcja sekretów
  http.ts               # odpowiedzi + CORS
  security/paths.ts     # traversal, absolutne, %, \, Unicode NFC, .md, rozmiar 1 MB
  security/signing.ts   # postać kanoniczna + HMAC (Web Crypto)
  security/conflict.ts  # expectedModifiedTime → konflikt
  drive/client.ts       # podpisane żądanie do Apps Script (bez wycieku sekretów)
  drive/types.ts
  auth/tokens.ts        # JWT: client_id / kod / state / access token + PKCE
  auth/verifyToken.ts   # Resource Server: Bearer → e-mail → ALLOWED_EMAIL
  auth/metadata.ts      # metadane OAuth
  tools/handlers.ts     # logika 7 narzędzi (czyste funkcje)
  tools/schemas.ts      # walidacja Zod
  tools/constants.ts    # ścieżki struktury Helios
apps-script/Code.gs     # kompletny adapter; pure-funkcje testowalne w Node
test/                   # 15 kategorii testów bezpieczeństwa (node:test + tsx)
```

## 4. Zewnętrzne usługi i koszty

| Usługa | Rola | Koszt | Karta |
|---|---|---|---|
| Vercel Hobby | hosting `/api/*` | 0 zł | nie |
| Google Cloud OAuth Client | logowanie | 0 zł | nie |
| Google Apps Script | adapter Drive | 0 zł (limity dzienne) | nie |
| Google Drive | notatki | konto | nie |
| next / mcp-handler / jose / zod | biblioteki OSS | 0 zł | nie |
| Redis / storage / AI Gateway | **nie używane** | — | — |

## 5. Fazy

- **Faza 1 (ten kod): tylko odczyt.** Narzędzia: `helios_status`,
  `helios_get_context`, `helios_search`, `helios_read_note`, `helios_list_tree`,
  `helios_inbox_status`, `helios_review_inbox`.
- **Faza 2 (osobny PR, po testach OAuth): zapis.** Narzędzia:
  `helios_commit_memory`, `helios_capture_raw`, `helios_apply_inbox_plan`,
  `helios_create_backup`, `helios_move_to_archive`. Warstwa adaptera i
  bezpieczeństwa jest już gotowa (walidacja ścieżek, konflikt wersji, kopie),
  a operacje zapisu są **domyślnie zablokowane** dwoma bezpiecznikami:
  `HELIOS_WRITE_ENABLED` (MCP) oraz `WRITE_ENABLED` (Apps Script).

## 6. Testy bezpieczeństwa (uruchamiane: `npm test`)

Pokryte kategorie: poprawny odczyt, path traversal, zakodowany traversal,
zapis poza folderem (ścieżka absolutna), konflikt wersji, błędny HMAC, stary
timestamp, ponowny nonce, zbyt duży zapis, niedozwolone rozszerzenie, brak
tokenu OAuth, błędny token, dozwolony `ALLOWED_EMAIL`, odrzucenie innego
adresu, brak wycieku sekretów.

Zasada kluczowa: testy weryfikują **realne** funkcje `apps-script/Code.gs`
(ładowane do Node przez `vm`), a nie ich kopię — dzięki temu podpis tworzony
przez MCP (Web Crypto) jest faktycznie akceptowany przez adapter.
