/** Pomocnicze odpowiedzi HTTP (Web API `Response`), z nagłówkami CORS. */

// CORS musi pozostać szeroki (Origin: *) — klienci MCP (Claude, ChatGPT) łączą
// się z różnych, nieprzewidywalnych originów (aplikacje desktopowe/mobilne bez
// stałej domeny). Żaden z tych endpointów nie polega na ciasteczkach sesyjnych
// jako uwierzytelnieniu (Bearer token w nagłówku, nie cookie), więc szeroki
// CORS nie osłabia izolacji — patrz README → „CORS”.
export function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
    "access-control-allow-headers":
      "authorization, content-type, mcp-protocol-version, mcp-session-id, last-event-id",
    "access-control-expose-headers": "www-authenticate, mcp-session-id",
    "access-control-max-age": "86400",
    "cache-control": "no-store",
  };
}

export function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders(), ...extraHeaders },
  });
}

/**
 * Dodaje CORS do dowolnej odpowiedzi. Opcjonalnie uzupełnia challenge Bearer
 * o wymagany scope, czego potrzebują klienci MCP przy odpowiedziach 401/403.
 */
export function withCors(response: Response, requiredScope?: string): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(corsHeaders())) headers.set(name, value);

  if (requiredScope && (response.status === 401 || response.status === 403)) {
    const challenge = headers.get("www-authenticate");
    if (challenge && !/(?:^|[, ])scope=/i.test(challenge)) {
      headers.set("www-authenticate", `${challenge}, scope="${requiredScope}"`);
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/** Odpowiedź błędu OAuth zgodna z RFC 6749 (bez wycieku sekretów/stack trace). */
export function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status);
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export function htmlError(
  title: string,
  message: string,
  status = 400,
  extraHeaders: Record<string, string> = {},
): Response {
  const body = `<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>` +
    `<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">` +
    `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></body>`;
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...htmlSecurityHeaders(),
      ...extraHeaders,
    },
  });
}

/**
 * Zamienia zweryfikowane adresy przekierowań na bezpieczne źródła CSP.
 * Do nagłówka trafia wyłącznie origin HTTP(S), nigdy ścieżka, zapytanie ani
 * surowa wartość, która mogłaby wstrzyknąć kolejną dyrektywę.
 */
function formActionOrigins(urls: readonly string[]): string[] {
  const origins = new Set<string>();
  for (const value of urls) {
    try {
      const url = new URL(value);
      const isHttps = url.protocol === "https:";
      const isLocalHttp =
        url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
      if ((isHttps || isLocalHttp) && url.origin !== "null") {
        origins.add(url.origin);
      }
    } catch {
      // Nieprawidłowy adres nie poszerza polityki CSP.
    }
  }
  return [...origins];
}

/**
 * Nagłówki bezpieczeństwa dla stron HTML renderowanych przez nasz serwer
 * (ekran zgody OAuth). CSP blokuje ładowanie jakichkolwiek zasobów zewnętrznych
 * i skryptów; `frame-ancestors 'none'` chroni przed clickjackingiem.
 *
 * Przeglądarki stosują `form-action` także do celów odpowiedzi 302 po wysłaniu
 * formularza. Dlatego ekran zgody musi jawnie dopuścić zweryfikowane cele
 * przekierowania OAuth, zachowując jednocześnie zamkniętą listę źródeł.
 */
export function htmlSecurityHeaders(allowedFormActionUrls: readonly string[] = []): Record<string, string> {
  const formAction = ["'self'", ...formActionOrigins(allowedFormActionUrls)].join(" ");
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy":
      `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    "referrer-policy": "no-referrer",
    "permissions-policy":
      "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "cache-control": "no-store",
  };
}
