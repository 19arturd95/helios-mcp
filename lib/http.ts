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
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...extraHeaders },
  });
}

/**
 * Nagłówki bezpieczeństwa dla stron HTML renderowanych przez nasz serwer
 * (ekran zgody OAuth). CSP blokuje ładowanie jakichkolwiek zasobów zewnętrznych
 * i skryptów; `frame-ancestors 'none'` chroni przed clickjackingiem.
 */
export function htmlSecurityHeaders(): Record<string, string> {
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
  };
}
