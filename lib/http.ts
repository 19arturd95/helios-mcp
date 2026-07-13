/** Pomocnicze odpowiedzi HTTP (Web API `Response`), z nagłówkami CORS. */

export function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, mcp-protocol-version",
    "cache-control": "no-store",
  };
}

export function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders(), ...extraHeaders },
  });
}

/** Odpowiedź błędu OAuth zgodna z RFC 6749 (bez wycieku sekretów/stack trace). */
export function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status);
}

export function htmlError(title: string, message: string, status = 400): Response {
  const safe = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]!);
  const body = `<!doctype html><meta charset="utf-8"><title>${safe(title)}</title>` +
    `<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">` +
    `<h1>${safe(title)}</h1><p>${safe(message)}</p></body>`;
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
