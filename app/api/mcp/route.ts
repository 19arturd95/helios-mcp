/**
 * Endpoint MCP (Streamable HTTP) — Faza 1: tylko odczyt.
 *
 * Chroniony przez `withMcpAuth`: każde żądanie musi mieć ważny token Bearer
 * wystawiony przez nasz serwer autoryzacji, a e-mail musi zgadzać się
 * z ALLOWED_EMAIL. Bez Redisa i bez SSE (transport stateless).
 */

import { createMcpHandler, withMcpAuth } from "mcp-handler";
import { loadConfig } from "@/lib/config";
import { verifyMcpBearer, type McpAuthInfo } from "@/lib/auth/verifyToken";
import { HELIOS_READ_SCOPE } from "@/lib/auth/constants";
import { READ_ONLY_TOOL_ANNOTATIONS } from "@/lib/tools/annotations";
import { makeToolContext, type ToolContext } from "@/lib/tools/handlers";
import * as H from "@/lib/tools/handlers";
import * as S from "@/lib/tools/schemas";
import { enforceRateLimit } from "@/lib/security/rateLimit";
import { corsHeaders, withCors } from "@/lib/http";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

// Kontekst narzędzi budowany leniwie (przy pierwszym żądaniu), aby nie
// wymuszać zmiennych środowiskowych podczas `next build`.
let ctxCache: ToolContext | null = null;
function ctx(): ToolContext {
  if (!ctxCache) ctxCache = makeToolContext(loadConfig());
  return ctxCache;
}

function asToolResult<T extends object>(value: T) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    structuredContent: value as Record<string, unknown>,
  };
}

const baseHandler = createMcpHandler(
  (server) => {
    server.registerTool(
      "helios_status",
      {
        title: "Status Heliosa",
        description: "Sprawdza połączenie z Helios Drive Adapter i zwraca podstawowy status (tryb tylko-odczyt).",
        inputSchema: S.statusSchema,
        outputSchema: S.statusOutputSchema,
        annotations: READ_ONLY_TOOL_ANNOTATIONS,
      },
      async () => asToolResult(await H.handleStatus(ctx())),
    );

    server.registerTool(
      "helios_get_context",
      {
        title: "Kontekst Heliosa",
        description: "Zbiera kontekst zapisu: czyta AGENTS.md, SCHEMA.md, index.md i wyszukuje powiązane strony. Nic nie zapisuje.",
        inputSchema: S.getContextSchema,
        outputSchema: S.getContextOutputSchema,
        annotations: READ_ONLY_TOOL_ANNOTATIONS,
      },
      async (args) => asToolResult(await H.handleGetContext(ctx(), args)),
    );

    server.registerTool(
      "helios_search",
      {
        title: "Wyszukaj w Heliosie",
        description: "Wyszukuje notatki w bazie Helios po frazie.",
        inputSchema: S.searchSchema,
        outputSchema: S.searchOutputSchema,
        annotations: READ_ONLY_TOOL_ANNOTATIONS,
      },
      async (args) => asToolResult(await H.handleSearch(ctx(), args)),
    );

    server.registerTool(
      "helios_read_note",
      {
        title: "Odczytaj notatkę Heliosa",
        description: "Czyta pojedynczą notatkę (Markdown) wraz z jej modifiedTime.",
        inputSchema: S.readNoteSchema,
        outputSchema: S.readNoteOutputSchema,
        annotations: READ_ONLY_TOOL_ANNOTATIONS,
      },
      async (args) => asToolResult(await H.handleReadNote(ctx(), args)),
    );

    server.registerTool(
      "helios_list_tree",
      {
        title: "Drzewo Heliosa",
        description: "Zwraca drzewo folderów i plików bazy Helios (do wskazanej głębokości).",
        inputSchema: S.listTreeSchema,
        outputSchema: S.listTreeOutputSchema,
        annotations: READ_ONLY_TOOL_ANNOTATIONS,
      },
      async (args) => asToolResult(await H.handleListTree(ctx(), args)),
    );

    server.registerTool(
      "helios_inbox_status",
      {
        title: "Status Inboxa Heliosa",
        description: "Zwraca liczbę i listę wpisów w Inboxie.",
        inputSchema: S.inboxStatusSchema,
        outputSchema: S.inboxStatusOutputSchema,
        annotations: READ_ONLY_TOOL_ANNOTATIONS,
      },
      async () => asToolResult(await H.handleInboxStatus(ctx())),
    );

    server.registerTool(
      "helios_review_inbox",
      {
        title: "Przejrzyj Inbox Heliosa",
        description: "Przygotowuje dane do przeglądu Inboxa: czyta wpisy i pobiera powiązany kontekst. Nic nie zmienia.",
        inputSchema: S.reviewInboxSchema,
        outputSchema: S.reviewInboxOutputSchema,
        annotations: READ_ONLY_TOOL_ANNOTATIONS,
      },
      async (args) => asToolResult(await H.handleReviewInbox(ctx(), args)),
    );
  },
  {
    serverInfo: { name: "helios-mcp", version: "0.1.0" },
    // Zdolności serwera (tylko narzędzia), transport stateless.
    capabilities: {},
    verboseLogs: false,
  },
);

// Warstwa uwierzytelnienia: weryfikacja tokenu Bearer + wskazanie
// Protected Resource Metadata przy 401.
type RequestHandler = (req: Request) => Response | Promise<Response>;

// Tworzymy warstwę auth leniwie, żeby `next build` nadal działał bez sekretów.
// PUBLIC_BASE_URL jest przekazywany jawnie do mcp-handler, więc nagłówek
// WWW-Authenticate nie może zostać zbudowany z podstawionego Host/X-Forwarded-Host.
let authHandlerCache: RequestHandler | null = null;
function authenticatedHandler(): RequestHandler {
  if (!authHandlerCache) {
    const config = loadConfig();
    authHandlerCache = withMcpAuth(
      baseHandler,
      async (_req: Request, bearerToken?: string): Promise<McpAuthInfo | undefined> => {
        return verifyMcpBearer(bearerToken, config);
      },
      {
        required: true,
        requiredScopes: [HELIOS_READ_SCOPE],
        resourceMetadataPath: "/.well-known/oauth-protected-resource",
        resourceUrl: config.baseUrl,
      },
    );
  }
  return authHandlerCache;
}

// Rate limiting best-effort (patrz lib/security/rateLimit.ts) PRZED
// weryfikacją tokenu — ogranicza też próby zgadywania/nadużywania bearer
// tokenów, nie tylko ruch już uwierzytelniony.
async function rateLimitedHandler(req: Request): Promise<Response> {
  const limited = await enforceRateLimit(req, { name: "api_mcp", limit: 60, windowSeconds: 60 });
  if (limited) return withCors(limited, HELIOS_READ_SCOPE);
  return withCors(await authenticatedHandler()(req), HELIOS_READ_SCOPE);
}

export { rateLimitedHandler as GET, rateLimitedHandler as POST, rateLimitedHandler as DELETE };

export function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}
