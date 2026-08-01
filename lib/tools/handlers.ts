/**
 * Logika narzędzi MCP (czyste funkcje, bez zależności od MCP SDK).
 *
 * Faza 1 — tylko odczyt. Handlery nie uruchamiają żadnego modelu AI;
 * przygotowują dane, a klasyfikację/treść zmian robi model hostujący.
 */

import type { HeliosConfig } from "../config";
import { callAdapter, DriveAdapterError, type AdapterClientConfig } from "../drive/client";
import type {
  AdapterOp,
  ListTreeResult,
  ReadResult,
  SearchHit,
  SearchResult,
  StatusResult,
  TreeNode,
} from "../drive/types";
import { normalizePath } from "../security/paths";
import { PATHS } from "./constants";
import type { GetContextInput, ListTreeInput, ReadNoteInput, ReviewInboxInput, SearchInput } from "./schemas";

export interface ToolContext {
  config: HeliosConfig;
  /** Wywołanie operacji adaptera. Wstrzykiwalne w testach. */
  call: <T = unknown>(op: AdapterOp, args?: Record<string, unknown>) => Promise<T>;
}

/** Publiczne wyniki MCP. Celowo nie zawierają identyfikatorów Google Drive. */
export type PublicStatusResult = Omit<StatusResult, "rootId">;
export type PublicReadResult = Omit<ReadResult, "id">;
export type PublicSearchHit = Omit<SearchHit, "id">;
export interface PublicSearchResult {
  query: string;
  hits: PublicSearchHit[];
  truncated?: boolean;
}
export interface PublicTreeNode {
  path: string;
  name: string;
  type: "folder" | "file";
  modifiedTime?: string;
  children?: PublicTreeNode[];
}
export interface PublicListTreeResult {
  root: PublicTreeNode;
  truncated?: boolean;
}

function publicRead(result: ReadResult): PublicReadResult {
  const { id: _id, ...safe } = result;
  return safe;
}

function publicSearch(result: SearchResult): PublicSearchResult {
  return {
    query: result.query,
    hits: result.hits.map(({ id: _id, ...safe }) => safe),
    ...(result.truncated === undefined ? {} : { truncated: result.truncated }),
  };
}

function publicTree(node: TreeNode): PublicTreeNode {
  return {
    path: node.path,
    name: node.name,
    type: node.type,
    ...(node.modifiedTime === undefined ? {} : { modifiedTime: node.modifiedTime }),
    ...(node.children === undefined ? {} : { children: node.children.map(publicTree) }),
  };
}

function isAdapterNotFound(error: unknown, message: string): boolean {
  return error instanceof DriveAdapterError && error.message === message;
}

/** Buduje domyślny kontekst narzędzi z realnym klientem adaptera. */
export function makeToolContext(config: HeliosConfig, fetchImpl?: typeof fetch): ToolContext {
  const clientConfig: AdapterClientConfig = {
    appsScriptUrl: config.appsScriptUrl,
    appsScriptSecret: config.appsScriptSecret,
    fetchImpl,
  };
  return {
    config,
    call: <T>(op: AdapterOp, args: Record<string, unknown> = {}) =>
      callAdapter<T>(clientConfig, op, args),
  };
}

async function readSafe(ctx: ToolContext, path: string): Promise<PublicReadResult | null> {
  try {
    const safe = normalizePath(path);
    return publicRead(await ctx.call<ReadResult>("read", { path: safe }));
  } catch (error) {
    if (isAdapterNotFound(error, "Notatka nie istnieje.")) return null;
    throw error;
  }
}

// --- helios_status -------------------------------------------------------
export async function handleStatus(ctx: ToolContext): Promise<PublicStatusResult> {
  const { rootId: _rootId, ...safe } = await ctx.call<StatusResult>("status");
  return safe;
}

// --- helios_read_note ----------------------------------------------------
export async function handleReadNote(ctx: ToolContext, input: ReadNoteInput): Promise<PublicReadResult> {
  const safe = normalizePath(input.path);
  return publicRead(await ctx.call<ReadResult>("read", { path: safe }));
}

// --- helios_search -------------------------------------------------------
export async function handleSearch(ctx: ToolContext, input: SearchInput): Promise<PublicSearchResult> {
  return publicSearch(
    await ctx.call<SearchResult>("search", { query: input.query, limit: input.limit ?? 10 }),
  );
}

// --- helios_list_tree ----------------------------------------------------
export async function handleListTree(ctx: ToolContext, input: ListTreeInput): Promise<PublicListTreeResult> {
  const path = input.path ? normalizePath(input.path, { requireExtension: false }) : undefined;
  const result = await ctx.call<ListTreeResult>("listTree", { path, maxDepth: input.maxDepth ?? 4 });
  return {
    root: publicTree(result.root),
    ...(result.truncated === undefined ? {} : { truncated: result.truncated }),
  };
}

// --- helios_get_context --------------------------------------------------
export interface GetContextResult {
  system: {
    agents: PublicReadResult | null;
    schema: PublicReadResult | null;
    index: PublicReadResult | null;
  };
  related: PublicSearchResult;
  input: { date: string; hints: string[] };
  note: string;
}

function buildQuery(input: GetContextInput): string {
  const parts: string[] = [];
  if (input.hints?.length) parts.push(...input.hints);
  // Pierwsze ~200 znaków surowej treści jako materiał do wyszukania.
  parts.push(input.rawText.slice(0, 200));
  return parts.join(" ").replace(/\s+/g, " ").trim();
}

export async function handleGetContext(
  ctx: ToolContext,
  input: GetContextInput,
): Promise<GetContextResult> {
  const [agents, schema, index] = await Promise.all([
    readSafe(ctx, PATHS.agents),
    readSafe(ctx, PATHS.schema),
    readSafe(ctx, PATHS.wikiIndex),
  ]);
  const related = publicSearch(await ctx.call<SearchResult>("search", {
    query: buildQuery(input),
    limit: 8,
  }));
  return {
    system: { agents, schema, index },
    related,
    input: {
      date: input.date ?? new Date().toISOString(),
      hints: input.hints ?? [],
    },
    note: "Tylko odczyt. Na podstawie tych danych można przygotować plan zmian, ale Faza 1 nie udostępnia operacji zapisu.",
  };
}

// --- helios_inbox_status -------------------------------------------------
function countFiles(node: TreeNode | undefined): number {
  if (!node) return 0;
  let count = node.type === "file" ? 1 : 0;
  for (const child of node.children ?? []) count += countFiles(child);
  return count;
}

export interface InboxStatusResult {
  inboxPath: string;
  entryCount: number;
  entries: Array<{ path: string; name: string; modifiedTime?: string }>;
}

export async function handleInboxStatus(ctx: ToolContext): Promise<InboxStatusResult> {
  let tree: ListTreeResult;
  try {
    tree = await ctx.call<ListTreeResult>("listTree", { path: PATHS.inboxDir, maxDepth: 2 });
  } catch (error) {
    if (isAdapterNotFound(error, "Folder nie istnieje.")) {
      return { inboxPath: PATHS.inboxDir, entryCount: 0, entries: [] };
    }
    throw error;
  }
  const entries: InboxStatusResult["entries"] = [];
  const walk = (node: TreeNode) => {
    if (node.type === "file") entries.push({ path: node.path, name: node.name, modifiedTime: node.modifiedTime });
    for (const c of node.children ?? []) walk(c);
  };
  walk(tree.root);
  return { inboxPath: PATHS.inboxDir, entryCount: countFiles(tree.root), entries };
}

// --- helios_review_inbox -------------------------------------------------
export interface ReviewInboxEntry {
  entry: PublicReadResult;
  related: PublicSearchResult;
}
export interface ReviewInboxResult {
  inboxPath: string;
  reviewed: ReviewInboxEntry[];
  note: string;
}

export async function handleReviewInbox(
  ctx: ToolContext,
  input: ReviewInboxInput,
): Promise<ReviewInboxResult> {
  const status = await handleInboxStatus(ctx);
  const limit = input.limit ?? 3;
  const reviewed: ReviewInboxEntry[] = [];
  for (const meta of status.entries.slice(0, limit)) {
    const entry = await readSafe(ctx, meta.path);
    if (!entry) continue;
    const related = publicSearch(await ctx.call<SearchResult>("search", {
      query: entry.content.slice(0, 200),
      limit: 5,
    }));
    reviewed.push({ entry, related });
  }
  return {
    inboxPath: status.inboxPath,
    reviewed,
    note: "Tylko odczyt. Zwrócone dane służą do przygotowania planu; Faza 1 nie udostępnia operacji zastosowania planu.",
  };
}
