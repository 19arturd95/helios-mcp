/** Typy operacji adaptera Helios Drive (Apps Script). */

export type ReadOnlyOp = "status" | "listTree" | "search" | "read";
export type WriteOp = "create" | "update" | "append" | "backup" | "moveToArchive";
/**
 * Operacje "meta" — nie dotyczą Google Drive i nie są gated przez
 * `WRITE_ENABLED` (to stan bezpieczeństwa OAuth, nie zapis notatek).
 */
export type SecurityOp = "consumeAuthCode";
export type AdapterOp = ReadOnlyOp | WriteOp | SecurityOp;

export const READ_ONLY_OPS: ReadOnlyOp[] = ["status", "listTree", "search", "read"];
export const WRITE_OPS: WriteOp[] = ["create", "update", "append", "backup", "moveToArchive"];
export const SECURITY_OPS: SecurityOp[] = ["consumeAuthCode"];

/** Wynik jednorazowego zużycia kodu autoryzacyjnego (patrz `consumeAuthCode_` w Code.gs). */
export interface ConsumeAuthCodeResult {
  consumed: boolean;
}

/** Metadane pliku zwracane przez adapter. */
export interface FileMeta {
  path: string;
  id: string;
  name: string;
  mimeType: string;
  modifiedTime: string;
  size?: number;
}

/** Węzeł drzewa katalogów. */
export interface TreeNode {
  path: string;
  name: string;
  type: "folder" | "file";
  id: string;
  modifiedTime?: string;
  children?: TreeNode[];
}

export interface StatusResult {
  ok: true;
  rootId: string;
  rootName: string;
  serverTime: string;
  writeEnabled: boolean;
}

export interface ReadResult {
  path: string;
  id: string;
  name: string;
  modifiedTime: string;
  content: string;
}

export interface SearchHit {
  path: string;
  id: string;
  name: string;
  modifiedTime: string;
  snippet?: string;
}

export interface SearchResult {
  query: string;
  hits: SearchHit[];
  /** `true`, gdy wynik został obcięty limitem kosztu (skan/odczyty treści). */
  truncated?: boolean;
}

export interface ListTreeResult {
  root: TreeNode;
  /** `true`, gdy drzewo zostało obcięte limitem liczby węzłów (`MAX_TREE_NODES`). */
  truncated?: boolean;
}

/** Ujednolicona odpowiedź adaptera. */
export type AdapterResponse<T = unknown> =
  | { ok: true; result: T }
  | { ok: false; error: string; code?: string };
