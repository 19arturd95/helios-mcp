/** Typy operacji adaptera Helios Drive (Apps Script). */

export type ReadOnlyOp = "status" | "listTree" | "search" | "read";
export type WriteOp = "create" | "update" | "append" | "backup" | "moveToArchive";
export type AdapterOp = ReadOnlyOp | WriteOp;

export const READ_ONLY_OPS: ReadOnlyOp[] = ["status", "listTree", "search", "read"];
export const WRITE_OPS: WriteOp[] = ["create", "update", "append", "backup", "moveToArchive"];

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
}

export interface ListTreeResult {
  root: TreeNode;
}

/** Ujednolicona odpowiedź adaptera. */
export type AdapterResponse<T = unknown> =
  | { ok: true; result: T }
  | { ok: false; error: string; code?: string };
