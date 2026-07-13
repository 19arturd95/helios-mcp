/**
 * Walidacja i normalizacja logicznych ścieżek notatek.
 *
 * Ścieżki są WZGLĘDNE względem katalogu głównego (ROOT_FOLDER_ID po stronie
 * Apps Script). Ta warstwa jest pierwszą linią obrony; Apps Script niezależnie
 * potwierdza, że każdy plik jest potomkiem ROOT_FOLDER_ID.
 *
 * Polityka (celowo restrykcyjna dla systemu notatek):
 *  - brak ścieżek absolutnych (wiodący `/`, dyski `C:\`),
 *  - brak `\` (separatory Windows) i znaków sterujących / NUL,
 *  - brak `%` (blokuje zakodowany traversal, np. %2e%2e%2f i podwójne kodowanie),
 *  - brak segmentów `.` oraz `..` (path traversal),
 *  - normalizacja Unicode do NFC,
 *  - domyślnie wyłącznie rozszerzenie `.md`.
 */

export class PathValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PathValidationError";
  }
}

export const DEFAULT_ALLOWED_EXTENSIONS = [".md"] as const;

/** Maksymalny rozmiar zapisu: 1 MB (w bajtach UTF-8). */
export const MAX_WRITE_BYTES = 1024 * 1024;

export interface NormalizePathOptions {
  /** Dozwolone rozszerzenia (małe litery, z kropką). Domyślnie `.md`. */
  allowedExtensions?: readonly string[];
  /** Czy wymagać rozszerzenia pliku. Domyślnie true (ścieżka wskazuje plik). */
  requireExtension?: boolean;
}

// Znaki sterujące (0x00–0x1F) i DEL (0x7F).
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

/**
 * Normalizuje i waliduje ścieżkę. Zwraca bezpieczną, względną ścieżkę
 * (segmenty rozdzielone `/`) albo rzuca `PathValidationError`.
 */
export function normalizePath(raw: unknown, opts: NormalizePathOptions = {}): string {
  if (typeof raw !== "string") {
    throw new PathValidationError("Ścieżka musi być tekstem.");
  }
  if (raw.length === 0) {
    throw new PathValidationError("Ścieżka jest pusta.");
  }
  if (raw.length > 1024) {
    throw new PathValidationError("Ścieżka jest zbyt długa.");
  }
  if (CONTROL_CHARS.test(raw)) {
    throw new PathValidationError("Ścieżka zawiera znaki sterujące.");
  }
  if (raw.includes("\\")) {
    throw new PathValidationError("Ukośnik wsteczny (\\) jest niedozwolony.");
  }
  // Blokada zakodowanego traversalu i podwójnego kodowania.
  if (raw.includes("%")) {
    throw new PathValidationError("Znak '%' jest niedozwolony (blokada zakodowanego traversalu).");
  }
  // Normalizacja Unicode.
  const normalized = raw.normalize("NFC");
  if (normalized.startsWith("/")) {
    throw new PathValidationError("Ścieżki absolutne są niedozwolone.");
  }
  // Dysk Windows, np. "C:\..." albo "C:/..."
  if (/^[a-zA-Z]:[\\/]/.test(normalized)) {
    throw new PathValidationError("Ścieżki absolutne są niedozwolone.");
  }

  const segments = normalized.split("/");
  const clean: string[] = [];
  for (const seg of segments) {
    if (seg === "" || seg === ".") {
      continue; // pomiń puste segmenty oraz "."
    }
    if (seg === "..") {
      throw new PathValidationError("Path traversal ('..') jest niedozwolony.");
    }
    if (seg.trim() !== seg || seg.trim().length === 0) {
      throw new PathValidationError("Segment ścieżki nie może zaczynać/kończyć się spacją.");
    }
    clean.push(seg);
  }

  if (clean.length === 0) {
    throw new PathValidationError("Ścieżka nie zawiera prawidłowych segmentów.");
  }

  const finalPath = clean.join("/");

  if (opts.requireExtension !== false) {
    const allowed = opts.allowedExtensions ?? DEFAULT_ALLOWED_EXTENSIONS;
    const lower = finalPath.toLowerCase();
    const ok = allowed.some((ext) => lower.endsWith(ext.toLowerCase()) && lower !== ext.toLowerCase());
    if (!ok) {
      throw new PathValidationError(
        `Niedozwolone rozszerzenie pliku. Dozwolone: ${allowed.join(", ")}.`,
      );
    }
  }

  return finalPath;
}

/** Liczba bajtów UTF-8 tekstu (działa w Node i w środowisku Edge/Workers). */
export function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * Sprawdza limit rozmiaru zapisu (domyślnie 1 MB). Rzuca `PathValidationError`
 * przy przekroczeniu.
 */
export function assertWithinWriteLimit(content: string, maxBytes: number = MAX_WRITE_BYTES): void {
  const size = utf8ByteLength(content);
  if (size > maxBytes) {
    throw new PathValidationError(
      `Zawartość przekracza limit ${maxBytes} bajtów (ma ${size}).`,
    );
  }
}
