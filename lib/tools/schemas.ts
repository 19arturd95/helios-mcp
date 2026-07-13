/** Schematy wejściowe narzędzi MCP (Zod). Faza 1 — tylko odczyt. */

import { z } from "zod";

export const statusSchema = {} as const;

export const getContextSchema = {
  rawText: z.string().min(1).describe("Surowa treść do zapamiętania (fragment rozmowy)."),
  conversationSummary: z
    .string()
    .optional()
    .describe("Krótkie podsumowanie rozmowy przygotowane przez model."),
  date: z.string().optional().describe("Data w formacie ISO (opcjonalnie)."),
  hints: z
    .array(z.string())
    .optional()
    .describe("Wskazówki użytkownika: tematy, tagi, sugerowane strony."),
} as const;

export const searchSchema = {
  query: z.string().min(1).describe("Fraza wyszukiwania."),
  limit: z.number().int().min(1).max(50).optional().describe("Maksymalna liczba wyników."),
} as const;

export const readNoteSchema = {
  path: z.string().min(1).describe("Ścieżka względna notatki, np. '20 Wiki/temat.md'."),
} as const;

export const listTreeSchema = {
  path: z.string().optional().describe("Podfolder do wylistowania (opcjonalnie)."),
  maxDepth: z.number().int().min(1).max(8).optional().describe("Maksymalna głębokość drzewa."),
} as const;

export const inboxStatusSchema = {} as const;

export const reviewInboxSchema = {
  limit: z
    .number()
    .int()
    .min(1)
    .max(20)
    .optional()
    .describe("Ile wpisów Inboxa przygotować do przeglądu."),
} as const;

// Pomocnicze typy wejść (wywnioskowane z Zod).
export type GetContextInput = {
  rawText: string;
  conversationSummary?: string;
  date?: string;
  hints?: string[];
};
export type SearchInput = { query: string; limit?: number };
export type ReadNoteInput = { path: string };
export type ListTreeInput = { path?: string; maxDepth?: number };
export type ReviewInboxInput = { limit?: number };
