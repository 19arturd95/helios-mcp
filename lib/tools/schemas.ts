/** Schematy wejściowe narzędzi MCP (Zod). Faza 1 — tylko odczyt. */

import { z } from "zod";

export const statusSchema = {} as const;

export const getContextSchema = {
  rawText: z.string().min(1).max(20_000).describe("Surowa treść do zapamiętania (fragment rozmowy)."),
  conversationSummary: z
    .string()
    .max(5_000)
    .optional()
    .describe("Krótkie podsumowanie rozmowy przygotowane przez model."),
  date: z.string().max(64).optional().describe("Data w formacie ISO (opcjonalnie)."),
  hints: z
    .array(z.string().min(1).max(200))
    .max(20)
    .optional()
    .describe("Wskazówki użytkownika: tematy, tagi, sugerowane strony."),
} as const;

export const searchSchema = {
  query: z.string().min(1).max(500).describe("Fraza wyszukiwania."),
  limit: z.number().int().min(1).max(50).optional().describe("Maksymalna liczba wyników."),
} as const;

export const readNoteSchema = {
  path: z.string().min(1).max(1024).describe("Ścieżka względna notatki, np. '20 Wiki/temat.md'."),
} as const;

export const listTreeSchema = {
  path: z.string().max(1024).optional().describe("Podfolder do wylistowania (opcjonalnie)."),
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
