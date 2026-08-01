/**
 * Ścisłe schematy wejść i wyjść narzędzi MCP.
 *
 * Każdy schemat jest zamknięty (`strict`), aby klient nie mógł przesyłać
 * nieudokumentowanych pól, a serwer nie zwracał przypadkiem danych spoza
 * publicznego kontraktu. W szczególności odpowiedzi nie zawierają wewnętrznych
 * identyfikatorów plików ani folderów Google Drive.
 */

import { z } from "zod";

const pathSchema = z.string().min(1).max(1024);
const modifiedTimeSchema = z.string().min(1).max(64);

export const statusSchema = z.object({}).strict();

export const getContextSchema = z
  .object({
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
  })
  .strict();

export const searchSchema = z
  .object({
    query: z.string().min(1).max(500).describe("Fraza wyszukiwania."),
    limit: z.number().int().min(1).max(50).optional().describe("Maksymalna liczba wyników."),
  })
  .strict();

export const readNoteSchema = z
  .object({
    path: pathSchema.describe("Ścieżka względna notatki, np. '20 Wiki/temat.md'."),
  })
  .strict();

export const listTreeSchema = z
  .object({
    path: z.string().max(1024).optional().describe("Podfolder do wylistowania (opcjonalnie)."),
    maxDepth: z.number().int().min(1).max(8).optional().describe("Maksymalna głębokość drzewa."),
  })
  .strict();

export const inboxStatusSchema = z.object({}).strict();

export const reviewInboxSchema = z
  .object({
    limit: z
      .number()
      .int()
      .min(1)
      .max(20)
      .optional()
      .describe("Ile wpisów Inboxa przygotować do przeglądu."),
  })
  .strict();

export const statusOutputSchema = z
  .object({
    ok: z.literal(true),
    rootName: z.string().min(1),
    serverTime: modifiedTimeSchema,
    readOnly: z.literal(true),
  })
  .strict();

export const readNoteOutputSchema = z
  .object({
    path: pathSchema,
    name: z.string().min(1),
    modifiedTime: modifiedTimeSchema,
    content: z.string().max(200 * 1024),
  })
  .strict();

export const searchHitOutputSchema = z
  .object({
    path: pathSchema,
    name: z.string().min(1),
    modifiedTime: modifiedTimeSchema,
    snippet: z.string().optional(),
  })
  .strict();

export const searchOutputSchema = z
  .object({
    query: z.string(),
    hits: z.array(searchHitOutputSchema).max(50),
    truncated: z.boolean().optional(),
  })
  .strict();

export const treeNodeOutputSchema: z.ZodTypeAny = z.lazy(() =>
  z
    .object({
      path: z.string().max(1024),
      name: z.string().min(1),
      type: z.enum(["folder", "file"]),
      modifiedTime: modifiedTimeSchema.optional(),
      children: z.array(treeNodeOutputSchema).optional(),
    })
    .strict(),
);

export const listTreeOutputSchema = z
  .object({
    root: treeNodeOutputSchema,
    truncated: z.boolean().optional(),
  })
  .strict();

export const getContextOutputSchema = z
  .object({
    system: z
      .object({
        agents: readNoteOutputSchema.nullable(),
        schema: readNoteOutputSchema.nullable(),
        index: readNoteOutputSchema.nullable(),
      })
      .strict(),
    related: searchOutputSchema,
    input: z
      .object({
        date: z.string().max(64),
        hints: z.array(z.string().max(200)).max(20),
      })
      .strict(),
    note: z.string(),
  })
  .strict();

export const inboxEntryOutputSchema = z
  .object({
    path: pathSchema,
    name: z.string().min(1),
    modifiedTime: modifiedTimeSchema.optional(),
  })
  .strict();

export const inboxStatusOutputSchema = z
  .object({
    inboxPath: z.string().min(1).max(1024),
    entryCount: z.number().int().min(0),
    entries: z.array(inboxEntryOutputSchema),
  })
  .strict();

export const reviewInboxOutputSchema = z
  .object({
    inboxPath: z.string().min(1).max(1024),
    reviewed: z.array(
      z
        .object({
          entry: readNoteOutputSchema,
          related: searchOutputSchema,
        })
        .strict(),
    ),
    note: z.string(),
  })
  .strict();

export type GetContextInput = z.infer<typeof getContextSchema>;
export type SearchInput = z.infer<typeof searchSchema>;
export type ReadNoteInput = z.infer<typeof readNoteSchema>;
export type ListTreeInput = z.infer<typeof listTreeSchema>;
export type ReviewInboxInput = z.infer<typeof reviewInboxSchema>;
