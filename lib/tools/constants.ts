/**
 * Domyślne ścieżki struktury Helios.
 *
 * Odpowiadają układowi opisanemu w promptcie. Jeśli Twoja realna struktura
 * na Drive różni się nazwami folderów, zmień je tutaj — to jedyne miejsce.
 */

export const PATHS = {
  agents: "90 System/AGENTS.md",
  schema: "90 System/SCHEMA.md",
  wikiIndex: "20 Wiki/index.md",
  inboxDir: "00 Inbox",
  archiveInboxDir: "99 Archive/Inbox",
  backupsDir: "90 System/Backups",
  log: "90 System/log.md",
} as const;
