/**
 * Adnotacje wspólne dla wszystkich narzędzi Heliosa.
 *
 * Jawne wartości są ważne, ponieważ domyślne wartości MCP opisują narzędzie
 * jako potencjalnie zapisujące, destrukcyjne i działające w otwartym świecie.
 */
export const READ_ONLY_TOOL_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const);
