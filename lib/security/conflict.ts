/**
 * Kontrola wersji optymistycznej (optimistic concurrency).
 *
 * Przy każdej aktualizacji hostujący model dostarcza `expectedModifiedTime`
 * (z `helios_get_context`/`helios_read_note`). Tuż przed zapisem porównujemy
 * go z bieżącym `modifiedTime` pliku. Rozbieżność = konflikt → przerwanie
 * zapisu (bez nadpisania cudzych zmian).
 */

export class VersionConflictError extends Error {
  constructor(
    public readonly path: string,
    public readonly expected: string,
    public readonly actual: string,
  ) {
    super(
      `Konflikt wersji dla "${path}": oczekiwano modifiedTime=${expected}, ` +
        `a bieżące to ${actual}. Zapis przerwany — odśwież kontekst i spróbuj ponownie.`,
    );
    this.name = "VersionConflictError";
  }
}

/** Parsuje znacznik czasu do epoch ms; NaN jeśli nieprawidłowy. */
function toEpochMs(value: string): number {
  return new Date(value).getTime();
}

/**
 * Rzuca `VersionConflictError`, jeśli oczekiwany i bieżący `modifiedTime`
 * nie wskazują tej samej chwili. Brak `expectedModifiedTime` przy
 * aktualizacji jest traktowany jak konflikt (wymóg obowiązkowy).
 */
export function assertNoVersionConflict(
  path: string,
  expectedModifiedTime: string | undefined,
  actualModifiedTime: string,
): void {
  if (!expectedModifiedTime) {
    throw new VersionConflictError(path, "(brak)", actualModifiedTime);
  }
  const expected = toEpochMs(expectedModifiedTime);
  const actual = toEpochMs(actualModifiedTime);
  if (Number.isNaN(expected) || Number.isNaN(actual)) {
    // Nie potrafimy bezpiecznie porównać → przerywamy dla bezpieczeństwa.
    throw new VersionConflictError(path, expectedModifiedTime, actualModifiedTime);
  }
  if (expected !== actual) {
    throw new VersionConflictError(path, expectedModifiedTime, actualModifiedTime);
  }
}
