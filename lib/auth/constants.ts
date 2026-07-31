/** Jedyny scope udostępniany przez Fazę 1 Helios MCP. */
export const HELIOS_READ_SCOPE = "helios.read";

/** Faza 1 nie akceptuje dodatkowych ani wymyślonych scope'ów. */
export function isExactReadScope(scope: string): boolean {
  const scopes = scope.split(/\s+/).filter(Boolean);
  return scopes.length === 1 && scopes[0] === HELIOS_READ_SCOPE;
}
