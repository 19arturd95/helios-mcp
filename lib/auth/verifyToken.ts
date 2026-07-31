/**
 * Weryfikacja tokenu Bearer po stronie serwera zasobu (Resource Server).
 *
 * Używane przez `withMcpAuth` w `app/api/mcp/route.ts`. Sprawdza:
 *  - podpis i ważność access tokenu (JWT wystawiony przez nasz serwer),
 *  - poprawny issuer i audience (zasób /api/mcp),
 *  - e-mail zgodny z ALLOWED_EMAIL — inaczej odmowa.
 */

import { loadConfig, mcpResourceUrl, type HeliosConfig } from "../config";
import { HELIOS_READ_SCOPE } from "./constants";
import { verifyAccessToken } from "./tokens";

/** Struktura zgodna z `AuthInfo` z MCP SDK. */
export interface McpAuthInfo {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt?: number;
  extra?: Record<string, unknown>;
}

/**
 * Zwraca `McpAuthInfo` dla prawidłowego, dozwolonego tokenu.
 * Zwraca `undefined` dla braku tokenu, tokenu nieprawidłowego lub
 * niedozwolonego adresu e-mail (→ withMcpAuth odpowie 401).
 */
export async function verifyMcpBearer(
  bearerToken: string | undefined,
  config?: HeliosConfig,
): Promise<McpAuthInfo | undefined> {
  if (!bearerToken || bearerToken.trim() === "") return undefined;
  const cfg = config ?? loadConfig();
  try {
    const verified = await verifyAccessToken(
      cfg.authSecret,
      cfg.baseUrl,
      mcpResourceUrl(cfg.baseUrl),
      bearerToken,
    );
    const email = verified.email.trim().toLowerCase();
    if (!email || email !== cfg.allowedEmail) {
      return undefined; // niedozwolone konto
    }
    const scopes = verified.scope.split(" ").filter(Boolean);
    if (!scopes.includes(HELIOS_READ_SCOPE)) {
      return undefined; // token bez minimalnego scope odczytu
    }
    return {
      token: bearerToken,
      clientId: verified.clientId,
      scopes,
      expiresAt: verified.exp,
      extra: { email },
    };
  } catch {
    return undefined; // podpis/ważność/audience nie przeszły
  }
}
