/**
 * Metadane OAuth publikowane przez serwer.
 *
 *  - Protected Resource Metadata (RFC 9728): mówi klientowi MCP, gdzie jest
 *    serwer autoryzacji dla zasobu /api/mcp.
 *  - Authorization Server Metadata (RFC 8414): opisuje endpointy naszego
 *    (własnego) serwera autoryzacji.
 */

import { mcpResourceUrl } from "../config.js";

export function protectedResourceMetadata(baseUrl: string) {
  const base = baseUrl.replace(/\/+$/, "");
  return {
    resource: mcpResourceUrl(base),
    authorization_servers: [base],
    scopes_supported: ["helios.read"],
    bearer_methods_supported: ["header"],
    resource_documentation: `${base}/`,
  };
}

export function authorizationServerMetadata(baseUrl: string) {
  const base = baseUrl.replace(/\/+$/, "");
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    scopes_supported: ["helios.read"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  };
}
