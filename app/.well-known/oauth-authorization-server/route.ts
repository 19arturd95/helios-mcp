/** Authorization Server Metadata (RFC 8414) — nasz własny serwer autoryzacji. */

import { loadConfig } from "@/lib/config";
import { authorizationServerMetadata } from "@/lib/auth/metadata";
import { corsHeaders, json } from "@/lib/http";

export const dynamic = "force-dynamic";

export async function GET() {
  const cfg = loadConfig();
  return json(authorizationServerMetadata(cfg.baseUrl));
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}
