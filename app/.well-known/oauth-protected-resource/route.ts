/** Protected Resource Metadata (RFC 9728) dla zasobu /api/mcp. */

import { loadConfig } from "@/lib/config";
import { protectedResourceMetadata } from "@/lib/auth/metadata";
import { corsHeaders, json } from "@/lib/http";

export const dynamic = "force-dynamic";

export async function GET() {
  const cfg = loadConfig();
  return json(protectedResourceMetadata(cfg.baseUrl));
}

export function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}
