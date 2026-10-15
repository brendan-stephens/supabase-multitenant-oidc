import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const TENANT_ID = "tenant-alpha";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

// Decode JWT claims without signature verification.
// Cryptographic validation happens in PostgREST via the registered OIDC provider;
// we read claims here only for response metadata and the INSERT user_id.
function jwtClaims(token: string): { sub: string; email: string } | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload.sub ? { sub: payload.sub, email: payload.email ?? "" } : null;
  } catch {
    return null;
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });

  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return Response.json({ error: "unauthorized" }, { status: 401, headers: cors });
  }

  const claims = jwtClaims(authHeader.slice(7));
  if (!claims) {
    return Response.json({ error: "unauthorized" }, { status: 401, headers: cors });
  }

  // PostgREST validates the CC JWT against the registered OIDC provider's JWKS.
  // RLS enforces user_id = auth.uid() for all queries.
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false },
    }
  );

  const url = new URL(req.url);
  const path = url.pathname.replace(/.*\/data/, "") || "/";

  if (req.method === "GET" && (path === "/" || path === "/notes")) {
    const { data, error } = await supabase
      .from("tenant_notes")
      .select("id, content, created_at")
      .order("created_at", { ascending: false });
    if (error) return Response.json({ error: error.message }, { status: error.status ?? 500, headers: cors });
    return Response.json({ user: claims, tenant: TENANT_ID, notes: data }, { headers: cors });
  }

  if (req.method === "POST" && (path === "/" || path === "/notes")) {
    const { content } = await req.json();
    const { data, error } = await supabase
      .from("tenant_notes")
      .insert({ user_id: claims.sub, content })
      .select("id, content, created_at")
      .single();
    if (error) return Response.json({ error: error.message }, { status: error.status ?? 500, headers: cors });
    return Response.json(data, { status: 201, headers: cors });
  }

  return Response.json({ error: "not_found" }, { status: 404, headers: cors });
});
