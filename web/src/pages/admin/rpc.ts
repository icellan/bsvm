// Thin wrapper around the admin JSON-RPC endpoint that wires the
// BRC-104 request signer into every call. Admin pages import
// adminRPC() instead of the underlying rpc/client admin helper so
// they never have to think about the auth state.

import { buildAdminHeaders } from "@/auth/session";

export async function adminRPC<R>(
  method: string,
  params: unknown[] = []
): Promise<R> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: Date.now(),
    method,
    params,
  });
  const headers = await buildAdminHeaders("POST", "/admin/rpc", body);
  headers["content-type"] = "application/json";

  const res = await fetch("/admin/rpc", {
    method: "POST",
    headers,
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`admin RPC ${method}: HTTP ${res.status} ${text}`);
  }
  const envelope = await res.json();
  if (envelope.error) {
    throw new Error(
      `admin RPC ${method}: ${envelope.error.message ?? JSON.stringify(envelope.error)}`
    );
  }
  return envelope.result as R;
}
