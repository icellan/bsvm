// BRC-103 handshake + per-request signing helper.
//
// Flow:
//   1. Read identity key from the wallet.
//   2. POST /.well-known/auth with { identityKey, initialNonce }.
//   3. Verify the server's signature (out of scope for the first
//      pass — the server signs with its advertised identity key;
//      trust-on-first-use is enough for now and the key is visible
//      to the operator in the admin panel header).
//   4. Stash (serverNonce, clientNonce) in the zustand session.
//   5. For every admin_* request, build the canonical payload the
//      server expects and ask the wallet to sign it.

import { useSession } from "@/state/session";
import {
  bytesToBase64,
  bytesToHex,
  hexToBytes,
  randomNonce,
  requestIdentityKey,
  sha256,
  signMessage,
} from "@/auth/wallet";

export type HandshakeResponse = {
  version: string;
  messageType: "initialResponse";
  identityKey: string; // server hex
  nonce: string; // server nonce base64
  yourNonce: string; // echoes client initialNonce
  signature: string; // server DER signature hex
};

export async function handshake(): Promise<void> {
  const identityKey = await requestIdentityKey();
  const initialNonceBytes = randomNonce();
  const initialNonce = bytesToBase64(initialNonceBytes);

  const res = await fetch("/.well-known/auth", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      version: "0.1",
      messageType: "initialRequest",
      identityKey,
      initialNonce,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`handshake failed: HTTP ${res.status} ${text}`);
  }
  const body = (await res.json()) as HandshakeResponse;

  useSession.getState().setSession({
    kind: "brc100",
    identityKey,
    serverIdentityKey: body.identityKey,
    serverNonce: body.nonce,
    clientNonce: initialNonce,
  });
}

// buildAdminHeaders composes the BRC-104 header set for a given
// request. Called immediately before the POST so the nonce pair
// reflects the live session state.
export async function buildAdminHeaders(
  method: string,
  path: string,
  body: string
): Promise<Record<string, string>> {
  const session = useSession.getState().session;
  if (!session) throw new Error("no active admin session");

  if (session.kind === "devAuth") {
    return { "x-bsvm-dev-auth": session.secret };
  }

  const requestIDBytes = randomNonce();
  const requestID = bytesToBase64(requestIDBytes);
  const clientNonceBytes = randomNonce();
  const clientNonce = bytesToBase64(clientNonceBytes);

  const payload = await canonicalHTTPPayload(
    requestIDBytes,
    method,
    path,
    body
  );
  const digest = await sha256(payload);
  const sigHex = await signMessage(digest);

  // Rotate the client-side nonce AFTER computing the payload —
  // subsequent requests start from the freshly minted value.
  useSession
    .getState()
    .setSession({ ...session, clientNonce });

  return {
    "x-bsv-auth-version": "0.1",
    "x-bsv-auth-message-type": "general",
    "x-bsv-auth-identity-key": session.identityKey,
    "x-bsv-auth-nonce": clientNonce,
    "x-bsv-auth-your-nonce": session.serverNonce,
    "x-bsv-auth-request-id": requestID,
    "x-bsv-auth-signature": sigHex,
  };
}

// canonicalHTTPPayload mirrors the server's go-sdk
// authpayload.FromHTTPRequest. A simplified implementation that
// matches the server for the exact shape of our JSON-RPC POSTs:
//
//   [requestID (32 bytes)]
//   [method string]
//   [path string]
//   [optional query string]
//   [header count varint] — always 0 (we include no x-bsv-* request
//                            headers in the canonical form; the
//                            server's FromHTTPRequest also includes
//                            only whitelisted headers, which don't
//                            include x-bsv-auth-* themselves)
//   [body bytes]
//
// When the server changes its payload derivation, this must follow.
async function canonicalHTTPPayload(
  requestID: Uint8Array,
  method: string,
  path: string,
  body: string
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  parts.push(requestID);
  parts.push(writeString(method));
  parts.push(writeString(path || "/"));
  // searchParams: empty → WriteOptionalString(0).
  parts.push(writeOptionalString(""));
  // header count: 0.
  parts.push(varint(0));
  // body: writeIntBytesOptional — 0xff for absent, length varint + bytes otherwise.
  if (body.length === 0) {
    parts.push(new Uint8Array([0xff]));
  } else {
    const bodyBytes = new TextEncoder().encode(body);
    parts.push(varint(bodyBytes.length));
    parts.push(bodyBytes);
  }
  return concat(parts);
}

function writeString(s: string): Uint8Array {
  const bytes = new TextEncoder().encode(s);
  return concat([varint(bytes.length), bytes]);
}

// writeOptionalString uses the 0xff sentinel for an absent value.
function writeOptionalString(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array([0xff]);
  return writeString(s);
}

// varint: the go-sdk util.Writer uses a variable-length encoding
// where values < 0xfd are a single byte; 0xfd + 2 bytes LE for
// values up to 0xffff, etc. We only ever hit the short paths here.
function varint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    b[1] = n & 0xff;
    b[2] = (n >> 8) & 0xff;
    return b;
  }
  if (n <= 0xffffffff) {
    const b = new Uint8Array(5);
    b[0] = 0xfe;
    for (let i = 0; i < 4; i++) b[1 + i] = (n >> (8 * i)) & 0xff;
    return b;
  }
  throw new Error("varint overflow");
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// Utilities exported for debugging / tests.
export const __internal = { writeString, writeOptionalString, varint, concat };

export { bytesToHex, hexToBytes };
