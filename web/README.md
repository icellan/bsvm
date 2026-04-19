# BSVM Explorer (spec 15)

React + TypeScript SPA served at `/` on every BSVM node. Includes:

- Public explorer: dashboard, block / transaction / address details, bridge and network pages.
- Admin panel (`/admin`): governance proposals, runtime config, prover controls, live log stream.
- BRC-100 wallet auth: connect with Metanet Desktop / BSV Desktop, sign BRC-104 requests per admin call.
- Dev-auth fallback: enter a shared secret when running against a `mock` / `execute` devnet without a wallet.

## Stack

- Vite 5 + React 18 + TypeScript 5.7
- Tailwind CSS (dark theme only)
- TanStack Query for RPC caching, Zustand for session state
- Lives at `web/` in the repo; builds into `pkg/webui/dist/` which is embedded into the Go binary via `//go:embed`.

## Commands

```bash
# Local dev (proxies /rpc, /admin/rpc, /.well-known/auth, /metrics, /ws to localhost:8545/6)
cd bsv-evm/web
npm ci
npm run dev

# Production build — writes into ../pkg/webui/dist, picked up by `go build`
npm run build

# Type-check only
npm run lint
```

When the upstream JSON-RPC shape changes, update `src/rpc/client.ts` — every page consumes the typed helpers there.

## Auth flow

The admin panel opens a BRC-103 handshake with the node by POSTing to `/.well-known/auth`. The wallet supplies an identity key that must appear in the shard's governance set; the node rejects anything else with HTTP 401.

Per-request BRC-104 signing happens in `src/auth/session.ts`. Each admin RPC builds the canonical HTTP payload (matching go-sdk `authpayload.FromHTTPRequest`), hashes it, and asks the wallet to sign. The node re-derives the same payload on the server, verifies the signature, and rotates the session nonce.

Dev-auth (`x-bsvm-dev-auth: <secret>`) short-circuits the handshake — used on `mock` / `execute` shards only. The server rejects the header in `prove` mode regardless of what secret is supplied.
