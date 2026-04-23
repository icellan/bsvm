# BSVM Console

Operator-facing React SPA served at `/` on every BSVM node. Mission-
control dark theme (chartreuse accent, JetBrains Mono on every data
surface) redesigned per the design handoff in
`design_handoff_bsvm_console/`.

Two tiers:

- **Public explorer** — Overview (shard health + 14-row block ladder),
  Bridge (BSV ↔ wBSV reserve + deposits/withdrawals), Network (chain
  tips + prover + speculative depth), Block / Transaction / Address
  detail, Search resolver.
- **Admin suite** (`/admin`) — Dashboard, Governance (multisig
  proposals), Config (runtime keys), Prover (pause/resume/flush), Logs
  (live WS stream). Gated by BRC-100 wallet handshake; redirects to
  `/admin/session` when unauthenticated.

## Stack

- Vite 5 + React 18 + TypeScript 5.7 (strict; `noEmit: true`)
- Tailwind CSS 3, theme driven by CSS variables (`--ts-*`) so light
  / dark themes flip by toggling `body.light`
- TanStack Query for RPC caching + 1–5 s refetch intervals
- Zustand (persisted) for auth session + theme
- Fonts: `@fontsource-variable/inter-tight` (chrome) +
  `@fontsource/jetbrains-mono` (data)
- Build output embedded into the Go binary via `//go:embed` at
  `pkg/webui/dist/`

## Design tokens

Declared in `src/index.css` under `:root` (dark default) and
`body.light` (light override). Never hard-code a colour in a
component — use `var(--ts-*)` or the Tailwind alias.

| Token | Dark | Light | Purpose |
|---|---|---|---|
| `--ts-bg` | `#0a0c10` | `#ffffff` | page bg |
| `--ts-bg-1` | `#0f1217` | `#f6f8fa` | panel bg |
| `--ts-bg-2` | `#13171e` | `#eef1f4` | row hover, segmented bg |
| `--ts-bg-3` | `#1a1f28` | `#e1e5ea` | bar track |
| `--ts-line` | `#232a36` | `#d0d7de` | panel borders |
| `--ts-line-2` | `#2e3644` | `#b4bcc5` | input borders |
| `--ts-text` | `#e6ecf3` | `#1f2328` | primary text |
| `--ts-text-2` | `#a8b2c0` | `#4a5363` | secondary text |
| `--ts-text-3` | `#6b7686` | `#656d76` | labels, kickers |
| `--ts-text-4` | `#4a5363` | `#8a94a2` | timestamps, ultra-muted |
| `--ts-ok` | `#7cf0b3` | = dark | success, finalized |
| `--ts-warn` | `#f2c45a` | = dark | warning |
| `--ts-bad` | `#ff6b6b` | = dark | error, frozen |
| `--ts-info` | `#8ab8ff` | = dark | proven tier |
| `--ts-accent` | `#c8ff5e` | `#2da14a` | brand / primary CTA |

## Component index

- `components/ui/` — `Panel`, `KPI`, `Sparkline`, `SparkBars`, `Chip`,
  `Tier`, `Segmented`, `Bar`, `Timeline`, `KV`, `Button`, `StatusDot`,
  `Pill`. Prop-driven, no global state.
- `components/charts/` — `ThroughputChart`, `DepthViz`, `BlockLadder`,
  `ProofTrajectory`, `BridgeFlow`. Data-bound to live RPC queries.
- `components/admin/` — `ProposalCard`, `LogConsole`.
- `components/Chrome.tsx`, `StatusBar.tsx`, `FreezeBanner.tsx`,
  `Layout.tsx` — persistent chrome.
- `components/AdminShell.tsx` — 220 px sidebar + main layout.
- `hooks/useRingBuffer.ts` — client-side sparkline history.
- `state/theme.ts`, `state/session.ts` — persisted Zustand stores.

## Commands

```bash
cd bsv-evm/web
npm ci

# Local dev — proxies /rpc, /admin/rpc, /.well-known/auth, /metrics,
# /ws to localhost:8545 / 8546.
npm run dev

# Production build — writes into ../pkg/webui/dist, picked up by
# `go build`. Bakes the short git hash into the footer via
# VITE define (__BUILD_HASH__).
npm run build

# Type-check only
npx tsc --noEmit
```

When the upstream JSON-RPC shape changes, update `src/rpc/client.ts` —
every page consumes the typed helpers there.

## Auth flow

The admin panel opens a BRC-103 handshake with the node by POSTing to
`/.well-known/auth`. The wallet supplies an identity key that must
appear in the shard's governance set; the node rejects anything else
with HTTP 401. Per-request BRC-104 signing happens in
`src/auth/session.ts`. Each admin RPC builds the canonical HTTP
payload (matching go-sdk `authpayload.FromHTTPRequest`), hashes it,
and asks the wallet to sign.

Dev-auth (`x-bsvm-dev-auth: <secret>`) short-circuits the handshake —
used on `mock` / `execute` shards only. The server rejects the header
in `prove` mode regardless of what secret is supplied.
