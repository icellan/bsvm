# Spec 15: Shard Explorer & Administration UI

## Goal

A web-based interface for BSVM shards serving two audiences: **users** browsing shard activity (block explorer), and **operators** managing shard operations (admin panel). The UI connects to the shard's existing RPC endpoints — no additional backend required.

Admin authentication uses the **BRC-100 wallet interface** standard (BSV BRC-3 signatures, BRC-103 mutual authentication, BRC-104 HTTP transport). Operators authenticate by signing a challenge with the private key corresponding to their shard governance public key. If the shard uses multisig governance, any key in the multisig set can authenticate for read access to admin data; executing governance operations (freeze/unfreeze/upgrade) requires the appropriate signature threshold.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Browser                                                      │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  BSVM Explorer (React SPA)                              │  │
│  │                                                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐  │  │
│  │  │  Explorer   │  │  Admin      │  │  BRC-100       │  │  │
│  │  │  (public)   │  │  (authed)   │  │  Wallet Bridge │  │  │
│  │  └──────┬──────┘  └──────┬──────┘  └───────┬────────┘  │  │
│  │         │                │                  │           │  │
│  │         └────────────────┼──────────────────┘           │  │
│  │                          │                              │  │
│  └──────────────────────────┼──────────────────────────────┘  │
│                             │                                  │
└─────────────────────────────┼──────────────────────────────────┘
                              │ JSON-RPC + BRC-104 auth headers
                              ▼
                  ┌─────────────────────────┐
                  │  Overlay Node            │
                  │                          │
                  │  GET /              → SPA │
                  │  POST /rpc          → RPC │
                  │  POST /admin/rpc    → RPC │
                  │  /.well-known/auth  → 103 │
                  └─────────────────────────┘
```

The SPA is a static build served by the overlay node's HTTP server. Public explorer data comes from `eth_*` and `bsv_*` RPC methods. Admin operations use `admin_*` RPC methods behind BRC-104 authenticated endpoints.

---

## Authentication: BRC-100 Wallet Integration

### How it works

1. The admin clicks "Connect Wallet" in the UI.
2. The UI communicates with a BRC-100 compliant wallet (BSV Desktop, Metanet Desktop, or any BRC-100 wallet) via the standard wallet interface.
3. The wallet provides the user's identity public key.
4. The UI sends an authentication challenge to the overlay node's `/.well-known/auth` endpoint (BRC-103 initial handshake).
5. The wallet signs the challenge using BRC-3 (ECDSA signature with the identity key).
6. The overlay node verifies:
   - The signature is valid (BRC-3 verification).
   - The signing public key matches one of the shard's governance keys (from genesis config).
7. If verified, subsequent requests use BRC-104 authenticated HTTP with `x-bsv-auth-*` headers.

### Authorization levels

| Governance Mode | Who can authenticate | What they can do |
|---|---|---|
| `none` | Nobody | Admin panel shows read-only node metrics. No governance actions. |
| `single_key` | Holder of the governance key | Full admin: freeze, unfreeze, upgrade, view all metrics. |
| `multisig` | Any key in the multisig set | View admin data. Initiate governance actions (but execution requires threshold signatures — see below). |

### Multisig governance actions

For multisig-governed shards, governance operations (freeze/unfreeze/upgrade) require M-of-N signatures. The UI facilitates this:

1. An authenticated admin initiates a governance action (e.g., "Freeze Shard").
2. The overlay node creates a **governance proposal** — a pending BSV transaction that spends the covenant UTXO via the `freeze` method.
3. The proposal is stored locally and shown to all authenticated admins.
4. Each admin reviews the proposal and signs it with their governance key via BRC-3.
5. When M signatures are collected, the overlay node broadcasts the BSV transaction.
6. The UI shows the transaction status (pending → confirmed).

Proposals expire after a configurable timeout (default: 24 hours). Unsigned proposals are discarded.

---

## Part 1: Public Explorer

No authentication required. Anyone who can reach the node's HTTP endpoint can view the explorer.

### 1.1 Dashboard (Home)

The landing page shows a real-time overview of the shard.

**Shard Identity Panel:**
- Shard name (from genesis config, optional)
- Chain ID (with copy-to-clipboard for MetaMask configuration)
- RPC endpoint URL (with copy-to-clipboard)
- Genesis covenant txid (linked to a BSV block explorer, e.g., whatsonchain.com)
- Governance mode: green `TRUSTLESS` badge, yellow `SINGLE KEY` badge, or blue `MULTISIG (M/N)` badge
- Shard status: green `ACTIVE` or red pulsing `FROZEN`

**Live Statistics (auto-refresh every 5 seconds):**
- Current block number (execution tip)
- Proven block number (proven tip) with delta badge showing lag (e.g., "2 blocks behind")
- Finalized block number (6+ BSV confirmations)
- Transactions per second (rolling 60-second average)
- Gas price (minimum, in gwei)
- Total wBSV supply on L2 (formatted as BSV with 8 decimal places)
- Bridge TVL (total BSV locked across all sub-covenant UTXOs)
- Active peer count (from gossip heartbeat)

**Recent Blocks Table (last 20):**

| Block | Age | Txns | Gas Used | Gas % | Coinbase | Status |
|---|---|---|---|---|---|---|
| 1,234 | 3s ago | 128 | 5,400,000 | 18% | 0xabc...def | Speculative |
| 1,233 | 8s ago | 128 | 12,300,000 | 41% | 0xabc...def | Proven |
| 1,232 | 15s ago | 64 | 3,200,000 | 11% | 0x123...789 | Finalized |

Status column shows colour-coded confirmation status: grey (speculative), blue (proven), green (finalized).

**Recent Transactions Table (last 20):**

| Tx Hash | Block | Age | From | To | Value | Gas Used | Status |
|---|---|---|---|---|---|---|---|

Click any row to navigate to the detail page.

**Data sources:** `eth_blockNumber`, `eth_getBlockByNumber`, `bsv_shardInfo`, `bsv_getGovernanceState`, WebSocket subscription for new blocks.

### 1.2 Block Detail Page

URL: `/block/:numberOrHash`

**Block header:**
- Block number, hash, parent hash
- Timestamp (human-readable + Unix)
- Coinbase address (linked to address page)
- Gas used / gas limit (with percentage bar)
- Transaction count
- State root, receipts root
- BSV confirmation status (speculative / proven / confirmed / finalized)
- BSV covenant txid (linked to BSV explorer) — shown once proven

**Transaction list:** All transactions in the block with hash, from, to, value, gas used, status.

**Data sources:** `eth_getBlockByNumber` (with full tx objects), `bsv_getBlockConfirmationStatus`.

### 1.3 Transaction Detail Page

URL: `/tx/:hash`

**Transaction summary:**
- Transaction hash
- Status: Success (green check) or Failed (red X) with revert reason if available
- Block number (linked to block page)
- From address (linked) → To address (linked)
- Value transferred (in wBSV)
- Gas price, gas limit, gas used, effective gas price
- Transaction type (0x00 legacy, 0x01 access list, 0x02 EIP-1559, 0x7E deposit system tx)
- Nonce
- Input data (collapsible, hex + decoded if ABI is known)

**Confirmation status:**
- `bsvConfirmationStatus` with visual indicator
- BSV covenant txid (once proven)
- Time since submission, time to proven, time to finalized

**Event logs:** Decoded event logs with topic names if ABI is available.

**Internal transactions:** If the transaction involved contract-to-contract calls, show the internal call trace (requires `debug_traceTransaction` or equivalent).

**Data sources:** `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `bsv_getTransactionConfirmationStatus`.

### 1.4 Address/Account Page

URL: `/address/:address`

**Account summary:**
- Address
- wBSV balance (formatted as BSV)
- Transaction count (nonce)
- Is contract: Yes/No
- If contract: code size, creation tx hash

**Transaction history:** Paginated table of transactions involving this address (both sent and received), most recent first.

**If contract:**
- Contract code (hex, collapsible)
- Read-only contract interaction (if ABI is provided/uploaded by user)
- Storage slots (via `eth_getStorageAt`, if the user queries specific slots)

**Token balances:** ERC-20 token balances (requires indexing `Transfer` events — deferred to v2, or use `eth_call` to query known token contracts).

**Data sources:** `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getBlockByNumber` with filtering.

### 1.5 Contract Interaction Page

URL: `/address/:address/interact`

For verified contracts (where the ABI is available):

**Read methods:** List all `view` and `pure` functions. User can call them directly (via `eth_call`) and see results.

**Write methods:** List all state-changing functions. User can construct a transaction (but must use their own wallet — MetaMask or similar — to sign and submit via `eth_sendRawTransaction`).

**ABI upload:** User can paste or upload an ABI JSON file to enable interaction with any contract.

### 1.6 Search

Universal search bar at the top of every page. Accepts:
- Block number → block detail page
- Transaction hash (0x + 64 hex chars) → transaction detail page
- Address (0x + 40 hex chars) → address page
- ENS-style names → deferred (no ENS on BSVM v1)

### 1.7 Bridge Status Page

URL: `/bridge`

**Bridge overview:**
- Total BSV locked (sum of all sub-covenant UTXOs)
- Total wBSV supply on L2
- Difference (should be zero; any mismatch is flagged red)
- Number of bridge sub-covenant UTXOs
- Rate limit: current period withdrawals / max per period

**Sub-covenant table:**

| UTXO | BSV Balance | Last Claimed Nonce | BSV Txid | Status |
|---|---|---|---|---|
| Sub-covenant A | 87.00 BSV | 42 | abc123... | Active |
| Sub-covenant B | 100.00 BSV | 0 | def456... | Active |

**Recent deposits (last 20):**

| BSV Txid | Amount | L2 Address | BSV Confirmations | Credited? |
|---|---|---|---|---|

**Recent withdrawals (last 20):**

| Nonce | Amount | BSV Address | L2 Tx | Claim Status | CSV Blocks Remaining |
|---|---|---|---|---|---|

**Data sources:** `bsv_bridgeStatus`, `bsv_getDeposits`, `bsv_getWithdrawals`.

### 1.8 Network Health Page

URL: `/network`

**Node table:**

| Peer ID | Address | Role | Last Heartbeat | Blocks Behind |
|---|---|---|---|---|
| QmPeer1 | 1.2.3.4:9945 | Prover | 2s ago | 0 |
| QmPeer2 | 5.6.7.8:9945 | Follower | 5s ago | 1 |

**Proving pipeline:**
- Execution tip vs proven tip (visual gap indicator)
- Speculative depth (current / max, with colour: green < 8, yellow 8-12, red > 12)
- Batches proven in last hour
- Average proving time (last 10 batches)
- Proofs won vs lost (for this node, if prover)

**BSV settlement:**
- Covenant UTXO chain depth (unconfirmed)
- Last BSV confirmation (block height, time ago)
- BSV fee wallet balance (satoshis)

**Data sources:** `bsv_networkHealth`, `bsv_provingStatus`, `bsv_feeWalletBalance`, `admin_peerList`.

---

## Part 2: Admin Panel

URL: `/admin`

Requires BRC-100 wallet authentication. The admin panel is only accessible if the shard has governance (`single_key` or `multisig`). For `GovernanceNone` shards, the admin section shows a message: "This shard is fully trustless. No administrative actions are available."

### 2.1 Admin Authentication Flow

```
┌──────────┐                ┌──────────┐                ┌──────────┐
│  Browser  │                │  BRC-100  │                │  Overlay  │
│  (UI)     │                │  Wallet   │                │  Node     │
└─────┬─────┘                └─────┬─────┘                └─────┬─────┘
      │                            │                            │
      │  1. Click "Connect Wallet" │                            │
      │───────────────────────────►│                            │
      │                            │                            │
      │  2. Wallet returns         │                            │
      │     identity public key    │                            │
      │◄───────────────────────────│                            │
      │                            │                            │
      │  3. POST /.well-known/auth │                            │
      │    (BRC-103 initialRequest │with identity key)          │
      │────────────────────────────┼───────────────────────────►│
      │                            │                            │
      │  4. Node checks: is this   │                            │
      │     key in governance set? │                            │
      │     If yes: returns nonce  │                            │
      │◄───────────────────────────┼────────────────────────────│
      │                            │                            │
      │  5. Request wallet to sign │nonce                       │
      │───────────────────────────►│                            │
      │                            │                            │
      │  6. Wallet signs via BRC-3 │                            │
      │◄───────────────────────────│                            │
      │                            │                            │
      │  7. POST /.well-known/auth │                            │
      │    (BRC-103 initialResponse with signature)             │
      │────────────────────────────┼───────────────────────────►│
      │                            │                            │
      │  8. Node verifies sig,     │                            │
      │     establishes session    │                            │
      │◄───────────────────────────┼────────────────────────────│
      │                            │                            │
      │  9. Subsequent requests    │                            │
      │     use BRC-104 headers    │                            │
      │     (x-bsv-auth-*)         │                            │
      │────────────────────────────┼───────────────────────────►│
```

The node maintains a session (nonce-based, expires after 1 hour of inactivity). The wallet identity key is checked against the shard's governance key(s) stored in the genesis config.

### 2.2 Admin Dashboard

Shows everything from the public dashboard plus:

**Prover Economics:**
- Revenue this period (wBSV earned from coinbase)
- BSV costs this period (mining fees spent)
- Profit margin (percentage)
- Proofs won / lost / abandoned
- Revenue per batch (rolling average)

**Fee Wallet:**
- Current BSV balance (satoshis)
- Estimated batches remaining at current balance
- Low balance warning threshold (configurable)
- Transaction history (BSV covenant advances, with fees)

**Mempool:**
- Pending transaction count
- Pending gas total
- Oldest pending transaction age
- Mempool size (bytes)

### 2.3 Governance Actions

The core admin functionality. Each action constructs a BSV transaction and (for multisig) manages the signing workflow.

#### Freeze Shard

Pauses the shard. `advanceState` is blocked. The shard stops processing new EVM transactions. Read-only RPC continues.

**UI flow:**
1. Admin clicks "Freeze Shard"
2. Confirmation dialog: "Freezing will stop all transaction processing. Users will not be able to submit transactions. Read-only RPC will continue. Are you sure?"
3. Admin confirms
4. **Single key:** The wallet signs the freeze transaction via BRC-3. The node broadcasts it to BSV immediately.
5. **Multisig:** The node creates a governance proposal. Other admins see it and sign. When threshold is reached, the node broadcasts.

**Status display after freeze:**
- Red "FROZEN" banner across the top of the entire UI
- Timestamp of freeze
- BSV txid of the freeze transaction
- "Unfreeze" button becomes available

#### Unfreeze Shard

Resumes normal operation after a freeze. Same UI flow as freeze but in reverse.

**Pre-conditions:** Shard must be frozen. If an upgrade was applied during the freeze, the UI shows a warning: "The covenant script was upgraded while frozen. Verify the new script before unfreezing."

#### Upgrade Covenant

Replaces the covenant locking script. Only available while the shard is frozen.

**UI flow:**
1. Admin clicks "Upgrade Covenant" (greyed out if shard is active; tooltip: "Freeze the shard first")
2. Admin provides the new covenant script (as hex, or uploads a compiled Rúnar output file)
3. The UI shows a diff-style comparison of old vs new script (hex, with size comparison)
4. Confirmation dialog with strong warning: "This will replace the covenant script. The shard will remain frozen after the upgrade. You must explicitly unfreeze to resume. This action is irreversible once broadcast to BSV."
5. Signing flow (same as freeze: single-key or multisig)

**After upgrade:**
- UI shows the new covenant script hash
- "Unfreeze" button is available
- Previous covenant script is shown for reference

#### Governance Proposal Queue (multisig only)

For multisig shards, a dedicated panel shows pending governance proposals:

| Proposal | Action | Created | Signatures | Required | Status |
|---|---|---|---|---|---|
| #1 | Freeze | 10 min ago | 2/3 | 3 | Awaiting signatures |
| #2 | Upgrade | 2 hours ago | 1/3 | 3 | Awaiting signatures |

Each proposal shows:
- The raw BSV transaction (hex, collapsible)
- Which keys have signed
- Which keys have not signed
- "Sign" button (triggers BRC-3 signature via wallet)
- "Reject" button (removes proposal locally — does not affect other nodes)
- Expiry countdown

### 2.4 Node Configuration

View and modify node runtime configuration (does NOT modify genesis or covenant — only local node settings).

**Configurable at runtime:**
- Minimum gas price (gwei)
- Target batch size
- Max batch flush delay
- Max speculative depth
- Prover mode (local GPU / SP1 Prover Network / pool)
- BSV RPC endpoint
- Peer list (add/remove bootstrap peers)

**Read-only (from genesis, cannot change):**
- Chain ID
- Governance mode and keys
- SP1 verifying key
- Bridge configuration

Changes take effect immediately. The UI shows a "Restart Required" indicator for changes that need a node restart (e.g., changing the BSV RPC endpoint).

**Data sources:** `admin_getConfig`, `admin_setConfig`.

### 2.5 Prover Management

**Proving queue:**
- Current batch being proved (tx count, gas, started at)
- Queue depth (batches waiting)
- GPU utilization (if local prover)
- SP1 Prover Network status (if network prover)

**Proving history (last 100):**

| Batch | Block | Txns | Gas | Prove Time | Result | BSV Txid |
|---|---|---|---|---|---|---|
| 1,234 | 1,234 | 128 | 5.4M | 6.2s | Won | abc... |
| 1,233 | 1,233 | 128 | 12.3M | 8.1s | Lost | — |

**Controls:**
- "Pause Proving" — stops generating proofs (node becomes follower)
- "Resume Proving" — re-enters the proving competition
- "Force Flush Batch" — immediately proves whatever is in the pending batch (useful for testing)

### 2.6 Bridge Administration

**Bridge health:**
- Total locked vs total supply mismatch detector
- Sub-covenant UTXO list with balances
- Rate limit status (current period usage)
- Pending withdrawal claims

**Deposit scanner:**
- Last scanned BSV block height
- Pending deposits (awaiting confirmations)
- Failed deposits (below minimum, wrong shard ID)
- "Rescan from height" button (re-scans BSV blocks for missed deposits)

**Data sources:** `admin_bridgeHealth`, `admin_rescanDeposits`.

### 2.7 Log Viewer

Live streaming view of the node's structured logs (via WebSocket).

**Filters:**
- Log level (DEBUG, INFO, WARN, ERROR)
- Component (overlay, prover, covenant, bridge, rpc, network)
- Time range

**Auto-scroll** with pause button. Clicking a log entry expands it to show full structured fields.

---

## Part 3: New RPC Methods

The following RPC methods are needed by the UI but not yet in spec 05. Add them.

### Public methods (no auth)

```
bsv_bridgeStatus → {
    totalLocked: "87000000000000000000",  // wei (87 BSV)
    totalSupply: "87000000000000000000",  // wei
    subCovenantCount: 3,
    rateLimitPeriod: 8640,
    currentPeriodWithdrawals: "5000000000000000000",
    maxPerPeriod: "8700000000000000000"
}

bsv_getDeposits(fromBlock, toBlock) → [{
    bsvTxid: "abc...",
    amount: "1000000000000000000",
    l2Address: "0x...",
    bsvConfirmations: 8,
    credited: true,
    l2BlockNumber: 1234
}]

bsv_getWithdrawals(fromBlock, toBlock) → [{
    nonce: 42,
    amount: "5000000000000000000",
    bsvAddress: "1ABC...",
    l2TxHash: "0x...",
    claimed: true,
    claimBsvTxid: "def...",
    csvBlocksRemaining: 0
}]

bsv_networkHealth → {
    peerCount: 5,
    executionTip: 1234,
    provenTip: 1232,
    finalizedTip: 1220,
    speculativeDepth: 2,
    maxSpeculativeDepth: 16,
    averageProvingTime: 6200,  // ms
    proofsWon: 145,
    proofsLost: 23,
    bsvChainTip: 800100,
    covenantUnconfirmedDepth: 14
}

bsv_provingStatus → {
    mode: "local",  // "local", "network", "pool", "follower"
    currentBatch: {
        txCount: 87,
        gasTotal: 4200000,
        startedAt: 1712345678
    },
    queueDepth: 1,
    gpuCount: 4,
    gpuUtilization: 0.85
}
```

### Admin methods (BRC-104 auth required)

```
admin_peerList → [{
    peerId: "QmPeer1",
    address: "/ip4/1.2.3.4/tcp/9945",
    role: "prover",
    lastHeartbeat: 1712345678,
    blocksBehind: 0
}]

admin_getConfig → { ... full node config ... }

admin_setConfig(key, value) → { success: true }

admin_bridgeHealth → {
    subCovenants: [{
        bsvTxid: "abc...",
        balance: 8700000000,  // satoshis
        lastClaimedNonce: 42,
        status: "active"
    }],
    mismatch: false,
    totalLocked: 33200000000,
    totalSupply: 33200000000
}

admin_rescanDeposits(fromHeight) → { scanning: true, fromHeight: 800000 }

admin_pauseProving → { success: true }
admin_resumeProving → { success: true }
admin_forceFlushBatch → { success: true, batchSize: 23 }

admin_createGovernanceProposal(action, params) → {
    proposalId: 1,
    action: "freeze",
    unsignedTx: "0100000001...",
    requiredSignatures: 3,
    currentSignatures: 0
}

admin_listGovernanceProposals → [{
    proposalId: 1,
    action: "freeze",
    createdAt: 1712345678,
    expiresAt: 1712432078,
    signatures: ["02abc...", "03def..."],
    required: 3,
    status: "pending"
}]

admin_signGovernanceProposal(proposalId, signature) → {
    proposalId: 1,
    signatures: 3,
    required: 3,
    status: "ready",
    broadcastTxid: "abc..."  // present if threshold met and broadcast
}
```

---

## Part 4: Implementation Notes

### Technology Stack

- **React** with TypeScript
- **Tailwind CSS** for styling
- **ethers.js** for Ethereum RPC calls (the shard is EVM-compatible)
- **BRC-100 SDK** (`@bsv/wallet-toolbox` or equivalent) for wallet authentication
- **WebSocket** for real-time block/tx subscriptions (`eth_subscribe`)
- **Vite** for build tooling

### Deployment

The SPA is built as static files and embedded in the overlay node binary (Go `embed` package). The overlay node serves:

- `GET /` → `index.html` (SPA)
- `GET /assets/*` → Static files (JS, CSS, images)
- `POST /rpc` → Public JSON-RPC endpoint
- `POST /admin/rpc` → Admin JSON-RPC endpoint (BRC-104 authenticated)
- `POST /.well-known/auth` → BRC-103 handshake endpoint

No separate web server. No reverse proxy. The explorer is part of the node.

### Configuration

```toml
[explorer]
enabled = true                    # Serve the explorer UI
admin_enabled = true              # Enable admin panel (requires governance != none)
session_timeout = "1h"            # Admin session expiry
proposal_timeout = "24h"          # Governance proposal expiry
cors_origins = ["*"]              # CORS for external access
```

### Mobile Responsiveness

The UI must be usable on mobile devices. The explorer pages (blocks, transactions, addresses) should be fully responsive. The admin panel is optimised for desktop but functional on tablet.

---

## Milestone

This UI is part of **Milestone 6 (RPC)** in spec 09. The RPC server and the explorer are built together. The public explorer is a P1 deliverable. The admin panel is P2 (requires governance implementation from Milestone 4).

## Deliverables

- [ ] React SPA with all public explorer pages (dashboard, block, tx, address, bridge, network)
- [ ] BRC-100 wallet authentication integration
- [ ] Admin panel with governance actions (freeze, unfreeze, upgrade)
- [ ] Multisig proposal workflow (create, sign, broadcast)
- [ ] All new RPC methods implemented in the overlay node
- [ ] Static build embedded in the Go binary
- [ ] Mobile-responsive explorer pages
- [ ] Documentation for operators on accessing and using the admin panel
