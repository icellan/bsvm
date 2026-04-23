# BSVM

## NOTE: BSVM is still a work in progress. A lot of things still need to be tested and validated. DO NOT USE IN PRODUCTION.

A validity-proven Ethereum Virtual Machine Layer 2 on BSV.

BSVM runs full EVM smart contracts on BSV, with every state transition proven correct by a STARK proof verified on-chain in Bitcoin Script. There is no sequencer key — the proof alone authorizes state advances. Anyone with a valid proof can advance the chain.

## Architecture

BSVM is an ecosystem of independent EVM instances (*shards*), each running as a BSV overlay network. Each shard has:

- **A covenant UTXO chain on BSV** — a sequence of BSV transactions forming a chain of state commitments. Each transaction spends the previous covenant UTXO and creates a new one carrying the updated state root. The locking script is a Rúnar-compiled FRI verifier that validates STARK proofs in Bitcoin Script.

- **A node network** — multiple independent nodes that replicate state via peer-to-peer gossip. All nodes execute the same EVM transactions deterministically. Any node can generate a STARK proof and advance the covenant. BSV resolves races — if two nodes advance simultaneously, miners accept whichever propagated first. The winner earns gas fees; losers replay the winner's batch and continue.

- **A bridge covenant** — BSV UTXOs that hold locked BSV backing the shard's native token (wBSV). Deposits lock BSV and mint wBSV on L2. Withdrawals burn wBSV and release BSV after proof verification.

```
┌─────────────────────────────────────────────────────────┐
│                    BSV Network (L1)                       │
│                                                          │
│   Covenant chain A     Covenant chain B    Covenant C    │
│   (DeFi shard)         (Identity shard)    (Social)      │
│   UTXO→UTXO→UTXO→     UTXO→UTXO→UTXO→    UTXO→UTXO→   │
└─────┬──────────────────────┬───────────────────┬─────────┘
      │                      │                   │
      ▼                      ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Shard A Nodes│    │ Shard B Nodes│    │ Shard C Nodes│
│  EVM+Prover  │    │  EVM+Prover  │    │  EVM+Prover  │
│  RPC+Gossip  │    │  RPC+Gossip  │    │  RPC+Gossip  │
└──────────────┘    └──────────────┘    └──────────────┘
```

## How It Works

1. A user submits a signed EVM transaction via `eth_sendRawTransaction` (standard Ethereum RPC).
2. The overlay node validates, executes through the Go EVM engine (sub-millisecond), and returns a receipt immediately.
3. The node batches up to 128 transactions and generates a STARK proof via SP1 (a zkVM that proves RISC-V execution of the Rust EVM `revm`).
4. The node builds a BSV transaction spending the covenant UTXO, with the STARK proof in the unlocking script and batch data in an OP_RETURN output.
5. BSV miners validate the STARK proof via the FRI verifier in the covenant's locking script. If valid, the state advances. If invalid, the transaction is rejected.
6. Users interact via MetaMask, ethers.js, Hardhat, or Foundry — standard Ethereum tooling with zero modifications.

## Dual-EVM Proof Pipeline

The system runs two EVM implementations that must produce identical results:

| | Go EVM (geth extraction) | Rust EVM (revm inside SP1) |
|---|---|---|
| Purpose | Fast local execution | Proven execution |
| Speed | Sub-millisecond | Seconds (proving) |
| Output | State root + receipts | State root + STARK proof |
| Where | Inside overlay node | External SP1 prover |

Both pass the Ethereum test suite. The Go EVM returns receipts instantly. The STARK proof follows in seconds. The BSV covenant only accepts the proof.

## EVM Compatibility

BSVM is 100% Ethereum-compatible. Users deposit BSV via the bridge, receive wBSV (the native gas token), and interact via standard Ethereum tooling:

- **Solidity contracts** deploy and execute unchanged
- **MetaMask** connects and displays balances
- **ethers.js / web3.js** send transactions and query state
- **Hardhat / Foundry** run tests against a BSVM node
- **ERC-20, ERC-721, Uniswap, Aave** — all standard contracts work

Gas is paid in wBSV. 1 wBSV = 1 BSV = 10¹⁸ L2 wei (matching Ethereum's 18-decimal convention).

## Fee Economics

At BSV's fee rate of 100 sat/KB, a 128-transaction batch costs ~21,600 satoshis (~$0.0065) to post on-chain.

| Batch | Gas | Revenue (1 gwei) | BSV cost | Margin |
|---|---|---|---|---|
| 128 simple transfers | 2.7M | 268,800 sats | 21,600 sats | 12× |
| 128 ERC-20 transfers | 8.3M | 832,000 sats | 21,600 sats | 39× |
| 128 Uniswap swaps | 19.2M | 1,920,000 sats | 21,600 sats | 89× |

Per-transaction L1 cost: ~169 satoshis (~$0.00005). Break-even gas price: ~0.08 gwei — roughly 60× cheaper than Ethereum mainnet.

## Security Model

**State transition integrity**: The STARK proof guarantees full EVM execution correctness — every opcode, every balance transfer, every gas deduction. A forged proof would require breaking the hash function underlying the FRI protocol.

**No sequencer key**: The proof is the sole authorization for state advances. No privileged party can advance state without a valid proof. This eliminates sequencer-level censorship and single points of failure.

**Data availability**: Batch data is published in the OP_RETURN output of every covenant-advance transaction. The STARK proof commits to the batch data hash, and the covenant verifies this on-chain via `OP_HASH256`. Batch data is permanently available on BSV.

**Censorship resistance**: The multi-node architecture provides first-order resistance (submit to any node). A forced-inclusion inbox covenant on BSV provides second-order resistance (submit directly to BSV, bypassing all nodes).

**Bridge security**: Withdrawals are verified via STARK proof (no 7-day challenge period). Tiered CSV timelocks protect against BSV reorgs. Rate limiting caps withdrawals at 10% of TVL per period.

**Governance**: Configurable per-shard at genesis. Three modes:
- `none` — fully trustless, no recovery from bugs
- `single_key` — one key can freeze/upgrade the shard
- `multisig` — M-of-N keys required for governance operations

Governance keys can freeze and upgrade the covenant but cannot advance state or access bridge funds.

## Covenant Contract

The state covenant is written in the Rúnar Go DSL and compiled to Bitcoin Script. It lives in `pkg/covenant/contracts/rollup.runar.go` and implements:

- **advanceState** — verifies the STARK proof, checks pre/post state roots against public values, validates batch data hash binding via `OP_HASH256`, enforces strict block number increment, and verifies the chain ID for cross-shard replay prevention
- **freeze** / **unfreeze** — governance key can pause and resume state advances
- **upgrade** — governance key can replace the covenant script (must freeze first)

The covenant has been validated on BSV regtest with 186 KB transactions (165 KB proof data + 20 KB batch data) executing at ~82ms per advance, with 25+ consecutive UTXO chain spends verified.

## Project Structure

```
bsvm/
├── cmd/
│   ├── bsvm/                 # Shard node binary
│   └── evm-cli/              # CLI debugging tool
├── pkg/
│   ├── vm/                   # Extracted EVM (from geth core/vm)
│   ├── state/                # StateDB implementation (MPT + LevelDB)
│   ├── mpt/                  # Merkle Patricia Trie
│   ├── block/                # L2 block types and execution pipeline
│   ├── overlay/              # Overlay node: execute, prove, broadcast
│   ├── covenant/             # Rúnar covenant contracts + management
│   │   └── contracts/        # rollup.go, bridge.go, sp1_verifier.go
│   ├── prover/               # SP1 zkVM prover (revm guest + Go host)
│   │   └── guest/            # Rust SP1 guest program
│   ├── network/              # P2P gossip within a shard
│   ├── shard/                # Shard lifecycle (genesis, join, discovery)
│   ├── rpc/                  # Ethereum JSON-RPC gateway
│   ├── bridge/               # BSV↔L2 bridge
│   ├── bsv/                  # BSV client interface
│   ├── types/                # Shared types (Address, Hash, Log, etc.)
│   ├── crypto/               # Keccak, secp256k1, address derivation
│   ├── rlp/                  # RLP encoding
│   └── event/                # Typed event feeds
├── internal/
│   └── db/                   # LevelDB/Pebble database abstraction
├── test/
│   ├── integration/          # BSV regtest integration tests
│   ├── evmtest/              # ethereum/tests runner
│   └── e2e/                  # End-to-end tests
├── spec/                     # Specifications (00-13)
├── whitepaper/               # Academic whitepaper
└── go.mod
```

## Specifications

The `spec/` directory contains 14 specification documents covering the complete system design:

| Spec | Topic |
|------|-------|
| 00 | Project overview and architecture |
| 01 | EVM extraction from geth |
| 02 | StateDB and Merkle Patricia Trie |
| 03 | L2 block engine and execution pipeline |
| 04 | (superseded by spec 10) |
| 05 | Ethereum JSON-RPC gateway |
| 06 | (superseded by spec 11) |
| 07 | BSV↔L2 bridge (deposits and withdrawals) |
| 08 | Genesis configuration and node startup |
| 09 | Implementation order, milestones, and validation gates |
| 10 | Deep BSV integration via Rúnar covenants |
| 11 | Overlay node, multi-node model, and shard network |
| 12 | Full EVM validity proofs via SP1 zkVM |
| 13 | Rúnar compiler requirements and FRI verifier |

Specs 10-13 are authoritative — where they conflict with specs 00-09, the later specs win.

## Implementation Status

| Component | Status |
|-----------|--------|
| Specifications (00-13) | Complete |
| Whitepaper | Complete |
| Covenant contract (Rúnar) | Complete — validated on BSV regtest |
| Integration tests | Complete — 186 KB txs, 25-advance chains |
| Gate 0a primitives | Confirmed — Baby Bear, Merkle depth 20, hash256 |
| EVM extraction | Not started (Milestone 1) |
| StateDB + MPT | Not started (Milestone 1) |
| Block engine | Not started (Milestone 2) |
| SP1 prover | Not started (Milestone 3) |
| FRI verifier (full) | Not started (Gate 0b) |
| Overlay node | Not started (Milestone 5) |
| RPC gateway | Not started (Milestone 6) |
| Network + replication | Not started (Milestone 7) |
| Bridge | Not started (Milestone 9) |

## Building

```bash
# Build the node binary
go build -o bin/bsvm ./cmd/bsvm

# Run unit tests
go test ./pkg/... ./internal/... -race -count=1

# Run ethereum/tests suite
go test ./test/evmtest/... -run TestVMTests -timeout 30m

# Run integration tests (requires BSV regtest node)
cd test/integration
go test -tags integration -v -timeout 600s
```

## Traffic simulator (`bsvm-sim`)

TUI-driven load generator for the devnet. Spins up a pool of users and
a library of common EVM contracts (ERC-20, ERC-721, WETH, Uniswap V2-
style AMM, multisig, storage, plain transfers), deploys them once, then
runs continuous randomised traffic. Operators can add/remove users and
start/stop workloads live via keybinds.

```bash
# Boot the devnet first (docker compose up), then:
go run ./cmd/bsvm-sim

# Headless mode (CI / logs to file):
go run ./cmd/bsvm-sim --headless --duration 60s --tps 3

# Limit workloads or target a single node:
go run ./cmd/bsvm-sim --nodes http://localhost:8546 \
    --workloads value-transfer,erc20-transfer,amm-swap
```

TUI keybinds: `a`/`x` add/drop user, `w` toggle selected workload,
`+`/`-` adjust rate, `]`/`[` adjust rate by 10, `p`/`r` pause/resume,
`tab` cycle panels, `?` help, `q` quit.

Contract sources live in `contracts/src/` — regenerate bytecode via
`contracts/README.md` after edits (pinned to solc 0.8.28, 200 runs).

## Dependencies

- Go 1.22+
- `github.com/holiman/uint256` — 256-bit integer math
- `github.com/syndtr/goleveldb` — LevelDB
- `golang.org/x/crypto` — blake2b, ripemd160
- `github.com/icellan/runar` — Rúnar Bitcoin Script compiler (Go DSL)
- `github.com/decred/dcrd/dcrec/secp256k1/v4` — secp256k1 EC operations
- `github.com/libp2p/go-libp2p` — P2P networking
- SP1 v4.1.1 + Rust toolchain (for the prover guest program)

No `github.com/ethereum/go-ethereum` in the final dependency tree. All geth code is copied and adapted.

## License

LGPL-3.0 (matching go-ethereum's library license, since the EVM is derived from `core/vm`).
