# BSVM: Ethereum Virtual Machine Layer 2 on BSV

## Project Name
`bsvm` — A standalone, embeddable EVM execution engine with BSV as the data availability and settlement layer.

## License
LGPL-3.0 (matching go-ethereum's library license, since we derive from `core/vm`)

## Vision
Run full Solidity/EVM smart contracts as a Layer 2 on BSV, leveraging BSV's unbounded block size for cheap data availability and its UTXO model for settlement finality. The EVM state is maintained off-chain in a Merkle Patricia Trie, with state roots (and optionally validity proofs) anchored into BSV transactions.

## Why BSV as L1?
- **Unbounded OP_RETURN / data carrier**: BSV allows large data payloads in transactions (no 80-byte limit), making it ideal for posting L2 batch data, state diffs, and proofs on-chain cheaply.
- **Stable protocol**: BSV's commitment to the original Bitcoin protocol means the L1 rules won't shift under the L2.
- **Low fees**: Sub-cent transaction fees make frequent state root anchoring economically viable.
- **UTXO model**: Enables clean deposit/withdrawal bridge design with lock scripts.

## High-Level Architecture

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
│              │    │              │    │              │
│ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │
│ │  Node A1 │ │    │ │  Node B1 │ │    │ │  Node C1 │ │
│ │  EVM     │ │    │ │  EVM     │ │    │ │  EVM     │ │
│ │  StateDB │ │    │ │  StateDB │ │    │ │  StateDB │ │
│ │  Prover  │ │    │ │  Prover  │ │    │ │  Prover  │ │
│ │  RPC     │ │    │ │  RPC     │ │    │ │  RPC     │ │
│ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │
│ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │
│ │  Node A2 │ │    │ │  Node B2 │ │    │ │  Node C2 │ │
│ │  ...     │ │    │ │  ...     │ │    │ │  ...     │ │
│ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │
└──────────────┘    └──────────────┘    └──────────────┘
```

## Design Principles

1. **Minimal fork of geth's `core/vm`**: Copy the EVM interpreter, opcodes,
   gas tables, precompiles — replace external dependencies with clean interfaces.

2. **Interface-driven decoupling**: StateDB is the key seam between the EVM
   and everything else.

3. **Ethereum RPC compatibility**: dApps and wallets work with zero changes.
   MetaMask, ethers.js, Hardhat, Foundry — all supported.

4. **BSV as consensus**: BSV miners validate covenant advances. The covenant
   UTXO chain is the single source of truth. Nodes within a shard don't
   run their own consensus — BSV is the consensus.

5. **Proof-based authorization**: The STARK proof is the sole
   authorization for state advances. Anyone with a valid proof can
   advance the state. Optional governance keys (configurable per-shard
   at genesis) can freeze/unfreeze the shard and upgrade the covenant
   script, but CANNOT advance state or access bridge funds. Shards
   can be configured as fully trustless (no governance keys) or
   governed (single key or M-of-N multisig). See spec 12.

6. **Multi-shard ecosystem**: Each use case runs its own EVM instance with
   its own covenant chain. Shards are sovereign and independent. Cross-shard
   interaction is bridging.

   Shard lifecycle (creation, discovery, joining, termination) is deferred to Phase 8 specification. Shard IDs are derived from the genesis covenant UTXO txid. Nodes discover shards via a bootstrap configuration that includes the genesis covenant txid.

7. **Multi-node replication**: Each shard is run by multiple nodes.
   Execution is deterministic. Any node can advance the covenant. No
   single point of failure.

## Phased Delivery

| Phase | Name | Description |
|-------|------|-------------|
| 1 | EVM Extraction | Extract geth core/vm, custom StateDB, pass ethereum/tests |
| 2 | Block Engine | L2 block types, execution pipeline, receipts |
| 3 | Prover | SP1 zkVM guest program (revm), Go host integration, STARK proof generation |
| 4 | Covenant | Rúnar covenant contracts, SP1 FRI verifier in Script, covenant manager |
| 5 | Overlay Node | Single-node: execute, prove, advance covenant, cache, broadcast |
| 6 | RPC Gateway | Ethereum-compatible JSON-RPC |
| 7 | Network + Replication | Multi-node gossip, state replication, covenant advance racing |
| 8 | Shard Lifecycle | Genesis, node discovery, joining existing shards |
| 9 | Bridge | BSV↔shard deposits/withdrawals, cross-shard bridging |
| 10 | Hardening | Fuzzing, ethereum/tests, proof soundness testing, multi-node stress testing |

## Key Prior Art & Learnings

- **duanbing/go-evm**: Proved the extraction is feasible. Key insight: implement `core/interface.go` to bridge UTXO and EVM worlds. Limitation: based on geth 1.8, missing post-Istanbul opcodes.
- **Kdag-K/evm**: Showed how to make the EVM consensus-agnostic. Their `Service` abstraction is a good pattern.
- **ava-labs/coreth**: Demonstrated UTXO↔account model bridging for atomic transactions. Their approach to translating between models is directly applicable.
- **evstack/go-execution-evm**: Modern rollup-oriented EVM extraction using the go-execution interface pattern.
- **Rúnar compiler**: Multi-language Bitcoin Script compiler (Go, TS, Rust,
  Python) with byte-identical output. Provides the covenant locking scripts
  and the SHA256 + field arithmetic primitives for STARK verification. Created
  by the same team as bsvm.

## Repository Structure

```
bsvm/
├── cmd/
│   ├── bsvm/              # Shard node binary
│   └── evm-cli/              # CLI debugging tool
├── pkg/
│   ├── vm/                   # Extracted EVM (from geth core/vm)
│   ├── state/                # StateDB implementation
│   ├── mpt/                  # Merkle Patricia Trie
│   ├── block/                # L2 block types and execution
│   ├── overlay/              # Overlay node: execute, prove, broadcast
│   ├── covenant/             # Rúnar covenant contracts + management
│   │   └── contracts/        # rollup.go, bridge.go, sp1_verifier.go
│   ├── prover/               # SP1 zkVM prover (revm guest + Go host)
│   │   └── guest/            # Rust SP1 guest program (revm inside zkVM)
│   ├── network/              # Peer-to-peer gossip within a shard
│   ├── shard/                # Shard lifecycle (genesis, join, discovery)
│   ├── rpc/                  # Ethereum JSON-RPC gateway
│   ├── bridge/               # BSV↔L2 bridge + cross-shard bridging
│   ├── bsv/                  # BSV client interface + RPC/ARC implementations
│   ├── types/                # Shared types
│   ├── crypto/               # Keccak, secp256k1, address derivation
│   ├── rlp/                  # RLP encoding
│   └── event/                # Typed event feeds
├── internal/
│   └── db/                   # LevelDB/Pebble database abstraction
├── test/
│   ├── evmtest/              # ethereum/tests runner
│   └── e2e/                  # End-to-end tests
├── spec/                     # Specifications
├── go.mod
└── README.md
```

Note: `pkg/sequencer/` and `pkg/anchor/` do not exist. Do not create them.
Transaction ordering and batch construction logic lives in `pkg/overlay/`. The prohibition on `pkg/sequencer/` means there is no privileged sequencer role — any overlay node can propose batches.
