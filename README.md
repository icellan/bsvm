# BSVM

## What this is

BSVM is an Ethereum-compatible Layer 2 on BSV with SP1 STARK validity
proofs. Users interact via standard Ethereum tooling (MetaMask,
ethers.js, Hardhat, Foundry); deposits and withdrawals bridge BSV via
covenant UTXOs. Every state advance is authorised on-chain by a STARK
proof verified directly in Bitcoin Script — there is no sequencer key,
no privileged operator on the advance path, and no challenge window.

## Architecture at a glance

- **Shards** — independent EVM instances on BSV. Each shard has its
  own covenant UTXO chain, its own node network, its own contract
  deployments, and its own bridge covenant. Shards do not share state.
- **Nodes** — multiple independent nodes per shard. Nodes gossip
  EVM transactions, execute deterministically, and race to advance the
  covenant on BSV. The first valid advance wins; losers replay the
  winner's batch. No leader election, no sequencer rotation.
- **Prover (dual EVM)** — a Go EVM extracted from geth runs in the
  overlay node for sub-millisecond execution and immediate (speculative)
  receipts. A Rust `revm` running inside the SP1 zkVM produces a STARK
  proof of full EVM execution. Both EVMs must produce identical state
  roots; disagreement is a critical bug.
- **Bridge covenant** — a BSV UTXO that locks deposits and releases
  withdrawals. Deposits credit native L2 balance (no separately managed
  wrapped token); withdrawals burn L2 balance and release BSV after
  proof verification, gated by a Merkle root of finalised withdrawals.
- **Three on-chain verification modes** — all three are mainnet-eligible
  under VK pinning per spec 12 + 13:
  - **Mode 1 `VerifyFRI`** — full SP1 STARK verifier in Bitcoin
    Script (KoalaBear field, Poseidon2 KoalaBear Merkle, colinearity,
    Fiat-Shamir transcript) via `runar.VerifySP1FRI`.
  - **Mode 2 `VerifyGroth16`** — full BN254 multi-pairing of the
    SP1-wrapped Groth16 proof, on-chain.
  - **Mode 3 `VerifyGroth16WA`** — witness-assisted BN254 pairing
    with the verifying key baked into the locking script.

BSV is the consensus layer. Nodes do not run their own consensus.

## Quick start

Devnet (BSV regtest, dockerised):

```bash
# Build the daemon binary
make build                          # → bin/bsvm

# Bring up the full devnet (BSV regtest + 3 BSVM nodes + prover)
docker compose up

# Run the unit-test suite locally (no BSV needed)
make test

# Run the ethereum/tests EVM oracle
make test-vm

# Optional: traffic generator against a running devnet
go run ./cmd/bsvm-sim
```

A single node can also be booted from a config file. Copy
`cmd/bsvm/bsvm.example.toml` to `bsvm.toml`, fill in `[bsv].node_urls`
and `[[bsv.chaintracks.providers]]`, and run `bin/bsvm --config
bsvm.toml`. Devnet helpers live in `cmd/bsvm/dev.go` (`bsvm dev …`
subcommands talk to the regtest node directly). For testnet, see
`deploy/testnet/README.md`.

## Where to read next

| Audience               | Start here                                                         |
|------------------------|--------------------------------------------------------------------|
| Operators              | `docs/operational-runbook.md` and `deploy/testnet/README.md`       |
| Developers             | `spec/00-PROJECT-OVERVIEW.md` and `docs/INDEX.md`                  |
| Decision history       | `docs/INDEX.md`                                                    |
| Specifications         | `spec/` (00–17, with 10–17 authoritative on conflict)              |
| Whitepaper             | `whitepaper/`                                                      |

## Repo layout

| Path             | Description                                                                  |
|------------------|------------------------------------------------------------------------------|
| `cmd/bsvm`       | Shard node daemon (config, boot, BSV wiring, bridge wiring, dev helpers).    |
| `cmd/bsvm-sim`   | TUI traffic generator for the devnet.                                        |
| `cmd/evm-cli`    | Standalone EVM/CLI debug tool.                                               |
| `pkg/`           | All Go libraries (vm, state, mpt, block, overlay, prover, covenant, bridge, network, rpc, shard, arc, beef, bsv, chaintracks, whatsonchain, indexer, governance, metrics, types, crypto, rlp, event, tracing, regtestharness, sim, webui, proofmode). |
| `prover/`        | SP1 host crates (`host`, `host-evm`, `host-bridge`, `host-revm`) and Rust guests (`guest`, `guest-evm`, `proof-verify-test`). |
| `internal/db`    | LevelDB / Pebble database abstraction.                                       |
| `spec/`          | Numbered specifications 00–17. Specs 10–17 win on conflict.                  |
| `docs/`          | Operator runbook, gate-0 results, SP1 proof-format notes, decision archive. |
| `deploy/`        | Operator boot harnesses (currently `deploy/testnet`).                        |
| `test/`          | `evmtest` (ethereum/tests runner), `integration`, `e2e`, `multinode`, `devnet`, `cross_evm_diff`, `mpt_conformance`, `fuzz`. |
| `contracts/`     | Solidity sources (and pinned bytecode) used by the simulator and tests.      |
| `tools/`         | `create-bsvm-devnet`, `hardhat-bsvm` integration helpers.                    |
| `web/`           | TypeScript explorer / admin UI.                                              |
| `scripts/`       | Build helpers (e.g. `docker-build.sh`).                                      |
| `whitepaper/`    | Academic whitepaper.                                                         |

## License

MIT. See `LICENSE`.

## Status

Pre-mainnet. Active development. Not audited. Use at your own risk.

All three verification modes (Mode 1 FRI, Mode 2 Groth16, Mode 3
Groth16-WA) are mainnet-eligible under verifying-key pinning per spec
12 + 13. The covenant has no sequencer signature on the advance path;
optional governance keys can freeze and upgrade a shard but cannot
advance state or access bridge funds. Implementation status of
individual milestones evolves rapidly — check `docs/INDEX.md` and the
recent decision docs in `docs/decisions/` for the current shape of each
subsystem rather than relying on any per-package status table here.
