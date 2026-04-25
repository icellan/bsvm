# Implementation Order & Dependencies

## Dependency Graph

```
                    pkg/rlp
                       │
                    pkg/types
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
       pkg/crypto   internal/db   pkg/vm/tracing
            │          │
            ▼          │
          pkg/vm ◄─────┘
            │
            ▼
         pkg/mpt
            │
            ▼
        pkg/state
            │
       ┌────┴──────────┐
       ▼                ▼
    pkg/block       pkg/prover
       │            (SP1 guest + host)
       │                │
       ▼                ▼
    pkg/event      pkg/covenant
       │            (Rúnar contracts, manager)
       │                │
       ▼                ▼
    pkg/overlay ◄───────┘
       │
  ┌────┼────┐
  ▼    ▼    ▼
pkg/ pkg/  pkg/
rpc  net   shard
  │  work  
  │    │    │
  ▼    ▼    ▼
    pkg/bridge
       │
    pkg/bsv  (BSV client interface, used by overlay, covenant, bridge)
       │
       ▼
   cmd/bsvm
```

## Implementation Milestones

### Milestone 0: Validation Gates (BLOCKS ALL OTHER WORK)

These gates must pass before implementation proceeds past Milestone 2.
They determine whether the proof architecture is viable.

**Gate 0a: SP1 FRI Verifier on BSV**
- Implement a minimal FRI verifier for SP1's STARK proof format using the Rúnar Go DSL
- Compile to Bitcoin Script
- Deploy and execute on BSV regtest
- Pass/fail against targets: <10MB script, <1000 stack elements, <1s execution
- If any target is exceeded by >3×, the proof architecture must be revised
  (options: optimistic proofs with fraud window, off-chain verification
  with on-chain commitment only, or hybrid)
- This gate blocks: Milestone 3 (Prover), Milestone 4 (Covenant)
- Gate 0a evaluation MUST complete before any implementation beyond the
  EVM extraction (Milestone 1). See Spec 13, Gate 0a, for the fallback
  plan if the FRI verifier exceeds script size targets.

**Gate 0a Primitive Validation: COMPLETE.** All FRI building blocks
have been implemented in Rúnar and validated on BSV regtest with
Plonky3-generated test vectors (1,326 total vectors). Measured locking
script sizes: KoalaBear add/mul 9 bytes, inv 477 bytes, Ext4 mul 509
bytes, Ext4 inv ~3.1 KB, Merkle proof depth-20 482 bytes, FRI
colinearity check 1,742 bytes. Rúnar additionally implements
Poseidon2 over KoalaBear directly in Bitcoin Script (28-round
permutation, Plonky3 p3-koala-bear 0.5.2 round constants), so on-chain
Merkle openings replay the SP1 FRI argument natively without any
host-side SHA-256 transcoding step.

**Gate 0a Full — COMPLETE.** The full SP1 v6.0.2 STARK / FRI verifier
ships as a Rúnar DSL intrinsic: `runar.VerifySP1FRI(proofBlob,
publicValues, sp1VKeyHash) bool` lowers to the production-scale
Bitcoin Script body (~849 KB compiled for the evm-guest preset; well
under the 2 MB target). The Mode 1 covenant
(`pkg/covenant/contracts/rollup_fri.runar.go`) calls this intrinsic on
every advance, replaying the STARK argument against the pinned
`SP1VerifyingKeyHash`. The previous `PrepareGenesis` Mode 1 mainnet
guardrail has been lifted — Mode 1, Mode 2, and Mode 3 are all
mainnet-eligible under the standard VK pinning policy (F06).

**Gate 0b: SP1 Proof Size and Verification Cost**

Gate 0b is the full round-trip: generate a real SP1 proof, verify it
on BSV regtest using the Rúnar-compiled FRI verifier. Execute these
steps in order:

1. **Generate a minimal SP1 proof**: Write the simplest possible SP1
   guest program (e.g., `a + b = sum`). Generate a proof using the
   SP1 SDK. Save the serialised proof bytes, verifying key, public
   values, and ELF binary.

2. **Document the proof binary layout**: Trace through SP1 v6.0.2
   source code to map the exact byte-level structure of the serialised
   proof. Document where each component lives: shard proofs, FRI
   commitments (Merkle roots), FRI query proofs (evaluations + Merkle
   paths), opening values, and public values. See spec 12 "SP1 Proof
   Binary Layout" for the structure to document.

3. **Document FRI parameters**: Extract SP1's exact FRI configuration
   from source (field, extension degree, hash function, blowup factor,
   number of queries, folding factor, proof-of-work bits, security
   level). These are compile-time constants in the Rúnar FRI verifier.

4. **Generate an EVM guest proof**: Write the BSVM guest program from
   spec 12 (simplified: single transfer). Generate a proof. Measure
   proof size, proving time, RISC-V cycle count, and number of FRI
   shards. Extract a complete FRI verification trace (every Merkle
   root checked, every colinearity equation, every field operation) —
   this trace is the golden reference for the Rúnar Script verifier.

5. **Implement the FRI verifier in Rúnar**: Build the full verifier
   using the proven primitives (KoalaBear, Merkle proofs, hash ops).
   The verifier follows the trace from step 4 step by step. See spec
   13, Gate 0a Full, for details.

6. **Test on BSV regtest**: Deploy the FRI verifier as a covenant on
   regtest. Verify it accepts the proofs from steps 1 and 4. Verify
   it rejects corrupted proofs (bad Merkle path, bad folding, wrong
   public values, wrong VK, truncated proof, all-zeros proof). Each
   negative test is as important as the positive tests.

7. **Measure and evaluate**: Compare against thresholds:

| Metric | Acceptable | Marginal | Unacceptable |
|---|---|---|---|
| Proof size | < 200KB | 200KB - 500KB | > 500KB |
| Verifier script size | < 5MB | 5MB - 10MB | > 10MB |
| Verification time (BSV regtest) | < 1s | 1s - 3s | > 3s |

- If any metric is "Unacceptable", halt and evaluate: reduce security
  parameter, use proof compression/recursion, or redesign
- This gate blocks: Milestone 3 (Prover)

**Checkpoint**: Both gates pass. Architecture is confirmed viable.
If either gate fails, halt and redesign before proceeding.

### Milestone 1: Standalone EVM

```
pkg/rlp/
pkg/types/
pkg/crypto/
pkg/vm/
pkg/vm/tracing/
internal/db/
pkg/mpt/ (with trienode/)
pkg/state/
```
Checkpoint: ethereum/tests VMTests pass.

### Milestone 2: Block Execution

```
pkg/block/ (types, executor, apply, state_transition, gas_pool)
pkg/types/transaction.go, receipt.go, signer.go
pkg/event/
```
Checkpoint: Can execute a batch of txs, produce state root, generate receipts.
No block producer timer — execution is called by the overlay node.

### Milestone 3: Prover (SP1)

```
prover/guest/              # SP1 guest program (Rust, revm inside SP1 zkVM)
prover/guest/Cargo.toml
prover/guest/src/main.rs   # ~2,000 lines: load state, execute revm, commit outputs
pkg/prover/host.go         # Go interface to SP1 prover (subprocess or network)
pkg/prover/state_export.go # Serialise accessed state + Merkle proofs for guest
pkg/prover/proof.go        # Proof serialisation/deserialisation
pkg/prover/parallel.go     # Parallel proving coordinator
pkg/prover/config.go       # SP1 prover configuration
pkg/prover/verify.go       # Local proof verification (Go, for testing)
```
Checkpoint: Given an EVM execution trace (batch of txs + pre-state),
the SP1 guest (revm) produces a STARK proof. The proof verifies in Go.
Round-trip test: execute batch in Go EVM, export state, prove in SP1,
verify proof matches Go EVM output.

### Milestone 4: Covenant

```
pkg/covenant/contracts/rollup.go
pkg/covenant/contracts/sp1_verifier.go
pkg/covenant/contracts/bridge.go
pkg/covenant/compile.go
pkg/covenant/manager.go
pkg/covenant/genesis.go
pkg/covenant/unlock.go
pkg/covenant/state.go
pkg/covenant/verify.go
pkg/covenant/governance.go         # GovernanceConfig types, freeze/unfreeze/upgrade logic
```
Checkpoint: Compile covenant with Rúnar for each governance mode (none,
single_key, multisig). Deploy to BSV regtest. Advance covenant with a
valid STARK proof. Verify rejected with invalid proof. Test governance:
freeze a governed shard, verify advanceState is rejected while frozen,
upgrade the covenant script while frozen, unfreeze, verify advanceState
works with the new script. Verify GovernanceNone has no freeze/upgrade
methods.

### Milestone 5: Overlay Node (single node)

```
pkg/overlay/node.go
pkg/overlay/process.go
pkg/overlay/cache.go
pkg/overlay/dsmonitor.go
pkg/overlay/rollback.go
pkg/overlay/gas.go
pkg/overlay/batch.go
pkg/overlay/config.go
```
Checkpoint: Single node running. Submit EVM tx via RPC → executes → proves →
advances covenant on BSV regtest → returns receipt.

### Milestone 6: RPC Gateway

```
pkg/rpc/ (all files from spec 05)
```
Checkpoint: MetaMask connects. Hardhat tests pass against the node.

### Milestone 7: Multi-Node Network

```
pkg/network/gossip.go
pkg/network/peers.go
pkg/network/sync.go
pkg/network/protocol.go
```
Checkpoint: Two nodes running same shard. Submit tx to node 1, node 2
receives it via gossip, both execute, both arrive at same state root.
One advances the covenant, the other accepts it.

### Milestone 8: Shard Lifecycle

```
pkg/shard/genesis.go
pkg/shard/join.go
pkg/shard/sync.go
pkg/shard/discovery.go
```
Checkpoint: `bsvm init` creates a new shard. `bsvm run` on a second
machine joins the shard and syncs by replaying the covenant chain from BSV.

### Milestone 9: Bridge

```
pkg/bridge/ (deposit, withdrawal, cross-shard)
contracts/L2Bridge.sol
```
Checkpoint: Deposit BSV → credited on L2. Withdraw from L2 → BSV released.

### Milestone 10: Hardening

- Fuzz the prover: random traces → prove → verify → must always be consistent
- Fuzz the verifier: tampered proofs must always be rejected
- ethereum/tests GeneralStateTests pass
- Multi-node stress test: 100 txs, 3 nodes, covenant advances correctly
- Cross-compiler covenant verification: Go + Rust Rúnar produce identical Script
- **Governance state machine testing**: Verify the full state machine:
  ACTIVE→freeze→FROZEN, FROZEN→unfreeze→ACTIVE, FROZEN→upgrade→FROZEN(new),
  ACTIVE→upgrade→REJECTED. Test with all governance modes. Verify governance
  keys cannot advance state. Verify multisig threshold enforcement.
- **Proof aggregation preparation**: The v1 covenant uses strict
  `Equal+1` for block numbers. Proof aggregation (proving blocks
  N→N+K in a single proof) requires a covenant migration to relax
  this to `GreaterThan`. Milestone 10 should design and test the
  migration path but aggregation is not required for launch.
- **EVM disagreement alerting**: Add a circuit breaker for persistent
  Go EVM / SP1 revm disagreement. Retry policy:
  - **Retry limit**: 2 retries per block (3 total attempts)
  - **Backoff**: 5s between retries (allows transient issues to resolve)
  - **Circuit breaker**: After 3 consecutive blocks with disagreements
    (not just retries for a single block), the node:
    1. Pauses the Batcher (stops accepting new transactions)
    2. Enters follower-only mode (replay other nodes' advances)
    3. Fires an operator alert via the health monitoring webhook
    4. Logs full diagnostic info: block number, Go root, SP1 root,
       transaction hashes, pre-state root
  - **Recovery**: Operator investigates, fixes the issue (likely an EVM
    divergence bug), and manually clears the circuit breaker via
    `bsvm admin reset-circuit-breaker`
  - **Single-node shard stall**: If no other nodes exist to advance the
    covenant, the shard stalls until the operator resolves the issue.
    This is by design — advancing with a known disagreement risks
    corrupting the covenant chain.
- **Cross-EVM differential testing**: Run full ethereum/tests suite against
  both Go EVM and SP1 revm, verify zero state root divergences (see Spec
  12, Cross-EVM Differential Testing)

## Testing Strategy

### Package Specifications Not Covered Elsewhere

The following packages are referenced in milestones but lack dedicated specs.
Their implementation is guided by reference implementations and standards:

- **`pkg/rlp/`**: RLP encoding/decoding per the Ethereum Yellow Paper
  (Appendix B). Must be bit-exact with geth's RLP for transaction hashing
  and state root computation. Extract from geth's `rlp/` package or
  implement from the specification.

- **`pkg/event/`**: Typed event feed for intra-process pub/sub (new blocks,
  new transactions, covenant confirmations). Can be modelled after geth's
  `event.Feed` — a simple synchronous fan-out channel multiplexer.

- **`pkg/network/`**: P2P gossip protocol for intra-shard transaction and
  block propagation. Uses libp2p.

  **Protocol ID**: `/bsvm/shard/<chain_id>/1.0.0`

  **Message types** (protobuf-encoded, prefixed with 1-byte type tag):

  | Type | Tag | Description | Max size |
  |------|-----|-------------|----------|
  | `TxGossip` | 0x01 | Single RLP-encoded EVM transaction | 128KB |
  | `BlockAnnounce` | 0x02 | L2 block header + tx hashes (not full txs) | 32KB |
  | `CovenantAdvanceAnnounce` | 0x03 | BSV txid + L2 block number + state root | 128B |
  | `BatchRequest` | 0x04 | Request full batch data for an L2 block | 40B |
  | `BatchResponse` | 0x05 | Full batch data (txs + context) | 512KB |
  | `Heartbeat` | 0x06 | Peer liveness signal (see Health Monitoring) | 64B |

  **Peer discovery**: bootstrap nodes (from config) + mDNS for local
  development. Peers exchange `Heartbeat` messages every 10 seconds.

  **Authentication**: none required — all data is publicly verifiable.
  Malicious messages are detected by state root verification.

  **DoS protection**:
  - Rate limit per peer: 100 messages/second (configurable)
  - Message size limit: see Max size column above
  - Peer scoring: peers that send invalid data (wrong state roots,
    malformed messages) are penalised; score < -100 = disconnect
  - Max connections per IP: 5

### Cross-Implementation MPT Conformance Tests

The system depends on the Go MPT (extracted from geth, in `pkg/mpt/`)
and the Rust MPT (alloy-trie, in the SP1 guest) producing bit-identical
state roots for the same state. ethereum/tests covers many cases but not
all MPT edge cases. A dedicated conformance suite is required:

```
test/mpt_conformance/
├── fixtures/               # JSON test fixtures for MPT edge cases
│   ├── empty_trie.json
│   ├── single_account.json
│   ├── delete_all_accounts.json
│   ├── single_storage_slot.json
│   ├── max_depth_path.json
│   ├── branch_node_collapse.json
│   ├── extension_node_split.json
│   └── mixed_operations.json
├── go_runner_test.go       # Runs fixtures against Go MPT
└── rust_runner/            # Runs fixtures against alloy-trie
    ├── Cargo.toml
    └── src/main.rs
```

Each fixture specifies:
1. A sequence of trie operations (insert, update, delete)
2. The expected root hash after each operation
3. The expected Merkle proof for specific keys

Both Go and Rust runners must produce identical results for every
fixture. This suite runs as part of Milestone 3's gate check (before
the SP1 guest program is used in production).

**Edge cases that MUST be covered**:
- Empty trie (root = `keccak256(RLP(""))`)
- Trie with single account, then delete it → empty trie
- Account with storage, delete all storage → storage root reverts to empty
- Maximum-depth key path (32 bytes of all 0xFF)
- Branch node that collapses to extension after deletes
- Storage trie with exactly one slot

### Unit Tests (per package)
Every package gets `*_test.go` files. Key test areas:

```
pkg/rlp/         → Encoding roundtrip, edge cases, geth compatibility
pkg/vm/          → Opcode correctness, gas calculation, precompile outputs
pkg/state/       → Snapshot/revert, storage isolation, commit/hash
pkg/mpt/         → Trie operations, proof generation, hash computation
pkg/block/       → State transition, receipt generation, genesis init
pkg/overlay/     → Tx processing, cache management, rollback, race recovery
pkg/rpc/         → JSON-RPC encoding, method routing, error codes
pkg/prover/      → Circuit compilation, proof generation/verification
pkg/covenant/    → Covenant compilation, state management
pkg/bridge/      → Deposit parsing, amount conversion, withdrawal proofs
pkg/network/     → Gossip protocol, peer management
```

### Integration Tests

```
test/evmtest/
├── vm_test_runner.go      # Runs ethereum/tests VMTests
├── state_test_runner.go   # Runs ethereum/tests GeneralStateTests
└── fixtures/              # Symlink or copy of ethereum/tests

test/e2e/
├── deploy_contract_test.go    # Deploy + interact with ERC-20
├── bridge_deposit_test.go     # Simulate BSV deposit → L2 credit
├── bridge_withdrawal_test.go  # Simulate L2 withdrawal → BSV release
├── rpc_compatibility_test.go  # eth_* methods against known responses
└── hardhat_test.go            # Run Hardhat test suite against L2
```

## Go Module Dependencies (go.mod)

```
module github.com/icellan/bsvm

go 1.22

require (
    github.com/holiman/uint256 v1.3.1        // 256-bit math
    github.com/syndtr/goleveldb v1.0.0        // LevelDB
    golang.org/x/crypto v0.28.0               // blake2b, ripemd160
    github.com/gorilla/websocket v1.5.3       // WebSocket
    github.com/urfave/cli/v2 v2.27.5          // CLI framework
    github.com/BurntSushi/toml v1.4.0         // Config parsing
    golang.org/x/sync v0.8.0                  // errgroup
    github.com/klauspost/compress v1.17.11    // zstd compression
    github.com/bsvm/runar-go v0.3.0       // Rúnar Go compiler
    github.com/decred/dcrd/dcrec/secp256k1/v4 // secp256k1 EC operations
    github.com/libp2p/go-libp2p               // P2P networking
)
```

**Notable absences**: No `github.com/ethereum/go-ethereum` in go.mod. The EVM code is copied and adapted, not imported.

## Build & CI

```makefile
# Makefile

.PHONY: build test lint clean

build:
	go build -o bin/bsvm ./cmd/bsvm
	go build -o bin/evm-cli ./cmd/evm-cli

test:
	go test ./pkg/... ./internal/... -race -count=1

test-vm:
	go test ./test/evmtest/... -run TestVMTests -timeout 30m

test-state:
	go test ./test/evmtest/... -run TestStateTests -timeout 60m

test-e2e:
	go test ./test/e2e/... -timeout 10m

lint:
	golangci-lint run ./...

fuzz:
	go test ./test/fuzz/... -fuzz=. -fuzztime=60s

clean:
	rm -rf bin/ data/

docker:
	docker build -t bsvm:latest .

all: lint test build
```

## Performance Targets

> **Proving targets are PROVISIONAL and depend on SP1 benchmarks. See
> spec 12 for details. These must be benchmarked with the actual SP1
> guest program before being treated as commitments.**
>
> SP1 has a built-in keccak256 precompile, so keccak256 cost is no
> longer a critical unknown. The key variables are SP1 proof generation
> time and proof size for realistic EVM batches.

| Metric | Target | Notes |
|---|---|---|
| Simple transfer execution | < 50μs | SLOAD/SSTORE dominate |
| ERC-20 transfer | < 200μs | Including storage reads |
| Block execution (100 txs) | < 50ms | Excluding proving |
| State root computation | < 100ms | For 100 tx block |
| STARK proving (single tx) | ~2s (CPU) / ~1s (GPU) | SP1 with revm guest |
| STARK proving (128 tx batch) | ~10s (CPU) / ~3-5s (GPU) | SP1 with revm guest |
| User-perceived tx latency | < 50ms | Execution only; proving is async |
| RPC eth_call latency | < 10ms | p99 |
| RPC eth_getBalance | < 1ms | p99, cached state |

### Milestone 3 Gate: Proving Feasibility

Before proceeding past Milestone 3, the following must be demonstrated:
1. The SP1 guest program (revm) correctly executes ethereum/tests fixtures
   and produces state roots matching the Go EVM
2. An SP1 proof for a 10-tx batch is generated within acceptable time
3. The proof is verified using the Rúnar-compiled FRI verifier on BSV regtest
4. Script execution time and size are within Milestone 0 bounds

**Failure criteria (any one triggers a stop)**:
- SP1 guest and Go EVM produce different state roots for any ethereum/tests fixture
- SP1 proof generation for a 10-tx batch exceeds 5 minutes
- FRI verifier script exceeds 10MB or takes >3 seconds on BSV regtest
- Proof size exceeds 500KB for a 10-tx batch

**Fallback options (evaluated in order)**:
1. Use SP1's proof compression (recursive proving) to reduce proof size
2. Increase batch size to amortise fixed verification cost
3. Use SP1's prover network for faster proving (offload to remote GPU)
4. If none of the above bring proving into acceptable bounds, evaluate
   alternative zkVMs (RISC Zero, Jolt) or a hybrid approach with
   optimistic execution + fraud proofs as fallback

## Security Considerations

1. **No sequencer key**: The STARK proof is the sole authorization.
   No privileged key to compromise. Nodes have BSV fee wallets but these
   confer no special authority over the covenant.
2. **Bridge covenant sharding**: Bridge UTXOs are split across multiple
   covenant UTXOs. A bug exposes at most one sub-covenant.
3. **Denial of service**: Rate limit RPC, validate all tx inputs, enforce gas limits.
4. **Reorg handling**: If BSV reorgs, overlay nodes detect and roll back
   to the last confirmed state, then re-execute.
5. **State consistency**: Crash recovery must not corrupt state. Use atomic writes / WAL.
6. **Multi-node consensus**: BSV is the consensus layer. Nodes don't need
   their own BFT — they execute deterministically and accept the BSV chain.
7. **MEV / front-running**: Node operators can observe pending transactions
   via the gossip layer. The node that wins the covenant advance race
   determines transaction ordering within the block, creating MEV
   opportunity. **This is a launch risk for DeFi shards.** Mitigation
   options for Milestone 10:
   - Commit-reveal for transaction ordering (nodes commit to a tx batch
     hash before revealing contents)
   - Encrypted mempool (threshold decryption among shard nodes)
   - Fair ordering protocol (transactions ordered by hash, not by node choice)
   For initial deployment on non-DeFi shards (identity, social), this risk
   is accepted. DeFi shards SHOULD NOT launch without at least commit-reveal.
8. **BSV unconfirmed chain limits**: The overlay relies on BSV's unlimited
   unconfirmed chain depth. Monitor for mempool evictions and propagation
   failures. See spec 11 "BSV Unconfirmed Chain Limits."

## Milestone 10 Also Includes

In addition to fuzzing and stress testing, Milestone 10 (Hardening)
must address:

- **State pruning**: Implement archival vs pruned node modes with MPT
  garbage collection. Without pruning, disk usage grows unboundedly.
  This is required for production operation.
- **Protocol upgrades**: The covenant migration mechanism enables upgrading
  the covenant script (e.g., for EVM hardfork support, bug fixes, or
  proving system improvements) without losing state.

  **Migration design**:

  The old covenant is spent one final time with a special `migrate` method.
  The `migrate` method:
  1. Requires a valid STARK proof for the current state (same as `advanceState`)
  2. Takes a `newCovenantScriptHash` parameter — the hash of the new
     covenant's locking script
  3. Verifies that output 0 uses the new locking script (not the old one)
  4. Carries forward the current state (stateRoot, blockNumber) into the
     new covenant UTXO
  5. The covenant script enforces: the state root and block number in
     output 0 match the current values (no state change during migration)

  ```go
  // Added to pkg/covenant/contracts/rollup.go
  c.Method("migrate", func(m *runar.MethodBuilder) {
      proof           := m.StarkProofParam("proof")
      newScriptHash   := m.Param("newScriptHash", runar.Bytes32)

      // Verify the prover knows the current state (prevents stale migrations)
      publicInput := m.SHA256(m.Cat(
          c.GetState("stateRoot"),
          c.GetState("stateRoot"),  // pre == post (no state change)
          c.GetState("blockNumber"),
      ))
      StarkVerifySubroutine(m, StarkVerifierParams{
          Proof: proof, PublicInput: publicInput, /* ... */
      })

      // Output 0 must use the NEW covenant script
      m.RequireOutputScriptHash(0, newScriptHash)

      // State is carried forward unchanged
      m.RequireOutputState(0, "stateRoot", c.GetState("stateRoot"))
      m.RequireOutputState(0, "blockNumber", c.GetState("blockNumber"))

      // Satoshis preserved
      m.RequireOutputValue(0, m.InputValue(0))
  })
  ```

  **Migration process**:
  1. New covenant script is compiled with Rúnar and published (ANF + Script)
  2. All shard nodes upgrade to software that understands the new script
  3. Any node can trigger migration by calling `migrate` with a valid proof
  4. After migration, the covenant UTXO chain continues from the new script
  5. Old nodes that haven't upgraded will fail to parse new covenant advances
     and must upgrade to continue participating

  **Safety properties**:
  - Migration requires a valid STARK proof — no one can migrate without
    proving knowledge of the current state
  - State is preserved exactly — the state root and block number are
    carried forward
  - The new script hash is committed in the migration transaction —
    observers can verify which script the covenant migrated to
  - Migration is a single atomic BSV transaction — it either succeeds
    completely or not at all

  **Governance**: Migration is permissionless (any valid proof triggers it).
  In practice, shard operators coordinate upgrades via the gossip network.
  A node that triggers an unwanted migration can be overridden by other
  nodes migrating back — though this is adversarial and unlikely in
  cooperative shards. For high-value shards, a governance contract on L2
  can gate migration by requiring a multisig or vote before the migrate
  proof is generated.
- **Coordinated proving**: Implement gossip-based proving coordination
  so nodes in a shard divide proving work instead of independently
  racing. Reduces wasted computation as shard node count grows.
- **MEV mitigation**: Implement commit-reveal for transaction ordering.
  Nodes commit to a transaction hash before revealing the transaction
  content, preventing front-running by competing nodes.
- **Shard discovery registry**: Deploy an on-chain BSV registry of
  active shards (chain ID, genesis covenant txid, bootstrap peers)
  so new users and nodes can discover available shards.
