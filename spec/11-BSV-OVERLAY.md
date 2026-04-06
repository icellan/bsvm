# Spec 11: Overlay Node & Shard Network

## Core Model

The L2 is an overlay network on BSV. Each shard is run by multiple nodes
that replicate state. Nodes share EVM transactions via peer-to-peer gossip.
All nodes execute the same transactions deterministically and arrive at the
same state root. Any node can produce the STARK proof and advance
the covenant on BSV. BSV is the consensus layer — the covenant UTXO chain
is the single source of truth.

There is no sequencer key. The STARK proof is the sole authorization
for covenant advances. Anyone with a valid proof can advance the state. If
a node goes offline, other nodes seamlessly continue.

## Multi-Node Model

The overlay node is one of potentially many nodes in a shard. All nodes:
- Receive EVM transactions (from RPC clients or peer gossip)
- Broadcast received txs to all other nodes in the shard
- Execute transactions deterministically (same order → same state)
- Can generate proofs and advance the covenant

Transaction ordering: BSV determines final order. Between BSV blocks,
the covenant UTXO chain itself determines ordering — whichever node
advances the covenant first defines the canonical order for those
transactions. This is the key insight: the UTXO chain is a
total-ordering mechanism.

### Ordering Protocol

Because different nodes may see transactions in different order (due to
network latency), nodes cannot independently compute the same state root.
Instead, nodes follow a **propose-and-accept** model:

1. **One node leads per-advance**: The first node to successfully broadcast
   a covenant-advance BSV tx is the de facto leader for that advance.
2. **Other nodes follow**: They detect the advance (via BSV mempool or
   peer gossip), extract the batch data, re-execute the transactions in
   the canonical order, verify the state root matches, and update their
   local state.
3. **Concurrent work is speculative**: A node processing transactions
   locally before advancing the covenant is speculating that it will win
   the race. If it loses, it discards its speculative state and replays
   the winner's batch.

This means at any given moment, nodes may be in one of two states:
- **Leading**: processing transactions and racing to advance the covenant
- **Following**: replaying another node's covenant advances

Under low contention (few nodes, sparse transactions), most advances
succeed on first attempt. Under high contention, nodes experience more
rollbacks. The **backoff strategy** for high contention:

1. After a lost race, add random jitter (50-200ms) before the next advance attempt
2. If a node loses N consecutive races, increase jitter exponentially (up to 2s)
3. Nodes can optionally enter "follower mode" — stop attempting advances
   and only replay — if they consistently lose races. They still serve RPC
   and gossip transactions.

### Timestamp Determinism

The L2 block timestamp is set by the proposing node (the node that
successfully advances the covenant). The timestamp is embedded in the
batch data (OP_RETURN) so that all other nodes use the exact same value
when replaying the batch.

Rules:
- The proposer sets `Timestamp = uint64(time.Now().Unix())` at execution time
- The timestamp is included in the batch encoding (see "Batch Data Encoding Format")
- Nodes replaying a winner's batch extract the timestamp from the batch data
  and use it verbatim — they do NOT use their own wall clock
- The timestamp must be >= the parent block's timestamp (monotonic)
- The timestamp must be <= the node's wall clock + 15 seconds (drift limit)
- These rules ensure the EVM's `TIMESTAMP` opcode returns identical values
  across all nodes for the same block

This is the same model used by Ethereum L2s (Optimism, Arbitrum) where
the sequencer/proposer sets the timestamp and all verifiers replay it.

### Timestamp Validation Rules

**During live execution (proposer)**:
- `timestamp = uint64(time.Now().Unix())`
- Must be >= parent block's timestamp (monotonic)
- Must be <= node's wall clock + 15 seconds (drift limit)

**During replay from BSV data (verifier/syncing node)**:
- Timestamp is extracted verbatim from batch data
- Must be >= parent block's timestamp (monotonic) — this is checked
- The wall-clock drift check is SKIPPED during replay — timestamps in confirmed batches are accepted as canonical
- This allows nodes to sync historical data without clock issues

**During winner replay (after losing a race)**:
- Same rules as replay from BSV data — timestamp from winner's batch data is accepted verbatim
- The local block header is overwritten with the winner's timestamp

### What Happens to Orphaned Transactions

When a node loses a race:
1. The winner's batch is replayed to determine the new canonical state
2. Transactions the loser had processed but the winner did NOT include are
   **re-queued** for inclusion in the next advance
3. Transactions that fail on re-execution (because state changed) are
   **dropped** with an error logged
4. Transactions that the winner included but the loser hadn't seen are
   applied as part of the replay

### Transaction Deduplication During Re-Queue

When a node loses a covenant race and replays the winner's batch:

1. Collect the winner's transaction set: `winnerTxs = decodeBatchData(winnerOpReturn)`
2. Collect the loser's transaction set: `loserTxs = localBlock.Transactions`
3. Compute orphaned transactions: `orphaned = loserTxs - winnerTxs` (set difference by tx hash)
4. For each orphaned transaction:
   a. Validate nonce against the new state (post-winner execution)
   b. Validate balance sufficiency against the new state
   c. If valid, re-queue to mempool
   d. If invalid (nonce consumed, insufficient balance), drop with log: `tx <hash> dropped: <reason>`
5. Transactions already in the winner's batch are NOT re-queued (they're already executed)

**Deduplication key**: Transaction hash (`keccak256(RLP(signedTx))`). A transaction with the same hash is never included twice in the canonical chain, regardless of which node produced the batch.

**Cross-batch dedup**: The overlay node maintains a `recentTxHashes` set (last 10,000 tx hashes). Transactions already in this set are rejected at mempool admission. The set is pruned when blocks are confirmed.

## Competitive Proving

### Economic Model

Nodes in a shard are economic competitors. Each node independently
gathers transactions, builds batches, generates proofs, and races to
advance the covenant. The winner earns the L2 coinbase fees. Losers'
proving work is wasted. There is no cooperative proving protocol
between competing nodes.

This is structurally identical to Bitcoin mining: redundant work is the
cost of permissionless participation. The barrier to entry is: run the
software, have access to proving hardware (GPU or proving pool), and
have some BSV for fees.

**Competitive axes**:

1. **Proving speed**: More/faster GPUs produce proofs sooner.
2. **Transaction flow**: The node serving more RPC clients sees more
   transactions first and can build more profitable batches.
3. **BSV propagation latency**: First valid covenant-advance tx to
   reach miners wins.

### Why Redundant Proving is Economically Sustainable

GPU proving cost per batch is ~1,500-5,500 sats (electricity +
amortised hardware). Gas revenue per winning batch is ~268,800 sats
(128 txs at 1 gwei). A node winning 1 in 5 races spends ~27,500 sats
on proving (5 attempts) and earns ~268,800 sats — still a 10x margin.
Proving cost is less than 2% of batch revenue. Nodes can waste 80-90%
of proofs and remain profitable.

The number of active provers self-regulates: new provers enter when
margins are attractive, marginal provers exit to follower mode
(RPC-only, no proving) when margins thin. No coordination needed.

### Competing Nodes Build Different Batches

Competing nodes are NOT proving the same computation. Each node builds
its own batch from its own view of pending transactions. Network
latency means nodes see transactions in different orders and may have
different subsets. They prove different batches with different state
roots. The winner's batch becomes canonical.

When a node loses a race, it detects the competing covenant-advance tx,
discards its own unbroadcast proof, replays the winner's batch from the
OP_RETURN data, and continues from the winner's state. Orphaned
transactions that are still valid against the new state are re-queued
for the next batch. Transactions that are now invalid (nonce conflict,
insufficient balance) are dropped.

A node that consistently loses can switch to **follower mode**: serve
RPC, gossip transactions, but don't prove. This is a valid operating
mode that still contributes to shard liveness and decentralisation.

### Proving Pools

A node does NOT need to own GPUs. SP1 proving is divisible — the
RISC-V trace is broken into ~30 independent shards. The node keeps
transaction selection, batch composition, fee revenue, and final proof
assembly. It outsources individual shard proofs to a pool of GPU
workers:

```
Node (operator):
  - Gathers txs, builds batch, executes EVM, splits trace into shards
  - Sends shard proving jobs to pool workers
  - Receives shard proofs, combines into final proof
  - Broadcasts covenant-advance, earns coinbase fees

Pool workers (GPU operators):
  - Receive individual shard trace segments
  - Prove them, return shard proofs
  - Paid per shard proof (regardless of whether the node wins the race)
  - Can serve multiple competing nodes simultaneously
```

The worker sees a trace segment, not the full batch. It does not know
the transaction contents, the ordering, or which node it is helping. It
just does the math.

This dramatically lowers the barrier to running a prover node. You
need: a CPU server for EVM execution, BSV for fees, and a proving pool
account. No GPU hardware. The SP1 Prover Network (run by Succinct Labs)
is an existing production implementation of this model.

**Deployment options**:

1. **Self-hosted GPUs**: Full control, fixed cost. Proving time scales
   with GPU count.
2. **SP1 Prover Network**: Pay-per-proof, elastic, no hardware.
   Suitable for variable load.
3. **Custom proving pool**: Shard community runs their own pool of GPU
   workers.
4. **Hybrid**: Self-hosted for baseline, pool for spikes.

### Single-Node Internal Pipelining

A competitive node overlaps execution and proving without revealing
anything to competitors. While the GPU proves batch N, the CPU executes
incoming transactions and accumulates batch N+1. When batch N's proof
completes and is broadcast, batch N+1 is already executed and ready —
the GPU starts immediately with zero idle time.

```go
type PipelinedProver struct {
    gpu          *SP1Prover
    pendingBatch *PendingBatch  // Accumulating on CPU while GPU is busy
    provingBatch *ProvingBatch  // Currently being proved on GPU
    mu           sync.Mutex
}

func (p *PipelinedProver) OnTransactionReceived(tx *Transaction) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.pendingBatch.Add(tx)

    if p.pendingBatch.Size() >= p.adaptiveBatchSize() && p.provingBatch == nil {
        p.startProving() // GPU is idle, start immediately
    }
}

func (p *PipelinedProver) onProofComplete(proof *Proof) {
    p.mu.Lock()
    defer p.mu.Unlock()

    p.broadcastCovenantAdvance(p.provingBatch, proof)

    if p.pendingBatch.Size() > 0 {
        p.startProving() // Next batch ready, zero GPU idle time
    } else {
        p.provingBatch = nil
    }
}
```

This pipelining is invisible to other nodes and to BSV. It is purely a
local optimisation that maximises GPU utilisation for competitive advantage.

---

## Covenant Advance Racing

Multiple nodes may attempt to advance the covenant simultaneously:
- Node A generates a proof and broadcasts a covenant-advance BSV tx
- Node B also generates a proof and broadcasts a competing tx
- Only one can spend the covenant UTXO — BSV miners pick the winner
  (typically whichever propagated first)
- The losing node's tx is rejected (double-spend of the covenant UTXO)
- All nodes accept the winner's state root (which they can verify
  independently by re-executing the transactions)
- The losing node continues from the winner's new covenant tip

This is not a problem — it's the mechanism. No leader election needed.

## Execution Verification

All nodes in the shard independently verify every covenant advance by
re-executing the batch and comparing state roots. This is not optional —
it is the execution correctness guarantee (see spec 12, "Execution
Correctness").

```go
// pkg/overlay/verify.go

type ExecutionVerifier struct {
    overlay *OverlayNode
}

// VerifyCovenantAdvance re-executes the batch from a covenant-advance
// transaction and verifies the resulting state root matches.
func (v *ExecutionVerifier) VerifyCovenantAdvance(cached *CachedTx) error {
    statedb, err := state.New(cached.PreStateRoot, v.overlay.stateDB.Database())
    if err != nil {
        return err
    }
    for _, tx := range decodeBatch(cached.BatchData) {
        evm := vm.NewEVM(buildBlockContext(cached.L2Block.Header), statedb, ...)
        ApplyTransaction(evm, statedb, cached.L2Block.Header, tx)
    }
    computedRoot := statedb.IntermediateRoot(true)

    if computedRoot != cached.StateRoot {
        slog.Error("EXECUTION MISMATCH — covenant advance has incorrect state root",
            "block", cached.L2BlockNum,
            "expected", cached.StateRoot,
            "computed", computedRoot,
            "bsvTx", cached.BSVTxID,
        )
        return fmt.Errorf("execution mismatch at block %d: covenant=%s computed=%s",
            cached.L2BlockNum, cached.StateRoot, computedRoot)
    }
    return nil
}
```

After accepting any covenant advance (self-produced or from another
node), the overlay node MUST verify by re-executing the batch and
comparing state roots. This is cheap — EVM execution takes milliseconds
and the node was going to execute the transactions anyway.

## Shard Sync

A new node joining an existing shard:
1. Connect to bootstrap peers
2. Get the genesis covenant txid from shard config
3. Walk the BSV covenant UTXO chain from genesis:
   - For each covenant-advance tx, extract batch data from OP_RETURN
   - Re-execute the EVM transactions to build local state
   - Verify computed state roots match the covenant chain
4. Once caught up to the covenant tip, start participating normally

This is trustless sync — the new node verifies everything from BSV data.

### Sync Protocol Details

```go
// pkg/overlay/sync.go

func (n *OverlayNode) SyncFromBSV(genesisCovenantTxID Hash) error {
    currentTxID := genesisCovenantTxID
    syncedBlockNum := n.chainDB.ReadHeadHeader().Number.Uint64()

    for {
        // 1. Find the next covenant-advance tx that spends currentTxID
        nextTx, err := n.findNextCovenantAdvance(currentTxID)
        if err != nil {
            return fmt.Errorf("sync: failed to find next advance after %s: %w", currentTxID, err)
        }
        if nextTx == nil {
            // No more advances — we've reached the covenant tip
            break
        }

        // 2. Decode batch data from OP_RETURN
        batchData, err := decodeBatchData(nextTx.Outputs[1].Script)
        if err != nil {
            return fmt.Errorf("sync: malformed batch data at tx %s: %w", nextTx.TxID, err)
        }

        // 3. Re-execute the batch and verify state root
        statedb, _ := state.New(n.chainDB.ReadHeadHeader().StateRoot, n.db)
        result, err := n.executeBatch(statedb, batchData)
        if err != nil {
            return fmt.Errorf("sync: execution failed at block %d: %w", batchData.BlockNumber, err)
        }
        if result.StateRoot != batchData.PostStateRoot {
            return fmt.Errorf("sync: state root mismatch at block %d: computed=%s expected=%s",
                batchData.BlockNumber, result.StateRoot, batchData.PostStateRoot)
        }

        // 4. Commit state and write block
        statedb.Commit(true)
        n.chainDB.WriteBlock(result.L2Block)

        // 5. Checkpoint progress every 1000 blocks for resume
        if batchData.BlockNumber % 1000 == 0 {
            n.chainDB.WriteSyncCheckpoint(batchData.BlockNumber, nextTx.TxID)
            slog.Info("sync progress", "block", batchData.BlockNumber)
        }

        currentTxID = nextTx.TxID
    }

    slog.Info("sync complete", "tip", n.chainDB.ReadHeadHeader().Number)
    return nil
}

// findNextCovenantAdvance finds the BSV transaction that spends
// output 0 of the given txid. Uses BSVClient.GetSpendingTx() or
// walks the BSV blockchain if the BSV node supports utxo spend indexing.
func (n *OverlayNode) findNextCovenantAdvance(txid Hash) (*bsv.Transaction, error)
```

**Caught-up detection**: The node is "caught up" when no BSV transaction
spends the latest known covenant UTXO. The node then transitions from
sync mode to live mode (accepting transactions, participating in gossip).

**Resume from checkpoint**: If sync is interrupted (crash, restart), the
node reads the last `SyncCheckpoint` from the database and resumes from
that point instead of replaying from genesis.

**Snapshot-based fast sync (optional)**: For long chains, a new node can
download a state snapshot from a peer (see Spec 02, State Snapshots),
verify the snapshot root against the covenant chain, and resume sync
from the snapshot height. This avoids replaying the entire history.
Snapshot sync is optional — full replay from genesis is always available
as the trustless fallback.

---

## Why This Works on BSV

BSV allows arbitrarily long chains of unconfirmed transactions. Transaction A
creates an output, transaction B spends that output, transaction C spends B's
output, and so on — all before any of them are mined into a block. When a
miner builds a block, it includes the entire chain.

BTC limits unconfirmed chains to ~25 transactions. BSV has no such limit.
This means the covenant UTXO can advance hundreds or thousands of times
between BSV blocks. Each advance is a BSV transaction. They all get mined
in the next block (or across a few blocks).

This is how BSV was designed to work. The L2 overlay is simply using BSV
as intended.

---

## Transaction Flow

```
User (wallet / dApp / RPC client)
    │
    │  eth_sendRawTransaction (signed EVM tx, standard RLP)
    │
    ▼
L2 Overlay Node
    │
    │  1. Receive EVM transaction
    │  2. Validate (signature, nonce, gas, balance)
    │  3. Execute through EVM engine
    │  4. Get new state root + receipt
    │  5. Build BSV covenant-advance transaction:
    │       Input 0:  previous covenant UTXO (proof-authorized)
    │       Input 1:  prover's fee-funding UTXO (signed by prover)
    │       Output 0: new covenant UTXO (new state root, fixed sats)
    │       Output 1: OP_RETURN (batch data)
    │       Output 2: prover's fee change
    │  6. Sign the fee-funding input (input 1); covenant input
    │     is authorized by the STARK proof, not a signature
    │  7. Broadcast BSV tx to BSV network
    │  8. Update local cache: the output we just created is now
    │     the current covenant UTXO
    │  9. Return receipt to user IMMEDIATELY
    │
    │  Ready for next transaction. No waiting.
    │
    ▼
BSV Network
    │
    │  Transactions propagate to miners
    │  Eventually mined into blocks
    │  The overlay monitors for confirmations and double-spend alerts
    │
    ▼
Permanent Record
```

---

## The Local Transaction Cache

The overlay node maintains a cache of BSV transactions it has broadcast but
that are not yet confirmed in a BSV block. This is the critical data
structure.

```go
// pkg/overlay/cache.go

// TxCache tracks the chain of BSV transactions the overlay has broadcast.
// It is the source of truth for the current state until BSV confirms them.
type TxCache struct {
    mu sync.RWMutex

    // The chain of unconfirmed covenant-advancing transactions.
    // Ordered: index 0 is the oldest unconfirmed, last is the most recent.
    // Each entry spends the output of the previous entry.
    chain []*CachedTx

    // The last BSV-confirmed covenant UTXO.
    // If the chain is empty, this IS the current covenant UTXO.
    // If the chain is non-empty, the tip of the chain is the current UTXO.
    confirmedTip ConfirmedState

    // Quick lookup
    byBSVTxID map[Hash]*CachedTx
    byL2Block map[uint64]*CachedTx
}

type CachedTx struct {
    BSVTx       *bsv.Transaction  // The full BSV transaction
    BSVTxID     Hash              // Its txid
    L2Block     *L2Block          // The L2 block it commits
    StateRoot   Hash              // Post-execution state root
    L2BlockNum  uint64
    BroadcastAt time.Time
    Confirmed   bool              // Set to true when mined
    BSVBlockHeight uint64         // Set when confirmed
}

type ConfirmedState struct {
    BSVTxID    Hash
    Vout       uint32
    Satoshis   uint64
    StateRoot  Hash
    L2BlockNum uint64
    BSVBlock   uint64
}

// Tip returns the current covenant UTXO to spend — either the tip of
// the unconfirmed chain, or the last confirmed UTXO.
func (c *TxCache) Tip() (txid Hash, vout uint32, sats uint64) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    if len(c.chain) > 0 {
        tip := c.chain[len(c.chain)-1]
        return tip.BSVTxID, 0, tip.BSVTx.Outputs[0].Satoshis
    }
    return c.confirmedTip.BSVTxID, c.confirmedTip.Vout, c.confirmedTip.Satoshis
}

// Append adds a newly broadcast transaction to the chain.
func (c *TxCache) Append(ctx *CachedTx) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.chain = append(c.chain, ctx)
    c.byBSVTxID[ctx.BSVTxID] = ctx
    c.byL2Block[ctx.L2BlockNum] = ctx
}

// Confirm marks transactions as mined. All transactions up to and
// including the given BSV txid are confirmed. They are removed from
// the unconfirmed chain and the confirmedTip advances.
func (c *TxCache) Confirm(bsvTxID Hash, bsvBlockHeight uint64) {
    c.mu.Lock()
    defer c.mu.Unlock()

    idx := -1
    for i, ctx := range c.chain {
        if ctx.BSVTxID == bsvTxID {
            idx = i
            break
        }
    }
    if idx < 0 {
        return // Not found — might already be confirmed
    }

    // Everything up to idx is now confirmed
    confirmed := c.chain[idx]
    c.confirmedTip = ConfirmedState{
        BSVTxID:    confirmed.BSVTxID,
        Vout:       0,
        Satoshis:   confirmed.BSVTx.Outputs[0].Satoshis,
        StateRoot:  confirmed.StateRoot,
        L2BlockNum: confirmed.L2BlockNum,
        BSVBlock:   bsvBlockHeight,
    }

    // Remove confirmed entries
    for i := 0; i <= idx; i++ {
        delete(c.byBSVTxID, c.chain[i].BSVTxID)
    }
    c.chain = c.chain[idx+1:]
}
```

### Confirmation Thresholds

| Term | BSV Confirmations | Meaning |
|------|-------------------|---------|
| **Unconfirmed** | 0 | Covenant tx broadcast but not in a BSV block |
| **Confirmed** | >= 1 | Covenant tx included in at least 1 BSV block |
| **Finalized** | >= 6 | Covenant tx has 6+ BSV block confirmations |

- `ConfirmedState` is updated when a covenant-advance tx receives its FIRST BSV confirmation (1 block)
- The RPC `safe` block tag maps to the **proven tip**: the latest L2 block with a completed SP1 proof broadcast to BSV (may have 0 BSV confirmations). "Safe" means "mathematically proven correct by STARK," not "BSV-confirmed." See Spec 05 for the authoritative block tag definitions.
- The RPC `finalized` block tag maps to the latest L2 block whose covenant tx is **finalized** (>= 6 BSV confirmations)
- Rollback from proven state requires the proof to be invalid (impossible if SP1 is sound) or a BSV reorg that orphans the broadcast tx. Rollback from finalized state requires a 6+ block BSV reorg (extremely rare)

**Default**: `ConfirmationsFinalized = 6` (configurable via `--bsv-finality-depth`)

---

## The Overlay Node (replaces Sequencer)

The sequencer concept is absorbed into the overlay node. It does everything:
receive, execute, build BSV tx, broadcast, serve RPC.

```go
// pkg/overlay/node.go

type OverlayNode struct {
    // EVM execution
    chainConfig  *vm.ChainConfig
    vmConfig     vm.Config
    stateDB      *state.StateDB
    chainDB      block.ChainDB

    // Covenant management
    covenantMgr  *covenant.CovenantManager
    txCache      *TxCache

    // BSV connectivity
    bsvClient    BSVClient

    // Proving
    prover       *prover.ParallelProver

    // Configuration
    config       OverlayConfig

    // Double-spend monitoring
    dsMonitor    *DoubleSpendMonitor

    // Governance state (detected from BSV covenant UTXO chain)
    governanceState GovernanceState // GovernanceActive or GovernanceFrozen

    // Execution/proving separation (see "Concurrency Model" below)
    mu            sync.Mutex       // Guards state mutations
    executionTip  Hash             // Latest state root after execution
    provenTip     Hash             // Latest state root with completed proof
    finalizedTip  uint64           // Latest L2 block with >= ConfirmationsFinalized BSV confirmations
    pendingProofs chan *ProvingJob  // Queue of blocks awaiting proof
}

type OverlayConfig struct {
    Coinbase             Address       // L2 address for coinbase fees (prover revenue)
    GasPriceGwei         uint64        // Minimum gas price in gwei (default: 1)
    BlockGasLimit        uint64        // Gas limit per L2 block (default: 30_000_000)
    ChainID              int64         // L2 chain ID

    // Adaptive batching — target 128 txs per batch for optimal economics.
    // STARK proof size grows logarithmically with batch size, so larger
    // batches amortise the fixed proof cost across more transactions.
    // At 128 txs, L1 cost per EVM tx drops to ~169 sats (~$0.00005).
    TargetBatchSize      int           // Target txs per batch (default: 128)
    MinBatchSize         int           // Don't prove fewer than this (default: 10)
    MaxBatchFlushDelay   time.Duration // Max wait for a full batch (default: 2s)
    // NOT a block production timer. Only fires when there are pending
    // transactions. If no transactions arrive, nothing happens.
    // Empty batches are never produced.
    MinProfitableBatchGas uint64       // Don't advance covenant unless batch gas
                                       // exceeds this (anti-loss, default: 200_000)
}
```

**Coinbase address setup**: The operator generates an L2 keypair (standard secp256k1) before starting the node. The Ethereum-style address (last 20 bytes of `keccak256(pubkey)`) is set as `Coinbase` in the node config. This address receives gas fees via the EVM's standard coinbase mechanism. The keypair is the operator's L2 wallet — they can use it to bridge wBSV to BSV for fee wallet replenishment. The private key is NOT used by the node software (only the address is configured).

### Processing a Single EVM Transaction

```go
// pkg/overlay/process.go

func (n *OverlayNode) ProcessTransaction(evmTx *Transaction) (*Receipt, error) {
    // ---------------------------------------------------------------
    // PHASE 1: Execute (fast, holds lock briefly)
    // ---------------------------------------------------------------
    n.mu.Lock()

    parentHeader := n.chainDB.ReadHeadHeader()
    statedb, err := state.New(parentHeader.StateRoot, n.stateDB.Database())
    if err != nil {
        n.mu.Unlock()
        return nil, err
    }

    header := &L2Header{
        ParentHash:  parentHeader.Hash(),
        Coinbase:    n.config.Coinbase,
        Number:      new(big.Int).Add(parentHeader.Number, big.NewInt(1)),
        GasLimit:    n.config.BlockGasLimit,
        Timestamp:   uint64(time.Now().Unix()),
        BaseFee:     big.NewInt(0),
    }

    // Start cumulative access recording BEFORE execution.
    // This tracks every account and storage slot the EVM touches.
    statedb.StartAccessRecording()

    // Execute through EVM — SP1 does not need a Go-side execution trace;
    // the Rust revm guest re-executes the transactions independently.
    evm := vm.NewEVM(n.buildBlockContext(header), statedb, n.chainConfig, n.vmConfig)
    receipt, err := ApplyTransaction(evm, statedb, header, evmTx)
    if err != nil {
        statedb.StopAccessRecording() // discard recording
        n.mu.Unlock()
        return nil, err
    }

    // Stop recording and capture the access set
    accessRecording := statedb.StopAccessRecording()

    // Compute new state root + commit
    stateRoot := statedb.IntermediateRoot(true)
    header.StateRoot = stateRoot

    // Export state for SP1 proving. IMPORTANT: we need PRE-STATE Merkle
    // proofs (the guest verifies it starts from the correct state root).
    // The current statedb has dirty/committed post-state. We open a
    // fresh read-only statedb at the parent's state root to generate
    // the Merkle proofs against the pre-state trie.
    preStateDB, _ := state.New(parentHeader.StateRoot, n.stateDB.Database())
    stateExport, _ := prover.ExportStateForProving(
        preStateDB,                   // read-only, at pre-state root
        accessRecording.Accounts,     // accounts accessed during execution
        accessRecording.Slots,        // slots accessed during execution
    )

    statedb.Commit(true)

    l2Block := &L2Block{
        Header:       header,
        Transactions: []*Transaction{evmTx},
        Receipts:     []*Receipt{receipt},
    }
    n.chainDB.WriteBlock(l2Block)
    n.executionTip = stateRoot

    n.mu.Unlock()
    // Lock released — next transaction can begin executing immediately.

    // ---------------------------------------------------------------
    // PHASE 2: Prove + broadcast (slow, runs without lock)
    // ---------------------------------------------------------------
    // SP1 prover runs the revm guest program with the exported state
    // and transaction batch. It produces a STARK proof of correct
    // execution covering every EVM opcode.
    n.prover.Submit(&ProvingJob{
        L2Block:      l2Block,
        PreState:     parentHeader.StateRoot,
        StateExport:  stateExport,
        Transactions: encodeTxBatch([]*Transaction{evmTx}),
        BlockContext:  header.ToBlockContext(),
        Callback: func(output *prover.ProveOutput, err error) {
            if err != nil {
                slog.Error("SP1 proof generation failed", "block", header.Number, "err", err)
                return
            }

            // Verify the SP1 output matches the Go EVM output.
            // If they disagree, do NOT broadcast — the BSV covenant chain
            // is never corrupted because the mismatched proof never hits BSV.
            // Retry the proof. If disagreement persists, log for investigation.
            // The receipt already returned to the user was speculative (same
            // as any pre-confirmation receipt on an L2).
            if output.PostStateRoot != stateRoot {
                slog.Error("EVM DISAGREEMENT — Go EVM and SP1 revm produced different state roots",
                    "block", header.Number,
                    "goRoot", stateRoot,
                    "sp1Root", output.PostStateRoot,
                )
                // Do not broadcast. Re-queue for proving retry.
                // In a multi-node shard, another node will likely advance
                // the covenant with its own batch. This node will then
                // replay the winner's batch (see ReplayFromWinner).
                n.prover.Retry(job)
                return
            }

            // ### EVM Disagreement Circuit Breaker
            //
            // If Go EVM and SP1 revm produce different state roots:
            //
            // 1. **First attempt**: Re-export state, re-prove. Log warning.
            // 2. **Second attempt**: Re-execute batch from scratch against
            //    parent state root, re-export, re-prove. Log error.
            // 3. **Third attempt**: Halt proving for this block. Enter
            //    **diagnostic mode**:
            //    - Node continues serving RPC reads from the last proven state
            //    - Node continues gossipping transactions
            //    - Node does NOT produce new blocks or advance the covenant
            //    - Node logs: `CRITICAL: persistent EVM disagreement at
            //      block N — manual investigation required`
            //    - Node exposes diagnostic data via
            //      `debug_evmDisagreement` RPC method
            // 4. **Operator intervention**: The operator must investigate
            //    (likely a revm or Go EVM bug), update software, and restart
            //    the node with `--resume-from-proven-tip`
            //
            // **Max retries before circuit breaker**: 3 (configurable via
            // `--max-proving-retries`)
            //
            // Other nodes in the shard are unaffected — they produce their
            // own proofs. The shard only stalls if ALL nodes hit the same
            // disagreement (indicating a systemic bug).

            bsvTx, err := n.buildCovenantAdvanceTx(l2Block, output.Proof)
            if err != nil {
                slog.Error("covenant tx build failed", "err", err)
                return
            }

            bsvTxID, err := n.bsvClient.Broadcast(bsvTx)
            if err != nil {
                slog.Error("BSV broadcast failed", "err", err)
                return
            }

            n.txCache.Append(&CachedTx{
                BSVTx:      bsvTx,
                BSVTxID:    bsvTxID,
                L2Block:    l2Block,
                StateRoot:  stateRoot,
                L2BlockNum: header.Number.Uint64(),
                BroadcastAt: time.Now(),
            })
            n.provenTip = stateRoot
        },
    })

    // Return receipt immediately — proving happens in background
    return receipt, nil
}

### ProcessTransaction vs ProcessBatch — Execution Flow

**The Batcher is the primary entry point.** All transactions — whether
received via RPC (`eth_sendRawTransaction`) or peer gossip — are added
to the Batcher's pending list. The Batcher flushes to `ProcessBatch`
when either the target batch size (128 txs) is reached or the flush
timer expires (2s).

`ProcessTransaction` is a convenience wrapper equivalent to
`ProcessBatch([singleTx])`. It exists for the case where the Batcher
flushes with exactly one pending transaction (low-throughput periods).
**No transaction bypasses the Batcher to call ProcessTransaction
directly.**

The actual RPC flow is:
1. `eth_sendRawTransaction` → validate tx → `Batcher.Add(tx)` → return tx hash immediately
2. Batcher accumulates txs, starts flush timer on first pending tx
3. Batcher flushes → `ProcessBatch(txs)` → creates one L2 block → queues proof → returns receipts
4. Receipts are stored in ChainDB, available via `eth_getTransactionReceipt`

Both functions follow the same pattern: execute via Go EVM → export
state from pre-state snapshot → queue SP1 proving → broadcast covenant
advance. The only difference is the number of transactions per L2 block.

func (n *OverlayNode) buildCovenantAdvanceTx(l2Block *L2Block, proof *Proof) (*bsv.Transaction, error) {
    // Delegates to CovenantManager.AdvanceState which handles:
    // - Covenant input (proof-authorized, no signature)
    // - Fee-funding input (signed by prover's BSV wallet)
    // - Covenant output (new state, fixed sats)
    // - OP_RETURN output (batch data)
    // - Prover's fee change output
    // See spec 10, CovenantManager.AdvanceState for full details.

    newState := covenant.CovenantState{
        StateRoot:     l2Block.Header.StateRoot,
        BlockNumber:   l2Block.Header.Number.Uint64(),
    }

    return n.covenantMgr.AdvanceState(newState, n.encodeBatch(l2Block), proof)
}
```

---

## Speculative Execution and Cascade Rollback

The overlay node executes blocks speculatively — receipts are returned to
users before the SP1 proof is generated. Multiple blocks may execute and
accumulate on top of each other while earlier blocks are still being proved.
This creates a "speculative chain" of unproven blocks.

### The Problem

If block N fails proving (Go EVM and SP1 revm disagree), blocks N+1
through N+K that built on top of block N's state are also invalid.
Their pre-state roots reference block N's (incorrect) post-state, and
their receipts were computed against speculative state.

### Cascade Rollback Protocol

When a proving failure occurs at block N:

1. **Pause execution**: Stop accepting new transactions via the Batcher.
   Set a `provingFailure` flag that prevents `ProcessBatch` from running.

2. **Cancel pending proofs**: Cancel all proving jobs for blocks N+1
   through N+K (the speculative chain). Their proofs would be useless
   since their pre-state is invalidated.

3. **Rollback state**: Reload the StateDB from block N-1's state root
   (the last successfully proven state, or the last confirmed state).

4. **Re-execute**: Collect all transactions from blocks N through N+K.
   Re-execute them against the correct state (block N-1). Transactions
   that fail on re-execution (because state diverged) are dropped.

5. **Re-queue for proving**: The re-executed blocks enter the proving
   pipeline from scratch.

6. **Invalidate receipts**: Mark receipts for blocks N through N+K as
   superseded. If a user queries `eth_getTransactionReceipt` for a tx
   from the speculative chain, return the updated receipt (which may
   have a different status, gas used, or logs).

7. **Resume execution**: Clear the `provingFailure` flag. The Batcher
   resumes accepting transactions.

### Speculative Depth Limit

To bound the blast radius of cascade rollbacks:

```go
type SpeculativeConfig struct {
    MaxSpeculativeDepth int           // Default: 16
    // If more than MaxSpeculativeDepth unproven blocks accumulate,
    // the Batcher pauses until proving catches up. This limits the
    // number of blocks that must be re-executed on a cascade rollback.
    //
    // At 128 txs/block and ~5s proving time, 16 blocks = ~2,048 txs
    // and ~80s of speculative execution. This is a reasonable bound.
    PauseOnProvingBacklog bool        // Default: true
}
```

When `MaxSpeculativeDepth` is reached, the Batcher stops flushing until
the oldest unproven block completes proving. This applies backpressure
from the proving pipeline to the execution pipeline.

**Backpressure behavior when limit reached**:
1. The batcher stops flushing new batches (transactions accumulate in the mempool)
2. `eth_sendRawTransaction` continues accepting transactions (mempool is independent of batch depth)
3. Mempool size is capped at `MaxMempoolSize` (default: 4096 transactions). Beyond this, lowest-gas-price transactions are evicted.
4. When the oldest unproven block completes proving, the batcher resumes and flushes the next batch immediately.
5. If proving is stalled for > 180 seconds, the node enters follower-only mode (stops proposing, waits for another node to advance).

### Multi-Node Interaction

In a multi-node shard, cascade rollback is less likely because:
- If one node's proof fails, another node may have already advanced
  the covenant with a valid proof for the same (or different) batch
- The losing node detects the advance via the double-spend monitor
  and replays the winner's batch (see `ReplayFromWinner`)
- The cascade rollback only fires if the node's OWN proof fails AND
  no other node has advanced past the failing block

### Interaction Between Proof Merging and Cascade Rollback

If a head-of-line timeout triggers a proof merge (blocks N and N+1 merged into one proof), and then block N-1's proof fails:

1. The merged proof for N->N+1 is invalidated (it depends on N-1's post-state as pre-state)
2. Cancel the merged proving job
3. Rollback blocks N-1 through N+1
4. Re-execute all transactions from blocks N-1, N, N+1 against the last confirmed state
5. Re-prove the re-executed blocks (starting from N-1)

Proof merging does NOT create special rollback complexity — merged proofs are treated as a single block advance for rollback purposes. The covenant only sees the final state root, not intermediate ones.

---

## BSV Transaction Chain Visualised

```
BSV Block N:
  Confirmed covenant state: stateRoot_100, L2 block 100

Between BSV blocks (seconds apart, chained unconfirmed):

  tx_101: input=tx_100:0 → output_0=covenant(stateRoot_101) + output_1=OP_RETURN(batch_101)
  tx_102: input=tx_101:0 → output_0=covenant(stateRoot_102) + output_1=OP_RETURN(batch_102)
  tx_103: input=tx_102:0 → output_0=covenant(stateRoot_103) + output_1=OP_RETURN(batch_103)
  tx_104: input=tx_103:0 → output_0=covenant(stateRoot_104) + output_1=OP_RETURN(batch_104)
  ... (hundreds more) ...
  tx_250: input=tx_249:0 → output_0=covenant(stateRoot_250) + output_1=OP_RETURN(batch_250)

BSV Block N+1:
  Miner includes tx_101 through tx_250 (all 150 transactions).
  Confirmed covenant state: stateRoot_250, L2 block 250

Between BSV blocks:
  tx_251: input=tx_250:0 → ...
  tx_252: input=tx_251:0 → ...
  ...
```

Each tx is ~300-500 bytes for a single-tx L2 block (covenant overhead +
compact batch data). BSV handles this trivially. 150 transactions in a
block adds ~60KB — negligible for BSV's multi-GB blocks.

---

## Governance Freeze Detection

When the overlay node detects a governance freeze transaction on BSV
(broadcast by the governance key holder or another node), it transitions
to frozen mode:

```go
// pkg/overlay/governance.go

type GovernanceState int
const (
    GovernanceActive GovernanceState = iota
    GovernanceFrozen
)

func (n *OverlayNode) HandleGovernanceFreeze() {
    n.mu.Lock()
    defer n.mu.Unlock()

    n.governanceState = GovernanceFrozen

    // 1. Stop accepting new EVM transactions via RPC.
    //    eth_sendRawTransaction returns error: "shard is frozen by governance"
    n.batcher.Pause()

    // 2. Stop attempting covenant advances.
    //    Proving jobs are cancelled. No new BSV txs are broadcast.
    n.prover.PauseAll()

    // 3. Continue serving read-only RPC:
    //    eth_call, eth_getBalance, eth_getLogs, eth_getTransactionReceipt,
    //    eth_blockNumber, bsv_shardInfo (with frozen=true), etc.

    slog.Warn("SHARD FROZEN by governance — read-only mode",
        "block", n.chainDB.ReadHeadHeader().Number,
    )
}

func (n *OverlayNode) HandleGovernanceUnfreeze() {
    n.mu.Lock()
    defer n.mu.Unlock()

    n.governanceState = GovernanceActive

    // Resume normal operation
    n.batcher.Resume()
    n.prover.ResumeAll()

    slog.Info("SHARD UNFROZEN by governance — resuming normal operation",
        "block", n.chainDB.ReadHeadHeader().Number,
    )
}

func (n *OverlayNode) HandleGovernanceUpgrade(newScriptHash Hash) {
    n.mu.Lock()
    defer n.mu.Unlock()

    // The covenant script has changed. The node must:
    // 1. Update its local covenant reference to the new script
    // 2. Recompile the covenant (if the new ANF is available)
    // 3. Remain frozen until an unfreeze transaction is detected

    slog.Warn("COVENANT UPGRADED by governance — awaiting unfreeze",
        "newScriptHash", newScriptHash,
        "block", n.chainDB.ReadHeadHeader().Number,
    )
}
```

The governance state is detected by monitoring the covenant UTXO chain
on BSV (same mechanism as `DoubleSpendMonitor`). When the node observes
a covenant UTXO being spent by a `freeze`, `unfreeze`, or `upgrade`
method (identified by the unlocking script structure), it calls the
appropriate handler.

```go
// Added to DoubleSpendMonitor.processConfirmedBlock or a dedicated
// GovernanceMonitor that watches the covenant UTXO chain.

func (m *GovernanceMonitor) detectGovernanceTx(tx *bsv.Transaction) {
    // Parse the unlocking script to identify the covenant method:
    // - "freeze":   sets frozen=1 in the new UTXO state
    // - "unfreeze": sets frozen=0 in the new UTXO state
    // - "upgrade":  output 0 has a different locking script
    //
    // The simplest detection: read the frozen byte from the new
    // covenant UTXO's state data. If it changed, a governance
    // action occurred.
    newState := parseCovenantState(tx.Outputs[0])
    if newState.Frozen && !m.currentState.Frozen {
        m.overlay.HandleGovernanceFreeze()
    } else if !newState.Frozen && m.currentState.Frozen {
        m.overlay.HandleGovernanceUnfreeze()
    }

    // Check for script change (upgrade)
    if tx.Outputs[0].LockingScript != m.currentScript {
        m.overlay.HandleGovernanceUpgrade(hash256(tx.Outputs[0].LockingScript))
        m.currentScript = tx.Outputs[0].LockingScript
    }

    m.currentState = newState
}
```

---

## Double-Spend Monitoring

The only risk to the overlay is a BSV chain reorganisation that invalidates
one of the unconfirmed covenant transactions. This would break the chain:
if tx_105 is invalidated, tx_106 through tx_250 all become invalid because
they spend outputs that no longer exist.

### How to detect it

```go
// pkg/overlay/dsmonitor.go

type DoubleSpendMonitor struct {
    bsvClient  BSVClient
    txCache    *TxCache
    overlay    *OverlayNode
}

func (m *DoubleSpendMonitor) Run(ctx context.Context) error {
    // Subscribe to BSV block notifications and double-spend alerts.
    // BSV nodes (via MAPI/ARC) can notify when a double-spend is detected.

    blockCh, _ := m.bsvClient.SubscribeBlocks(ctx)
    dsCh, _ := m.bsvClient.SubscribeDoubleSpendAlerts(ctx)

    for {
        select {
        case <-ctx.Done():
            return nil

        case block := <-blockCh:
            m.processConfirmedBlock(block)

        case alert := <-dsCh:
            m.handleDoubleSpend(alert)
        }
    }
}

func (m *DoubleSpendMonitor) processConfirmedBlock(block *BSVBlock) {
    // Find our covenant transactions in this block
    for _, tx := range block.Transactions {
        m.txCache.Confirm(tx.ID, block.Height)
    }

    // Update finalized tip: scan all confirmed covenant txs and find
    // the latest L2 block with >= ConfirmationsFinalized BSV confirmations.
    m.overlay.updateFinalizedTip(block.Height)
}

func (n *OverlayNode) updateFinalizedTip(currentBSVHeight uint64) {
    // Walk confirmed covenant txs from the TxCache. Any L2 block whose
    // covenant-advance BSV tx has >= ConfirmationsFinalized confirmations
    // is considered finalized. The finalized tip is the highest such block.
    n.txCache.mu.RLock()
    defer n.txCache.mu.RUnlock()

    for _, ctx := range n.txCache.confirmed {
        confirmations := currentBSVHeight - ctx.BSVBlockHeight + 1
        if confirmations >= ConfirmationsFinalized && ctx.L2BlockNum > n.finalizedTip {
            n.finalizedTip = ctx.L2BlockNum
        }
    }
}

// FinalizedTip returns the latest L2 block number with >= 6 BSV confirmations.
func (n *OverlayNode) FinalizedTip() uint64 { return n.finalizedTip }

// ChainTips returns a snapshot of all three tip values for RPC and metrics.
type ChainTips struct {
    ExecutionTip  uint64 // Latest executed L2 block
    ProvenTip     uint64 // Latest proved + broadcast L2 block
    FinalizedTip  uint64 // Latest L2 block with >= 6 BSV confirmations
}

func (n *OverlayNode) GetChainTips() ChainTips {
    n.mu.Lock()
    defer n.mu.Unlock()
    return ChainTips{
        ExecutionTip:  n.executionTip.BlockNum,
        ProvenTip:     n.provenTip.BlockNum,
        FinalizedTip:  n.finalizedTip,
    }
}

func (m *DoubleSpendMonitor) handleDoubleSpend(alert *DoubleSpendAlert) {
    // A covenant-advance transaction was double-spent. In a multi-node
    // shard, this is EXPECTED when another node wins the advance race.
    // It can also happen if:
    //
    // 1. Another node in the shard advanced the covenant first (normal racing)
    // 2. A BSV reorg orphaned a block containing a confirmed covenant tx
    //
    // In case 1: this is the standard race-loss path. The losing node
    // detects it, fetches the winning tx's batch data, replays it, and
    // continues from the winner's state.
    //
    // In case 2: deeper rollback is needed — see Rollback section.

    invalidTx := m.txCache.FindByBSVTxID(alert.TxID)
    if invalidTx == nil {
        return // Not our transaction
    }

    // Check if a competing covenant-advance tx exists (race loss)
    competitor := m.findCompetingCovenantTx(alert)
    if competitor != nil {
        slog.Info("lost covenant advance race — replaying winner",
            "ourTx", alert.TxID,
            "winnerTx", competitor.ID,
            "l2Block", invalidTx.L2BlockNum,
        )
        m.overlay.ReplayFromWinner(competitor, invalidTx.L2BlockNum)
        return
    }

    // No competing tx found — this is a BSV reorg or unexpected event
    slog.Error("DOUBLE SPEND DETECTED — initiating rollback",
        "invalidBSVTx", alert.TxID,
        "l2Block", invalidTx.L2BlockNum,
    )
    m.overlay.Rollback(invalidTx.L2BlockNum)
}
```

### Rollback and Recovery

```go
// pkg/overlay/rollback.go

func (n *OverlayNode) Rollback(toL2Block uint64) error {
    n.mu.Lock()
    defer n.mu.Unlock()

    // 1. Find the last confirmed state before the invalid point
    confirmedState := n.txCache.LastConfirmedBefore(toL2Block)

    // 2. Reload state from the confirmed state root
    statedb, err := state.New(confirmedState.StateRoot, n.stateDB.Database())
    if err != nil {
        return fmt.Errorf("failed to reload state: %w", err)
    }
    n.stateDB = statedb

    // 3. Collect all L2 blocks that need re-execution
    invalidBlocks := n.txCache.BlocksFrom(toL2Block)

    // 4. Clear the invalid cache entries
    n.txCache.TruncateFrom(toL2Block)

    // 5. Re-execute transactions directly (NOT via ProcessTransaction,
    //    which would attempt proving and BSV broadcast — causing deadlock
    //    since we hold the lock, and wasting work since we need to rebuild
    //    the entire chain before broadcasting any of it).
    blockNum := confirmedState.L2BlockNum
    for _, block := range invalidBlocks {
        blockNum++
        header := &L2Header{
            ParentHash: n.chainDB.ReadHeadHeader().Hash(),
            Coinbase:   n.config.Coinbase,
            Number:     new(big.Int).SetUint64(blockNum),
            GasLimit:   n.config.BlockGasLimit,
            Timestamp:  block.Header.Timestamp,
            BaseFee:    big.NewInt(0),
        }

        for _, tx := range block.Transactions {
            evm := vm.NewEVM(n.buildBlockContext(header), statedb, n.chainConfig, n.vmConfig)
            _, err := ApplyTransaction(evm, statedb, header, tx)
            if err != nil {
                slog.Error("transaction failed on re-execution",
                    "txHash", tx.Hash(),
                    "err", err,
                )
                // Transaction may fail on re-execution if state diverged.
                // This is expected — skip it and continue.
                continue
            }
        }

        stateRoot := statedb.IntermediateRoot(true)
        statedb.Commit(true)
        header.StateRoot = stateRoot

        l2Block := &L2Block{Header: header, Transactions: block.Transactions}
        n.chainDB.WriteBlock(l2Block)
    }

    n.executionTip = statedb.IntermediateRoot(true)

    // 6. Queue all re-executed blocks for proving + BSV broadcast.
    //    This happens after the lock is released, via the proving pipeline.
    go n.reproveAndBroadcast(confirmedState.L2BlockNum+1, blockNum)

    slog.Info("rollback complete",
        "rolledBackTo", confirmedState.L2BlockNum,
        "reExecuted", len(invalidBlocks),
    )

    return nil
}
```

**Atomicity guarantee**: Rollback uses a LevelDB `WriteBatch` that atomically:
1. Deletes block headers, bodies, and receipts for blocks N through N+K
2. Updates the `latestBlock` pointer to N-1
3. Updates the `confirmedState` pointer

If the node crashes mid-rollback, on restart the node detects the inconsistency (latestBlock pointer vs. actual headers) and re-executes the rollback. The pre-rollback state is recoverable from the confirmed state root, which is never deleted during rollback.

### RPC Availability During Rollback

During a rollback, the overlay node holds a write lock on state. RPC behavior:

- **Read methods** (`eth_getBalance`, `eth_call`, `eth_getTransactionReceipt`): Serve from a **read-only snapshot** of the last confirmed state. Queries targeting rolled-back blocks return `null` (block not found). No RPC call blocks for more than 5 seconds.
- **Write methods** (`eth_sendRawTransaction`): Transactions are buffered in the mempool. They are NOT executed until rollback completes and a new block is produced.
- **Status method** (`eth_syncing`): Returns `{syncing: true, rollbackInProgress: true, rollbackFromBlock: N+K, rollbackToBlock: N-1}` during rollback.

The read-only snapshot is created before the rollback begins (cheap — LevelDB snapshot). This prevents RPC hangs during long rollbacks.

```go
// ReplayFromWinner handles the common case of losing a covenant advance
// race to another node. It replays the winner's batch data.
func (n *OverlayNode) ReplayFromWinner(winnerTx *bsv.Transaction, fromBlock uint64) error {
    n.mu.Lock()
    defer n.mu.Unlock()

    // 1. Extract batch data from the winner's OP_RETURN output.
    //    This includes the winner's timestamp, which we use verbatim
    //    to ensure deterministic replay (see "Timestamp Determinism").
    batchData := extractBatchData(winnerTx)
    txs := decodeBatch(batchData)

    // 2. Truncate our cache from the contested block
    n.txCache.TruncateFrom(fromBlock)

    // 3. Reload state from before the contested block
    parentHeader := n.chainDB.ReadHeaderByNumber(fromBlock - 1)
    statedb, err := state.New(parentHeader.StateRoot, n.stateDB.Database())
    if err != nil {
        return err
    }

    // 4. Re-execute the winner's transactions in their order
    // (same as Rollback step 5, using the winner's tx list)
    // ...

    // 5. Accept the winner's covenant advance as our new tip
    n.txCache.AcceptExternal(winnerTx)

    return nil
}
```

### Double-Spend Scenarios

In a multi-node shard, the covenant UTXO can be spent by anyone with a
valid STARK proof. This means double-spends are **expected** as part
of the multi-node racing mechanism:

1. **Covenant advance race** (expected, normal): Two nodes independently
   process transactions and attempt to advance the covenant. Both produce
   valid proofs. Both broadcast BSV transactions spending the same covenant
   UTXO. BSV miners accept whichever propagated first. The loser's tx is
   rejected. This is the standard operating mode — see "Ordering Protocol"
   above. The DoubleSpendMonitor detects this and triggers `ReplayFromWinner`.

2. **BSV reorg**: A confirmed block is orphaned. The transactions in it return
   to the mempool and may or may not be re-mined. Deep reorgs on BSV are
   extremely rare. This triggers a full `Rollback`.

3. **Network partition**: A node broadcasts a tx but it doesn't propagate.
   The node broadcasts the next tx spending the first one's output.
   Miners see the second but not the first — the second is invalid without
   the first. BSV's transaction dependency resolution handles this: miners
   request the parent tx.

Scenario 1 is common and handled gracefully. Scenarios 2 and 3 are rare
edge cases.

### Distinguishing Race Loss from BSV Reorg

| Signal | Race Loss | BSV Reorg |
|--------|-----------|-----------|
| Our covenant tx | Rejected (input already spent) | Was confirmed, now orphaned |
| Competing tx | Spends same input, different output | Different block reorganization |
| Our BSV block confirmations | 0 (never confirmed) | Was >= 1, now reverted |
| Recovery action | Replay winner's batch | Rollback to last confirmed state |

**Detection logic**:
1. If our covenant tx was NEVER confirmed (0 confirmations) and a competing tx spending the same UTXO is confirmed -> **Race loss**. Call `ReplayFromWinner(competingTx)`.
2. If our covenant tx HAD >= 1 confirmation but the BSV block containing it was orphaned -> **BSV reorg**. Call `Rollback(lastConfirmedBlock)` and re-prove from the fork point.

---

## Gas Model

Standard Ethereum gas, priced in gwei, paid from L2 wBSV balance. Users
deposit BSV via the bridge, get wBSV on L2, and interact via MetaMask /
ethers.js / Hardhat exactly like Ethereum. They never know BSV exists
underneath. There is one fee model — no BSV-specific gas logic, no
alternative payment modes.

**Transaction ordering**: The node that produces a batch determines
the ordering of transactions within that batch. This is equivalent to
sequencer ordering on current L2s. For v1, this is accepted as a known
property. A future enhancement is threshold-encrypted mempools where
transactions are encrypted until after batch ordering is committed,
preventing content-based MEV. See also spec 09 Security Considerations
item 7 for DeFi shard requirements.

The overlay node sets a minimum gas price (configurable, default 1 gwei).
Users submit standard EVM transactions via `eth_sendRawTransaction`. Gas
fees are deducted from the sender's L2 balance and credited to the block's
coinbase address. This is identical to Ethereum.

---

## Prover Economics

The prover earns revenue on L2 and pays costs on L1:

**Revenue**: The prover sets their L2 address as the block's `Coinbase`.
The EVM's standard fee mechanism credits gas fees to the coinbase via
`StateTransition.execute()`. No custom logic — this is how Ethereum works.

**Cost**: The prover pays the BSV mining fee for the covenant-advance
transaction from their own BSV wallet. At 100 sats/KB and a target batch
of 128 transactions, the BSV transaction is ~216KB (the STARK proof is
~165KB and batch data is ~20KB). Cost per advance: **~21,600 sats**
(~$0.0065 at $30/BSV). Per EVM transaction: **~169 sats** (~$0.00005).

**Profitability** at 1 gwei gas price:

| Batch contents | Total gas | Revenue (sats) | BSV cost (sats) | Profit | Per-tx L1 cost |
|---|---|---|---|---|---|
| 10 simple transfers | 210,000 | 21,000 | 20,000 | +1,000 | 2,000 sats |
| 100 simple transfers | 2,100,000 | 210,000 | 21,600 | +188,400 | 216 sats |
| **128 simple transfers** | **2,688,000** | **268,800** | **21,600** | **+247,200** | **169 sats** |
| **128 ERC-20 transfers** | **8,320,000** | **832,000** | **21,600** | **+810,400** | **169 sats** |
| **128 Uniswap swaps** | **19,200,000** | **1,920,000** | **21,600** | **+1,898,400** | **169 sats** |

(1 gwei = 10^9 wei. 1 satoshi = 10^10 wei. So 1 gas at 1 gwei = 0.1 sats.)

At **0.1 gwei** (cheaper than any existing L2):

| Batch contents | Total gas | Revenue (sats) | BSV cost (sats) | Profit |
|---|---|---|---|---|
| 128 simple transfers | 2,688,000 | 26,880 | 21,600 | **+5,280** |
| 128 ERC-20 transfers | 8,320,000 | 83,200 | 21,600 | **+61,600** |
| 128 Uniswap swaps | 19,200,000 | 192,000 | 21,600 | **+170,400** |

Even at 0.1 gwei, a full 128-tx batch is profitable. Break-even
gas price for 128 simple transfers: **~0.08 gwei** — roughly 60×
cheaper than Ethereum mainnet.

The overlay node batches transactions and only advances the covenant when
the batch is full (128 txs) or the flush timeout expires (2s). The
`min_profitable_batch_gas` threshold prevents advancing the covenant at
a loss for tiny batches during quiet periods.

**Prover float**: The prover needs BSV to pay mining fees while wBSV
accumulates on L2. At ~21,600 sats per advance and say 10 advances per
hour (one every 6 minutes during moderate load), that's ~216,000
sats/hour = ~$0.065/hour. A float of 0.01 BSV (~$0.30) funds several
hours of operation. The prover periodically withdraws accumulated wBSV
via the bridge to replenish the BSV float.

### Multi-node competition

When multiple nodes race to prove:
- The winning node earns the L2 coinbase fees
- Losing nodes waste proving compute
- Over time, nodes can coordinate (via gossip) to take turns, reducing
  wasted work
- Nodes can specialise: some execute and gossip, others focus on proving

### Fee funding

Every prover node needs a BSV wallet to pay mining fees for covenant-advance
transactions. This wallet has no special authority — it only signs its own
fee-funding inputs. The covenant input is authorized by the STARK proof.
If the wallet runs dry, the node cannot advance the covenant but can still
serve RPC reads and gossip transactions.

### Fee Wallet Persistence

The fee wallet's UTXO set must survive node restarts. On crash, the
wallet state may be inconsistent (UTXO marked spent locally but the
spending BSV tx not yet confirmed).

```go
// pkg/covenant/fee_wallet_db.go

type FeeWalletDB struct {
    db db.Database
}

// Persist writes the current UTXO set to disk. Called after every
// successful covenant advance and after every UTXO consolidation.
func (w *FeeWalletDB) Persist(utxos []UTXO) error

// Load reads the UTXO set from disk on startup.
func (w *FeeWalletDB) Load() ([]UTXO, error)

// ReconcileOnStartup compares the persisted UTXO set against the
// BSV node's view. For each persisted UTXO:
//   - If the BSV node confirms it's unspent: keep
//   - If the BSV node confirms it's spent: remove
//   - If the BSV node doesn't know the tx: remove (tx was never broadcast)
// Then scan the fee wallet address for any new UTXOs received while
// the node was offline (e.g., bridge withdrawal replenishment).
func (w *FeeWalletDB) ReconcileOnStartup(bsvClient BSVClient, address string) ([]UTXO, error)
```

`ReconcileOnStartup` is called during `runNode()` before the overlay
node begins processing. The reconciliation is idempotent — running it
multiple times converges to the same UTXO set.

---

### BSV Connectivity Loss Handling

If the BSV node or ARC becomes unreachable, the overlay node degrades
gracefully:

```go
type BSVConnectivityState int
const (
    BSVConnected       BSVConnectivityState = iota
    BSVDegraded                                    // ARC down but node reachable, or vice versa
    BSVDisconnected                                // Both unreachable
)

type ConnectivityMonitor struct {
    bsvClient    BSVClient
    state        BSVConnectivityState
    lastContact  time.Time
    alertWebhook string
}
```

**Behavior during BSV disconnection**:

1. **Execution continues**: The overlay node continues accepting and
   executing EVM transactions locally. Receipts are returned to users.
   These blocks are speculative (unproven) — same as any pre-BSV-confirmation
   state.

2. **Proving continues**: STARK proofs are generated as normal. They
   are queued for broadcast when connectivity is restored.

3. **Covenant advances pause**: The node cannot broadcast covenant-advance
   transactions to BSV. Proven blocks accumulate in the local cache.

4. **Alert at 30 seconds**: If BSV is unreachable for >30 seconds, log
   a warning and fire the health monitoring webhook.

5. **Speculative depth limit**: If the speculative chain (unbroadcast
   blocks) exceeds `MaxSpeculativeDepth` (default: 16), the batcher
   pauses — no new blocks are produced until connectivity is restored
   or existing blocks are broadcast.

6. **Reconnection**: On reconnection, the node:
   a. Checks the BSV covenant tip (another node may have advanced)
   b. If behind: replays the winner's advances
   c. If still leading: broadcasts queued covenant-advance txs in order
   d. Resumes normal operation

7. **ARC fallback**: If ARC is down but the BSV node RPC is reachable,
   the node broadcasts directly via the BSV node's `sendrawtransaction`.
   If the BSV node is down but ARC is reachable, the node uses ARC for
   broadcasting and polls ARC for tx status. Both paths are functional
   for covenant advances.

```toml
[bsv]
# Connectivity monitoring
connectivity_check_interval = "5s"
disconnect_alert_threshold = "30s"
# Fallback: if primary fails, try secondary
node_url = "http://localhost:8332"
arc_url = "https://arc.taal.com"
fallback_to_arc = true  # Use ARC if node_url is unreachable
```

---

## Updated Sequencer / Overlay Package Structure

```
pkg/overlay/          ← replaces pkg/sequencer/ AND pkg/anchor/
├── node.go           # Main overlay node: receive → execute → build BSV tx → broadcast
├── process.go        # EVM transaction processing
├── cache.go          # Local BSV transaction cache (unconfirmed chain)
├── dsmonitor.go      # Double-spend and reorg monitoring
├── rollback.go       # State rollback and re-execution on chain break
├── gas.go            # Gas pricing and profitability thresholds
├── batch.go          # Batch multiple EVM txs per BSV tx
├── inbox.go          # Forced inclusion inbox scanner
├── verify.go         # Execution verification for covenant advances
├── sync.go           # Shard sync: replay covenant chain from BSV, checkpoint, resume
├── connectivity.go   # BSV connectivity monitoring and fallback
├── config.go         # Overlay configuration
└── governance.go     # Governance freeze/unfreeze detection and handling
```

---

## BSV Unconfirmed Chain Limits

The overlay relies on BSV's unlimited unconfirmed transaction chain depth.
Practical considerations that must be addressed:

1. **BSV node mempool size**: Individual BSV nodes may evict low-fee
   transactions under memory pressure. The covenant chain transactions
   should use sufficient fee rates to avoid eviction.

2. **Propagation reliability**: If a BSV node restarts, the unconfirmed
   chain must be re-propagated. The overlay node should monitor for missing
   ancestors and re-broadcast if needed.

3. **Maximum cache depth**: The overlay should set a configurable maximum
   unconfirmed chain depth (default: 1000 transactions). If the cache
   exceeds this depth without any BSV confirmations, the overlay pauses
   new advances and logs a warning. This prevents unbounded growth if BSV
   is experiencing issues.

4. **Confirmation monitoring**: The overlay tracks how many covenant txs
   are confirmed per BSV block. If confirmations stop arriving, it
   indicates a problem (mempool eviction, network partition, etc.).

```go
type CacheLimits struct {
    MaxUnconfirmedDepth int           // Default: 1000
    StaleThreshold      time.Duration // Alert if oldest unconfirmed > this (default: 30m)
}
```

### Scalability and Proof Aggregation (Future)

The current model creates one BSV transaction per L2 block. At high L2
throughput (e.g., 10 blocks/second), this generates 6,000 BSV transactions
per BSV block interval (~10 minutes). While BSV can handle this volume,
two future optimisations can reduce the L1 footprint:

1. **Proof aggregation**: Generate a single STARK proof covering multiple
   L2 blocks. Instead of proving blocks 101, 102, 103 separately, prove
   the composite transition 100→103 in one proof. This reduces the number
   of covenant advances (and BSV transactions) proportionally. The
   trade-off is increased proving time per aggregate proof and higher
   latency for BSV finality of individual blocks.

2. **Recursive STARKs**: Prove that "I have a valid proof for block 101
   AND a valid proof for block 102" in a single outer proof. This is
   more complex to implement but enables amortisation without re-proving
   the original transitions.

These are post-v1 optimisations. The initial design (one proof per block)
is correct and sufficient for moderate throughput.

## Inbox Scanning

The overlay node scans the forced inclusion inbox covenant chain for
pending transactions that must be included in the next batch.

```go
// pkg/overlay/inbox.go

type InboxScanner struct {
    bsvClient  BSVClient
    inboxTxID  Hash   // Current inbox covenant UTXO tip
}

// ScanInbox returns pending forced-inclusion transactions and the
// current inbox Merkle root for the covenant inclusion proof.
func (s *InboxScanner) ScanInbox() ([]*Transaction, Hash, error) {
    // Walk the inbox covenant chain from last known tip
    // Extract EVM txs from OP_RETURN outputs
    // Return them for inclusion in the next batch
}
```

The overlay node includes inbox transactions at the START of each batch
(before user-submitted transactions via RPC/gossip), ensuring they
execute first. This guarantees censorship resistance: even if all shard
nodes ignore a user's RPC submissions, the user can bypass them entirely
by submitting to the inbox covenant on BSV.

## Health Monitoring

Nodes gossip periodic heartbeats to track shard liveness. If the visible
node count drops below a configurable minimum, remaining nodes fire alerts.

```go
type HealthMonitor struct {
    minNodes          int           // Minimum healthy nodes before alert
    heartbeatInterval time.Duration // Default: 10s
    alertWebhook      string        // URL to POST alerts to
    peerCount         func() int   // From network manager
}

func (h *HealthMonitor) Run(ctx context.Context) error {
    ticker := time.NewTicker(h.heartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return nil
        case <-ticker.C:
            if h.peerCount() < h.minNodes {
                h.fireAlert("shard node count below minimum",
                    "peers", h.peerCount(), "min", h.minNodes)
            }
        }
    }
}
```

Config:

```toml
[health]
min_nodes = 3
heartbeat_interval = "10s"
alert_webhook = "https://your-monitoring.example.com/alert"
```

This is informational — the shard continues operating even with fewer
nodes than `min_nodes`. The alert is for operators to investigate.

### Metrics Endpoint

The node exposes a Prometheus-compatible metrics endpoint at
`/metrics` (default port: 9090, configurable via `[metrics]` section).

Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `bsvevm_execution_tip` | gauge | Latest executed L2 block number |
| `bsvevm_proven_tip` | gauge | Latest proven L2 block number |
| `bsvevm_finalized_tip` | gauge | Latest finalized L2 block number (≥6 BSV confirmations) |
| `bsvevm_proven_tip_lag` | gauge | `execution_tip - proven_tip` (blocks behind) |
| `bsvevm_bsv_fee_wallet_sats` | gauge | Fee wallet balance in satoshis |
| `bsvevm_bsv_connectivity` | gauge | 0=disconnected, 1=degraded, 2=connected |
| `bsvevm_peer_count` | gauge | Number of connected shard peers |
| `bsvevm_unconfirmed_depth` | gauge | Length of unconfirmed covenant tx cache |
| `bsvevm_proving_duration_seconds` | histogram | Time to generate a STARK proof |
| `bsvevm_evm_execution_seconds` | histogram | Time to execute a batch through the Go EVM |
| `bsvevm_gas_used_total` | counter | Cumulative gas used across all blocks |
| `bsvevm_txs_processed_total` | counter | Cumulative EVM transactions processed |
| `bsvevm_covenant_advances_total` | counter | Cumulative covenant advances broadcast |
| `bsvevm_race_losses_total` | counter | Times this node lost a covenant advance race |

### Proven Tip Lag Alert

If the proven tip falls behind the execution tip by more than
`MaxProvenLag` blocks (default: 32), the node fires an operator alert.
This indicates the prover is not keeping up — likely due to proving
failures, resource exhaustion, or BSV connectivity issues.

If `proven_tip_lag > MaxProvenLag * 2` (default: 64), the node enters
follower-only mode: it stops producing new blocks and waits for another
node to advance the covenant, or for the operator to investigate.

```toml
[health]
min_nodes = 3
heartbeat_interval = "10s"
alert_webhook = "https://your-monitoring.example.com/alert"
max_proven_lag = 32            # Alert when proven tip is this far behind execution tip
max_proven_lag_follower = 64   # Enter follower-only mode at this lag

[metrics]
enabled = true
addr = "0.0.0.0:9090"
```

---

## Crash Recovery Protocol

If a node crashes (power loss, OOM kill, panic), it may have committed
state locally but not yet broadcast the covenant advance to BSV. On
restart, the node must reconcile local state with the BSV covenant chain.

### Recovery Steps

```go
// Called during node startup in runNode(), after loading local state
func (n *OverlayNode) RecoverFromCrash() error {
    localHead := n.chainDB.ReadHeadHeader()
    covenantTip := n.fetchCovenantTipFromBSV()

    switch {
    case localHead.Number.Uint64() == covenantTip.BlockNumber:
        // Local state matches BSV — clean shutdown or proof was broadcast
        // before crash. Nothing to do.
        return nil

    case localHead.Number.Uint64() > covenantTip.BlockNumber:
        // Local state is AHEAD of BSV. The node executed blocks but
        // crashed before proving/broadcasting them.
        //
        // Resolution: roll back local state to the covenant tip and
        // re-execute the gap blocks. Transactions from the gap that
        // were gossiped to peers may have been included by another
        // node — check BSV for advances by other nodes first.
        slog.Warn("local state ahead of BSV covenant — recovering",
            "localHead", localHead.Number,
            "covenantTip", covenantTip.BlockNumber,
        )

        // Check if another node advanced past our local head
        bsvAdvances := n.scanCovenantChain(covenantTip.BlockNumber, localHead.Number.Uint64())
        if len(bsvAdvances) > 0 {
            // Another node advanced — replay their batches
            return n.replayBSVAdvances(bsvAdvances)
        }

        // No other node advanced. Roll back to covenant tip and
        // re-prove the gap blocks.
        return n.rollbackToCovenantTip(covenantTip)

    case localHead.Number.Uint64() < covenantTip.BlockNumber:
        // BSV is AHEAD of local state. Another node advanced while
        // this node was offline. Replay from BSV to catch up.
        return n.SyncFromBSV(n.config.GenesisCovenantTxID)
    }
    return nil
}
```

### Atomicity Requirements

To minimise recovery complexity:

1. **State commit and block write are atomic**: `StateDB.Commit()` and
   `ChainDB.WriteBlock()` must be in the same database batch. If one
   succeeds and the other fails, the database is inconsistent.

2. **WAL (Write-Ahead Log)**: The database backend (LevelDB/Pebble)
   provides crash-safe writes via its internal WAL. No additional WAL
   is needed at the application level.

3. **Covenant TxID is written AFTER broadcast confirmation**: The
   `WriteCovenantTxID` call happens only after the BSV client confirms
   the broadcast succeeded. If the node crashes between broadcast and
   write, recovery re-broadcasts (BSV handles duplicate broadcasts
   gracefully — the tx is already in the mempool).

---

## Batching

The overlay node targets **128 transactions per batch**. STARK proof size
grows logarithmically with batch size — a 128-tx proof is only ~10% larger
than a single-tx proof (~165KB vs ~150KB). The batch data for 128 txs is
~20KB zstd-compressed. The net effect: L1 cost per EVM transaction drops
from ~18,100 sats (1-tx batch) to ~169 sats (128-tx batch) — a 107×
reduction.

128 is chosen as the target because it balances three constraints:
- **Proving time**: ~5-10s (vs ~45-60s for 1024), keeping the proven tip
  close to the execution tip
- **Fill latency**: fills in ~1.3s at 100 tx/sec, keeping user-perceived
  finality tight
- **Economics**: 12× profit margin at 1 gwei, still profitable at 0.1 gwei
- **Power of 2**: cleaner for STARK trace length alignment

### Nonce Gap Handling

When a transaction arrives with nonce N+K where the account's current nonce is N:

- **K = 0**: Valid — execute immediately (or queue for next batch)
- **K = 1..16**: **Queued** — held in per-account pending queue, sorted by nonce. Released for execution when preceding nonces arrive or are confirmed. Queued transactions expire after `TxQueueTimeout` (default: 1 hour).
- **K > 16**: **Dropped** — rejected with error `nonce too high (gap > 16)`. The sender must re-submit with a lower nonce.

After a cascade rollback, accounts may have their nonce reset. Queued transactions are re-validated against the new state: those with consumed nonces are dropped; those with valid future nonces remain queued.

### Transaction Replacement (Gas Bumping)

When a transaction arrives with the same nonce as an existing pending
transaction from the same sender:

1. **Higher gas price**: If the new transaction's effective gas price
   is >= 110% of the existing transaction's gas price, the existing
   transaction is replaced. The 10% minimum bump prevents spam.
2. **Equal or lower gas price**: The new transaction is rejected with
   error `replacement transaction underpriced`.
3. **Already in a flushed batch**: If the original transaction has
   already been included in a batch (flushed by the Batcher), the
   replacement is rejected with `nonce already consumed`.

This matches Ethereum's transaction replacement semantics (EIP-2 style
minimum bump). The Batcher checks replacement eligibility before adding
to the pending list.

### Adaptive Batching

The batcher accumulates transactions and flushes based on whichever
condition triggers first:

```go
// pkg/overlay/batch.go

type Batcher struct {
    pending       []*Transaction
    targetBatch   int            // Target: 128
    minBatch      int            // Minimum: 10 (don't prove fewer)
    maxWait       time.Duration  // Max flush delay: 2s
    minGas        uint64         // Min batch gas for profitability
    timer         *time.Timer
    pendingGas    uint64         // Accumulated gas in pending txs
    overlay       *OverlayNode
}

func (b *Batcher) Add(tx *Transaction) {
    b.pending = append(b.pending, tx)
    b.pendingGas += tx.Gas()

    if len(b.pending) >= b.targetBatch {
        // Target batch size reached — flush immediately (optimal economics)
        b.Flush()
    } else if b.timer == nil {
        // Start the flush timer on first pending tx
        b.timer = time.AfterFunc(b.maxWait, func() {
            b.FlushIfProfitable()
        })
    }
}

func (b *Batcher) Flush() {
    if len(b.pending) == 0 {
        return
    }
    txs := b.pending
    b.pending = nil
    b.pendingGas = 0
    if b.timer != nil {
        b.timer.Stop()
        b.timer = nil
    }
    b.overlay.ProcessBatch(txs)
}

func (b *Batcher) FlushIfProfitable() {
    // Timer expired — flush if we have enough for profitability
    if len(b.pending) >= b.minBatch && b.pendingGas >= b.minGas {
        b.Flush()
    } else if len(b.pending) > 0 {
        // Not enough for profitability, but we have pending txs.
        // Reset timer for another wait cycle. Eventually the batch
        // will grow large enough, or the node operator can configure
        // a lower minGas threshold to accept smaller batches.
        b.timer = time.AfterFunc(b.maxWait, func() {
            // After two wait cycles, flush regardless to prevent
            // transactions from being stuck indefinitely.
            b.Flush()
        })
    }
}
```

### Batch economics by size

| Batch size | SP1 proof | Batch data (zstd) | Total BSV tx | Fee (100 sat/KB) | Per-tx L1 cost |
|---|---|---|---|---|---|
| 1 tx | ~150KB | ~0.2KB | ~181KB | 18,100 sats | 18,100 sats |
| 10 txs | ~155KB | ~1.5KB | ~187KB | 18,700 sats | 1,870 sats |
| **128 txs** | **~165KB** | **~20KB** | **~216KB** | **21,600 sats** | **169 sats** |
| 512 txs | ~185KB | ~75KB | ~291KB | 29,100 sats | 57 sats |
| 1,024 txs | ~200KB | ~150KB | ~381KB | 38,100 sats | 37 sats |

The proof grows logarithmically. The batch data grows linearly. At 128
txs, the proof is ~76% of the total transaction size. The dominant cost
is the proof itself, which barely changes between 1 tx and 128 txs.

### Throughput at different shard loads

| Shard load | Batch fill time | Batches per BSV block (10 min) | L2 txs per BSV block |
|---|---|---|---|
| 1 tx/sec | 2s (flush timeout) | ~300 | ~150 |
| 10 tx/sec | 2s (flush timeout) | ~300 | ~1,500 |
| 100 tx/sec | ~1.3s | ~460 | ~59,000 |
| 1,000 tx/sec | ~0.13s | ~4,600 | ~589,000 |

At high load (1000 tx/sec), the L2 processes ~589K transactions per BSV
block interval across ~4,600 covenant advances. Each covenant-advance tx
is ~216KB, totalling ~994MB per BSV block — within BSV's multi-GB capacity.

### Backpressure and Adaptive Batching

When transactions arrive faster than the prover can prove, the system
applies backpressure to prevent unbounded speculative execution.

**Backpressure mechanism**: The overlay node tracks two tips: the
execution tip (latest executed block) and the proven tip (latest block
with a completed STARK proof broadcast to BSV). The gap between them is
the speculative depth.

```go
type BackpressureConfig struct {
    MaxSpeculativeDepth int // Max blocks ahead of proven tip (default: 16)
    HighWaterMark       int // Start warning at this depth (default: 12)
    LowWaterMark        int // Resume accepting after drop to this depth (default: 8)
}
```

**Behaviour**:

1. **Speculative depth < HighWaterMark**: Normal operation. Accept all
   valid transactions. Batch size targets 128 txs.
2. **Speculative depth >= HighWaterMark**: Log warning. Accept
   transactions but increase batch size to amortise proving cost.
3. **Speculative depth >= MaxSpeculativeDepth**: Stop accepting new
   transactions. `eth_sendRawTransaction` returns error
   `{"code": -32005, "message": "shard at capacity, proving backlog"}`.
   Resume accepting when depth drops to LowWaterMark.

This prevents the node from making promises (receipts) that it cannot
back with proofs in a reasonable timeframe.

**Adaptive batch sizing**: When the pending transaction queue is growing
faster than proving can keep up, the batcher increases batch size to
improve throughput:

```go
func (b *Batcher) adaptiveBatchSize() int {
    speculativeDepth := b.overlay.ExecutionTip() - b.overlay.ProvenTip()

    if speculativeDepth > uint64(b.config.HighWaterMark) {
        // Under pressure: use larger batches for better throughput.
        // Larger batches have higher per-batch proving time but
        // lower per-tx proving time (proof size grows logarithmically).
        return min(1024, len(b.pending))
    }
    // Normal: use target batch size
    return min(b.targetBatch, len(b.pending))
}
```

Under normal load (speculative depth < 12), batches target 128 txs.
Under heavy load (depth 12-16), batches grow up to 1024 txs. A 1024-tx
batch takes ~3x longer to prove than a 128-tx batch but processes 8x
more transactions — a net 2.7x throughput improvement at the cost of
higher latency.

**What users experience under heavy load**:

| Load level | Behaviour |
|---|---|
| Normal (<13 tx/sec) | Instant receipts, proven within seconds |
| Elevated (13-50 tx/sec) | Instant receipts, larger batches, proven within 10-30s |
| High (50-100 tx/sec, single GPU) | Instant receipts until MaxSpeculativeDepth, then rejected. Operator should add GPUs. |
| Sustained high (with adequate GPUs) | Instant receipts, larger batches, sub-second proving, no rejections |

The system never produces incorrect state under load. It slows down or
rejects transactions, but it never advances the covenant with an
unproven batch. Liveness degrades gracefully; safety is never
compromised.

---

## Canonical Batch Data Encoding Format

The batch data in the OP_RETURN output encodes the L2 block so that
any observer can reconstruct the state from BSV data alone. This is
the data availability contract between the Go overlay node and the
Rust SP1 guest program — both MUST produce identical encodings for
the same block, or the batchDataHash will mismatch and the covenant
will reject the advance.

### Wire Format

The OP_RETURN output script contains:
```
OP_FALSE OP_RETURN OP_PUSHDATA <payload>
```

Where `<payload>` is the concatenation of a 5-byte envelope header
and the canonical batch encoding:

```
Envelope header (5 bytes, NOT included in batchDataHash):
  [4 bytes]  Protocol magic: "BSVM" (0x4253564D)
  [1 byte]   Message type: 0x02 (batch data)

Canonical batch encoding (this is what gets hashed):
  Offset  Size    Field               Encoding
  ──────  ──────  ──────────────────  ─────────────────────────────────────
  0       1       version             0x01 (fixed for v1)
  1       8       blockNumber         uint64, big-endian
  9       8       timestamp           uint64, big-endian (proposer's wall clock)
  17      32      parentHash          bytes32 (L2 parent block hash)
  49      20      coinbase            bytes20 (proposer's L2 fee recipient)
  69      8       depositHorizon      uint64, big-endian (BSV block height, see spec 07)
  77      32      prevrandao          bytes32 (see derivation below)
  109     32      preStateRoot        bytes32 (state root before execution)
  141     32      postStateRoot       bytes32 (state root after execution)
  173     32      withdrawalRoot      bytes32 (SHA256 Merkle root of withdrawal hashes,
                                       or bytes32(0) if no withdrawals in this batch)
  205     4       txCount             uint32, big-endian
  209     var     transactions        for each tx: [4 bytes txLen (uint32 BE)] [txLen bytes txRLP]
```

Total fixed header: 209 bytes. Variable part: 4 + txLen bytes per transaction.

### batchDataHash Computation

The STARK proof commits `batchDataHash = hash256(batchEncoding)` where:
- `hash256` = `SHA256(SHA256(data))` (Bitcoin's double-SHA256, `OP_HASH256`)
- `batchEncoding` = the canonical batch encoding bytes starting at
  offset 0 (`version`) through the end of the last transaction
  (i.e., everything AFTER the 5-byte envelope header)

The envelope header (`BSVM\x02`) is NOT included in the hash domain.
This matches the covenant's verification: the covenant receives
`batchData` (without the envelope header) as an unlocking script
parameter, computes `hash256(batchData)`, and compares against
`batchDataHash` from the proof's public values.

### Compression

**v1: No compression.** The canonical encoding is stored uncompressed
in the OP_RETURN. At 128 transactions (~150 bytes each), the batch
data is ~20KB — negligible on BSV. The `batchDataHash` is computed
over the uncompressed canonical encoding.

If compression is added in a future version (version byte > 0x01),
the hash MUST still be computed over the uncompressed encoding. The
compressed payload would be stored in the OP_RETURN with a different
version byte, and the covenant would decompress before hashing. This
ensures the hash domain is stable across compression changes.

### Intentional Redundancy

The pre-state root and post-state root appear in both the batch data
(OP_RETURN) and the STARK proof's public values (and the covenant
UTXO state). This is deliberate — the batch data is self-contained
for replay without proof verification. A syncing node can re-execute
from batch data alone and verify state roots match, without needing
to verify STARK proofs (BSV miners already validated those).

### PREVRANDAO Derivation

The `prevrandao` field is derived by the proposer:
`keccak256(BSVBlockHash || L2BlockNumber)` where `BSVBlockHash` is
the hash of the most recently confirmed BSV block at execution time.
This value is embedded in the batch so that nodes replaying from BSV
data use the identical value for the EVM's `PREVRANDAO` opcode.
Without this field, replaying nodes cannot deterministically reproduce
the block context.

### Transaction Encoding

Each transaction in the variable-length section is:
```
[4 bytes]  txLen: length of txRLP in bytes (uint32, big-endian)
[txLen]    txRLP: the EIP-2718 typed transaction envelope
```

Transaction types:
- `0x00` prefix or no prefix: Legacy transaction (RLP-encoded LegacyTx)
- `0x01` prefix: EIP-2930 AccessListTx
- `0x02` prefix: EIP-1559 DynamicFeeTx
- `0x7E` prefix: Deposit system transaction (see spec 07)

Transactions appear in execution order. Deposit system transactions
(type 0x7E) MUST appear before user transactions in the batch.

### Batch Data Hash Binding

The SP1 guest program commits `batchDataHash` as a public output at
offset 104 in the public values (see spec 12, "Proof Public Values
Layout"). The covenant verifies this hash matches the actual batch data
via two checks:

1. `hash256(batchData) == batchDataHash` — the proof covers this data
2. `hashOutputs` match — the OP_RETURN contains this data

Together these ensure a malicious prover cannot post a valid proof
with garbage batch data. See spec 12, covenant contract step 6.

For genesis config announcements, message type 0x01:
```
  [4 bytes]  "BSVM"
  [1 byte]   0x01 (genesis config)
  [1 byte]   Version: 0x01
  [8 bytes]  Chain ID
  [32 bytes] Genesis state root
  [variable] RLP-encoded genesis config
```

For snapshot announcements, message type 0x04 (emitted every
`SnapshotInterval` blocks, default 10,000):
```
  [4 bytes]  "BSVM"
  [1 byte]   0x04 (snapshot announcement)
  [1 byte]   Version: 0x01
  [8 bytes]  L2 block number (the block at which the snapshot was taken)
  [32 bytes] State root at snapshot block
  [32 bytes] Snapshot hash (keccak256 of the serialised snapshot stream)
```

The snapshot announcement is included as an additional field in the
batch data OP_RETURN (output 1) of the covenant-advance transaction
for the snapshot block. It is appended after the transaction payload
and does NOT affect the batchDataHash computation (it falls outside
the canonical encoding range). This avoids adding an extra output
that would break the covenant's hashOutputs verification.
New nodes syncing from BSV scan for message type 0x04 to find the most
recent snapshot, download it from any peer, verify its hash, and resume
replay from that point.

This format is versioned and extensible. The version byte allows future
format changes without breaking older decoders.

This format must be implemented identically by all nodes. Add
`pkg/overlay/batch_codec.go` to the overlay package file list.

---

## Transaction Ordering

**Canonical ordering rule**: The transaction ordering within a batch
is determined solely by the serialized batch data in the OP_RETURN
output. All nodes MUST replay transactions in the exact order they
appear in the batch data. The prover that produces the batch chooses
the ordering.

This is equivalent to sequencer ordering on current L2s. The prover
has discretion over ordering within each batch. Other nodes accept
this ordering unconditionally when replaying from BSV data.

For nodes receiving transactions via gossip (before a batch is
published), each node maintains a local pending list in arrival order.
When building a batch, the node may reorder. When verifying a batch
from another node, the node replays in the batch's order regardless
of its own local arrival order.

Deterministic replay is guaranteed because the batch data is the
single source of truth for ordering.

---

## RPC Compatibility

The RPC layer remains Ethereum-compatible. The key difference is what
happens behind `eth_sendRawTransaction`:

```go
// Before (original spec): add to L2 mempool, wait for sequencer to include
// Now: execute immediately, build BSV tx, broadcast, return receipt

func (api *EthAPI) SendRawTransaction(encodedTx hexutil.Bytes) (Hash, error) {
    evmTx, err := DecodeTransaction(encodedTx)
    if err != nil {
        return Hash{}, err
    }

    // Execute and broadcast — this returns in milliseconds
    receipt, err := api.overlay.ProcessTransaction(evmTx)
    if err != nil {
        return Hash{}, err
    }

    return evmTx.Hash(), nil
}

// eth_getTransactionReceipt works immediately — the receipt exists
// as soon as ProcessTransaction returns. No "pending" state.

// eth_call and eth_estimateGas are unchanged.
```

From the user's perspective, the L2 feels instant. They call
`eth_sendRawTransaction`, get a tx hash back in milliseconds, and
`eth_getTransactionReceipt` returns a receipt immediately.

Behind the scenes, a BSV transaction was built and broadcast. The
user doesn't need to know or care. The BSV tx will be mined eventually,
and the overlay monitors for the (extremely unlikely) case where it isn't.

---

## Speculative Receipts

In the multi-node competitive model, receipts returned by a node are
speculative until the node's batch wins the covenant advance race and
is proven. If the node loses the race, some receipts may be invalidated.

### How Invalidation Happens

Node A and Node B both build batches from overlapping but not identical
transaction sets. Node A returns receipts to its users. Node A starts
proving. Node B proves faster, wins the covenant UTXO. Node A discards
its proof, replays Node B's batch, and rebuilds state. Transactions
that Node A had included but Node B did not are re-queued if still
valid, or dropped if now invalid (nonce conflict, insufficient balance
after Node B's batch changed the state).

If a transaction is dropped, the receipt Node A previously returned is
invalid. The user was told their transaction succeeded, but it did not
execute on the canonical chain.

### Minimising Invalidation

1. **Transaction gossip**: All nodes gossip received transactions to
   all peers. The faster transactions propagate, the more similar
   competing batches are. With good gossip, 95%+ of transactions
   overlap between competing batches — only ordering differs. Different
   ordering does not invalidate receipts (the tx succeeds at a
   different index, but still succeeds).
2. **Submit to multiple nodes**: Users (or RPC gateways) can broadcast
   transactions to all known shard nodes. Every competing batch
   includes the transaction. Receipt invalidation only happens when a
   transaction is completely absent from the winning batch.
3. **Nonce protection**: The EVM nonce system prevents duplicate
   execution. If the same transaction (same hash, same nonce) appears
   in the winning batch, it produces the same result regardless of
   which node won.

### Receipt Confirmation Status

Receipts indicate their confirmation level via a non-standard extension
field `bsvConfirmationStatus`:

```json
{
    "status": "0x1",
    "blockNumber": "0x1a4",
    "bsvConfirmationStatus": "speculative"
}
```

Values:

- `"speculative"`: Executed locally, not yet proven. May be invalidated
  if this node loses the proving race.
- `"proven"`: STARK proof generated and BSV transaction broadcast. The
  batch is cryptographically committed. Receipt is permanent unless a
  BSV reorg occurs (extremely rare).
- `"confirmed"`: BSV transaction confirmed in at least 1 BSV block.
- `"finalized"`: BSV transaction has 6+ BSV confirmations.

The standard Ethereum block tags map to these: `latest` = speculative,
`safe` = proven, `finalized` = 6+ BSV confirmations. See spec 05 for
the authoritative block tag definitions.

### Comparison with Existing L2s

This is the same fundamental trade-off every L2 makes. Arbitrum and
Optimism give instant receipts from a single sequencer that could
theoretically reorder before L1 posting. BSVM gives instant receipts
from any node, with the additional risk that a competing node may win
with a different batch. The speculative window is short (~5-10 seconds,
the proving time). Wallets that care about certainty should wait for
`"proven"` status before displaying success.

## What Disappears From the Original Spec

| Spec | Component | Status |
|------|-----------|--------|
| 04 | BSV Anchor Service | **Replaced** by covenant chain in overlay node |
| 06 | Sequencer (txpool, ordering) | **Replaced** by overlay node (no mempool) |
| 06 | Transaction validation | **Moved** into overlay.ProcessTransaction |
| 06 | Block production loop | **Replaced** by event-driven: one tx in → one block out |
| 10 | Fast path vs forced path | **Eliminated** — there is only one path |
| 10 | Forced tx scanner | **Eliminated** — no separate submission channel |
| 10 | Mempool watching | **Eliminated** — overlay IS the source of truth |
| 07 | wBSV gas token | **Unchanged** — wBSV is the native gas token, standard Ethereum gas model |

## What Remains Unchanged

| Spec | Component | Status |
|------|-----------|--------|
| 01 | EVM extraction | Unchanged |
| 02 | StateDB implementation | Unchanged |
| 03 | Block execution engine | Unchanged (used by overlay) |
| 05 | RPC Gateway | Mostly unchanged (sendRawTx wraps in BSV tx) |
| 07 | Bridge (for msg.value / DeFi) | Unchanged (still need deposits for L2 balance) |
| 10 | Rúnar covenant contracts | Unchanged (covenant is the chain) |

---

## BSV Client Interface

The BSV client provides all BSV network interaction needed by the overlay
node, covenant manager, bridge, and double-spend monitor.

```go
// pkg/bsv/client.go

type BSVClient interface {
    // Transaction broadcasting
    Broadcast(tx *Transaction) (TxID, error)

    // Transaction queries
    GetTransaction(txid TxID) (*Transaction, error)
    GetTransactionStatus(txid TxID) (*TxStatus, error)

    // UTXO queries
    GetUTXOs(address string) ([]UTXO, error)
    GetUTXO(txid TxID, vout uint32) (*UTXO, error)
    IsUTXOSpent(txid TxID, vout uint32) (bool, error) // For fee wallet reconciliation

    // Covenant chain walking (for sync)
    GetSpendingTx(txid TxID, vout uint32) (*Transaction, error) // Find the tx that spends a given output

    // Block queries
    GetBlockByHeight(height uint64) (*Block, error)
    GetBlockHeader(height uint64) (*BlockHeader, error)
    GetChainTip() (uint64, TxID, error)

    // Subscriptions
    SubscribeBlocks(ctx context.Context) (<-chan *Block, error)
    SubscribeDoubleSpendAlerts(ctx context.Context) (<-chan *DoubleSpendAlert, error)

    // SPV proof
    GetMerkleProof(txid TxID) (*MerkleProof, error)

    // Connectivity check (returns nil if reachable, error otherwise)
    Ping() error
}

type TxID = [32]byte

type TxStatus struct {
    TxID          TxID
    Confirmed     bool
    BlockHeight   uint64
    BlockHash     TxID
    Confirmations uint64
}

type UTXO struct {
    TxID     TxID
    Vout     uint32
    Satoshis uint64
    Script   []byte
}

type DoubleSpendAlert struct {
    TxID        TxID   // The tx that was double-spent
    CompetingTx TxID   // The competing tx
}
```

Implementation options (both supported):
- `pkg/bsv/rpc_client.go` — Direct BSV node JSON-RPC
- `pkg/bsv/arc_client.go` — BSV ARC broadcast API

---

## Peer Discovery

**Bootstrap**: Shard config includes a list of bootstrap peer
addresses (multiaddr format). New nodes connect to bootstrap peers
on startup.

**Peer exchange (PEX)**: Once connected, nodes exchange peer lists
periodically. Each node maintains a peer table of known nodes in the
shard. New peers are discovered via gossip.

**Implementation**: Use libp2p with the Kademlia DHT for peer
discovery within the shard. The DHT namespace is scoped by shard ID
(chain ID) so different shards don't interfere.

```toml
[network]
listen_addr = "/ip4/0.0.0.0/tcp/9945"
bootstrap_peers = [
    "/ip4/1.2.3.4/tcp/9945/p2p/QmPeerID1",
    "/ip4/5.6.7.8/tcp/9945/p2p/QmPeerID2",
]
max_peers = 50
shard_dht_namespace = "bsvm-8453111"  # derived from chain ID
```

---

## Summary

The L2 overlay node is a single process that:

1. **Receives** EVM transactions (via Ethereum-compatible RPC)
2. **Executes** them through the EVM engine (milliseconds)
3. **Builds** a BSV transaction advancing the covenant (milliseconds)
4. **Broadcasts** the BSV transaction (fire and forget)
5. **Caches** the transaction locally (this is the new chain tip)
6. **Returns** the receipt to the user (total: low milliseconds)
7. **Monitors** BSV for confirmations and the near-impossible double-spend

No mempool. No block interval timer. No ordering decisions. No waiting.
The L2 processes transactions as fast as they arrive. Every L2 state
transition is a BSV transaction. The covenant UTXO chain is the L2
blockchain. BSV is both the data availability layer and the settlement
layer, and the overlay uses it exactly as Bitcoin was designed to be used.
