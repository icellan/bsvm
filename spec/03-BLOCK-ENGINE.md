# Phase 2: L2 Block Engine

## Goal
Build the transaction execution pipeline that accepts signed EVM transactions, executes them through the EVM engine, produces L2 blocks with state roots, and generates receipts.

## L2 Block Structure

```go
// pkg/block/types.go

// L2Header is the header of an L2 block.
type L2Header struct {
    ParentHash  Hash        // Hash of parent L2 block header
    Coinbase    Address     // L2 address of the prover node. All gas fees from transactions
                            // in the block are credited here via the EVM's standard fee
                            // mechanism (StateTransition.execute step 6). In multi-node
                            // mode, set by whichever node wins the proving race. This is
                            // the prover's sole revenue stream — no BSV reward from the
                            // covenant. The prover withdraws accumulated wBSV via the
                            // bridge to fund BSV mining fees for future advances.
    StateRoot   Hash        // Post-execution MPT state root
    TxHash      Hash        // Merkle root of transactions in this block
    ReceiptHash Hash        // Merkle root of receipts
    LogsBloom   Bloom       // 2048-bit bloom filter for log topics
    Number      *big.Int    // L2 block number
    GasLimit    uint64      // Max gas for this block
    GasUsed     uint64      // Total gas used by all txs
    Timestamp   uint64      // Unix timestamp
    BaseFee     *big.Int    // EIP-1559 base fee (can be 0 or configurable)
    Extra       []byte      // Arbitrary extra data (max 32 bytes)
}

// AnchorRecord tracks BSV covenant information for an L2 block.
// Stored separately from L2Header so that the block hash is stable
// (it does NOT change after the block is posted to BSV).
//
// pkg/block/anchor.go
type AnchorRecord struct {
    L2BlockNum     uint64
    BSVTxID        Hash
    BSVBlockHeight uint64
    Confirmed      bool
}

// Stored via:
//   func (db ChainDB) WriteAnchorRecord(rec *AnchorRecord) error
//   func (db ChainDB) ReadAnchorRecord(l2BlockNum uint64) (*AnchorRecord, error)
//
// Write timing: The AnchorRecord is written by the overlay node AFTER the
// BSV covenant-advance transaction is confirmed (at least 1 BSV confirmation).
// During the window between batch execution and BSV confirmation, the
// AnchorRecord is absent — queries for it return nil, indicating the batch
// is proven but not yet anchored.

// L2Block is a complete L2 block.
type L2Block struct {
    Header       *L2Header
    Transactions []*Transaction
    Receipts     []*Receipt
}

// Hash returns the Keccak256 hash of the RLP-encoded header.
func (h *L2Header) Hash() Hash {
    return rlpHash(h)
}
```

## Transaction Types

We support standard Ethereum transaction types for maximum tooling compatibility:

```go
// pkg/types/transaction.go

// Transaction represents an L2 EVM transaction.
// We support EIP-2718 typed transaction envelopes.
type Transaction struct {
    inner TxData
    hash  atomic.Value // cached hash
    size  atomic.Value // cached size
}

// TxData is the interface for transaction payloads.
type TxData interface {
    txType() byte
    chainID() *big.Int
    nonce() uint64
    gasPrice() *big.Int
    gasTipCap() *big.Int
    gasFeeCap() *big.Int
    gas() uint64
    to() *Address
    value() *uint256.Int
    data() []byte
    accessList() AccessList
    
    rawSignatureValues() (v, r, s *big.Int)
    setSignatureValues(chainID, v, r, s *big.Int)
}

// Supported transaction types:
// Type 0: LegacyTx (pre-EIP-2718)
// Type 1: AccessListTx (EIP-2930)
// Type 2: DynamicFeeTx (EIP-1559)
//
// We do NOT support Type 3 (BlobTx / EIP-4844) since blobs are an L1 concept.
// Our L2 posts data to BSV instead.

type LegacyTx struct {
    Nonce    uint64
    GasPrice *big.Int
    Gas      uint64
    To       *Address // nil for contract creation
    Value    *uint256.Int
    Data     []byte
    V, R, S  *big.Int
}

type AccessListTx struct {
    ChainID    *big.Int
    Nonce      uint64
    GasPrice   *big.Int
    Gas        uint64
    To         *Address
    Value      *uint256.Int
    Data       []byte
    AccessList AccessList
    V, R, S    *big.Int
}

type DynamicFeeTx struct {
    ChainID    *big.Int
    Nonce      uint64
    GasTipCap  *big.Int // "maxPriorityFeePerGas"
    GasFeeCap  *big.Int // "maxFeePerGas"
    Gas        uint64
    To         *Address
    Value      *uint256.Int
    Data       []byte
    AccessList AccessList
    V, R, S    *big.Int
}
```

## Extracted Types

**Extracted types**: The following types and functions are extracted
from geth and adapted to use our types. They are not redefined in
detail in this spec because their implementation is a direct port
from geth's codebase:

- `GasPool` — from `core/gas_pool.go`. Simple uint64 wrapper with AddGas/SubGas.
- `TransactionToMessage(tx, signer, baseFee)` — from `core/state_transition.go`. Converts a signed tx to a Message.
- `Signer` — from `core/types/tx_signing.go`. EIP-155/2930/1559 signer for sender recovery.
- `ActivePrecompiles(rules)` — from `core/vm/contracts.go`. Returns precompile addresses active under given rules.
- `CreateBloom(receipts)` — from `core/types/bloom9.go`. Computes the 2048-bit bloom filter for a set of receipts.
- `DeriveSha(list)` — from `core/types/hashing.go`. Computes Merkle root of an ordered list (txs or receipts).

## Transaction Execution Pipeline

```go
// pkg/block/executor.go

type BlockExecutor struct {
    chainConfig *vm.ChainConfig
    vmConfig    vm.Config
    stateDB     *state.StateDB
    db          db.Database
}

// ExecuteBlock executes all transactions in a block and returns the results.
func (e *BlockExecutor) ExecuteBlock(block *L2Block, statedb *state.StateDB) (*ExecutionResult, error) {
    var (
        gasPool  = new(GasPool).AddGas(block.Header.GasLimit)
        receipts []*Receipt
        allLogs  []*Log
        gasUsed  uint64
    )
    
    // Create block context.
    // GetHash provides the BLOCKHASH opcode (EIP-2 — returns hash for
    // up to 256 ancestor blocks). Implementation reads from ChainDB:
    //
    //   func (e *BlockExecutor) getHashFn(ref *L2Header) vm.GetHashFunc {
    //       return func(n uint64) Hash {
    //           if n >= ref.Number.Uint64() || ref.Number.Uint64()-n > 256 {
    //               return Hash{} // Out of range or future block
    //           }
    //           h := e.chainDB.ReadCanonicalHash(n)
    //           return h // Hash{} if block doesn't exist (pre-genesis)
    //       }
    //   }
    //
    // For blocks before genesis (n < 0, which can't happen with uint64,
    // or blocks that don't exist), returns Hash{} (all zeros).
    blockCtx := vm.BlockContext{
        CanTransfer: CanTransfer,
        Transfer:    Transfer,
        GetHash:     e.getHashFn(block.Header),
        Coinbase:    block.Header.Coinbase,
        GasLimit:    block.Header.GasLimit,
        BlockNumber: new(big.Int).Set(block.Header.Number),
        Time:        block.Header.Timestamp,
        Difficulty:  big.NewInt(0), // post-merge
        BaseFee:     new(big.Int).Set(block.Header.BaseFee),
        // Random is derived from BSV block hash for PREVRANDAO determinism.
        // During live execution: keccak256(latestBSVBlockHash || l2BlockNumber)
        // During replay from BSV data: extracted verbatim from batch data.
        Random:      deriveRandom(bsvBlockHash, block.Header.Number),
    }
    
    // Create EVM instance (reused across txs in the block)
    evm := vm.NewEVM(blockCtx, statedb, e.chainConfig, e.vmConfig)
    
    for i, tx := range block.Transactions {
        // Set tx context
        msg, err := TransactionToMessage(tx, e.signer(), block.Header.BaseFee)
        if err != nil {
            return nil, fmt.Errorf("tx %d: %w", i, err)
        }
        
        statedb.SetTxContext(tx.Hash(), i)
        
        // Prepare access list
        statedb.Prepare(
            e.chainConfig.Rules(block.Header.Number, true, block.Header.Timestamp),
            msg.From, block.Header.Coinbase, msg.To,
            vm.ActivePrecompiles(e.chainConfig.Rules(...)),
            msg.AccessList,
        )
        
        // Execute
        receipt, err := ApplyTransaction(evm, gasPool, statedb, block.Header, tx, &gasUsed)
        if err != nil {
            return nil, fmt.Errorf("tx %d execution failed: %w", i, err)
        }
        
        receipts = append(receipts, receipt)
        allLogs = append(allLogs, receipt.Logs...)
    }
    
    // Compute post-block state root
    // deleteEmptyObjects = true (see usage rule below)
    stateRoot := statedb.IntermediateRoot(true)
    
    return &ExecutionResult{
        StateRoot: stateRoot,
        Receipts:  receipts,
        Logs:      allLogs,
        GasUsed:   gasUsed,
    }, nil
}
```

**`deleteEmptyObjects` usage rule**: Set `deleteEmptyObjects = true` for all post-Spurious Dragon execution. Accounts with nonce=0, balance=0, and no code are deleted during `Finalise()`. This matches Ethereum's EIP-161 semantics. On this L2, the Spurious Dragon rules are always active (no pre-Spurious Dragon history). The `true` argument to `IntermediateRoot` and `Commit` enables this cleanup.

## Transaction Application (single tx)

```go
// pkg/block/apply.go

func ApplyTransaction(
    evm *vm.EVM,
    gasPool *GasPool,
    statedb *state.StateDB,
    header *L2Header,
    tx *Transaction,
    usedGas *uint64,
) (*Receipt, error) {
    msg, err := TransactionToMessage(tx, signer, header.BaseFee)
    if err != nil {
        return nil, err
    }
    
    // Apply the transaction to the EVM
    result, err := ApplyMessage(evm, msg, gasPool)
    if err != nil {
        return nil, err
    }
    
    *usedGas += result.UsedGas
    
    // Create receipt
    receipt := &Receipt{
        Type:              tx.Type(),
        Status:            ReceiptStatusSuccessful,
        CumulativeGasUsed: *usedGas,
        TxHash:            tx.Hash(),
        GasUsed:           result.UsedGas,
        Logs:              statedb.GetLogs(tx.Hash()),
        BlockNumber:       header.Number,
    }
    
    if result.Failed() {
        receipt.Status = ReceiptStatusFailed
    }
    
    // Set contract address for contract creation txs
    if msg.To == nil {
        // Use the nonce from state (already incremented by state transition),
        // subtract 1 to get the nonce used for address derivation. This matches geth.
        receipt.ContractAddress = crypto.CreateAddress(msg.From, statedb.GetNonce(msg.From)-1)
    }
    
    // Compute bloom filter
    receipt.Bloom = CreateBloom(Receipts{receipt})
    
    return receipt, nil
}
```

## State Transition (message application)

```go
// pkg/block/state_transition.go

type StateTransition struct {
    evm     *vm.EVM
    msg     *Message
    gasPool *GasPool
    state   vm.StateDB
    
    initialGas uint64
    gasUsed    uint64
}

type Message struct {
    From       Address
    To         *Address
    Nonce      uint64
    Value      *uint256.Int
    GasLimit   uint64
    GasPrice   *big.Int
    GasFeeCap  *big.Int
    GasTipCap  *big.Int
    Data       []byte
    AccessList AccessList
    IsFake     bool // true for eth_call (skip signature checks)
}

func ApplyMessage(evm *vm.EVM, msg *Message, gasPool *GasPool) (*ExecutionResult, error) {
    st := &StateTransition{
        evm:     evm,
        msg:     msg,
        gasPool: gasPool,
        state:   evm.StateDB,
    }
    return st.execute()
}

func (st *StateTransition) execute() (*ExecutionResult, error) {
    // 1. preCheck(): Validate nonce, buy gas (deduct from sender balance)
    // 2. Check intrinsic gas
    // 3. Execute:
    //    - If msg.To == nil: CREATE (contract deployment)
    //    - Else: CALL
    // 4. Refund unused gas (see gas refund rules below)
    // 5. Pay fees to coinbase
    // 6. Transfer gas fees to coinbase:
    //    statedb.AddBalance(coinbase, gasUsed * effectiveGasPrice,
    //        tracing.BalanceIncreaseRewardTransactionFee)
    //    statedb.SubBalance(sender, gasUsed * effectiveGasPrice,
    //        tracing.BalanceDecreaseGasBuy)
    //    Note: gas purchase (SubBalance) happens in Step 1; the refund
    //    (AddBalance back to sender) and coinbase credit happen in Step 5/6.
    // 7. Return execution result
}
```

**Gas refund rules**: Gas refunds follow EIP-3529 (post-London): maximum refund is `gasUsed / 5` (not the pre-London `gasUsed / 2`). SSTORE refunds follow EIP-2200 + EIP-3529 rules. SELFDESTRUCT no longer grants a refund (EIP-3529). These rules are inherited from the extracted geth code and validated against the ethereum/tests suite.

### Transaction Validation

Validation occurs in `StateTransition.preCheck()` before gas purchase:

1. **Signature**: Invalid signature -> transaction rejected, NOT included in block.
2. **Nonce**: `tx.Nonce != statedb.GetNonce(sender)` -> transaction rejected, NOT included in block.
3. **Gas limit**: `tx.Gas > block.GasLimit` -> transaction rejected, NOT included in block.
4. **Balance**: `sender.Balance < tx.Gas * tx.GasPrice + tx.Value` -> transaction rejected, NOT included in block.
5. **MinGasPrice**: `tx.GasPrice < config.MinGasPrice` -> validated by overlay node (Spec 11) before accepting into mempool. The BlockExecutor does NOT re-validate; it assumes all transactions in the block passed overlay validation.

Failed transactions (reverts, out-of-gas) that pass preCheck ARE included in the block and consume gas. Invalid transactions that fail preCheck are NOT included.

## Gas Model

For the L2, we have flexibility in gas pricing. Options:

### Decision: Fixed gas price (Option A)

**BaseFee is fixed at 0.** The overlay node enforces a minimum gas price
via configuration (`GasPriceGwei`, default 1 gwei). EIP-1559 transaction
types (Type 2) are accepted — the `GasFeeCap` and `GasTipCap` fields
are validated but the effective gas price is simply `GasPrice` (for
Type 0/1) or `GasTipCap` (for Type 2, since BaseFee is 0).

This is a definitive v1 decision, not a recommendation. A future
version may introduce dynamic base fee adjustment via the protocol
upgrade mechanism (spec 09, Milestone 10). The `BaseFee` field is
present in L2Header for forward compatibility but is always 0 in v1.

### Failed transactions within a batch

Failed transactions (reverts, out-of-gas) are still included in the
block and consume gas, matching Ethereum behavior. The receipt has
`Status = ReceiptStatusFailed`. The sender's nonce is incremented
and the gas fee is charged. This applies to both `ProcessTransaction`
and `ProcessBatch` paths.

```go
// pkg/block/gas.go

type GasConfig struct {
    BlockGasLimit   uint64   // Default: 30_000_000 (same as Ethereum)
    MinGasPrice     *big.Int // Minimum accepted gas price (default: 1 gwei)
    // BaseFee is always 0 in v1. Dynamic base fee (EIP-1559) is a post-v1
    // feature that would be introduced via the protocol upgrade mechanism
    // (spec 09, Milestone 10). The UseEIP1559, ElasticityMultiplier, and
    // BaseFeeChangeDenominator fields from an earlier spec version have been
    // removed — they are not needed in v1 and would be dead code.
}
```

## Receipt Type

```go
// pkg/types/receipt.go

type Receipt struct {
    Type              uint8
    Status            uint64  // 1 = success, 0 = failure
    CumulativeGasUsed uint64
    Bloom             Bloom
    Logs              []*Log
    
    TxHash          Hash
    ContractAddress Address  // Set for contract creation txs
    GasUsed         uint64
    
    BlockHash       Hash
    BlockNumber     *big.Int
    TransactionIndex uint
}

const (
    ReceiptStatusFailed     = uint64(0)
    ReceiptStatusSuccessful = uint64(1)
)
```

## Block Production

> **NOTE**: The `BlockProducer` struct, `blockInterval`, `minTxPerBlock`,
> `maxTxPerBlock`, `EmptyBlocks` config, and the concept of "the sequencer
> produces blocks on a timer" are **superseded**. Block production is driven
> by the overlay node when transactions arrive, not by a timer.
>
> The `BlockExecutor` and `ExecuteBlock` function remain — they are called
> by the overlay node to execute transaction batches.

### Covenant TxID Tracking

The BSV covenant txid for each L2 block is tracked separately (not in the
header hash). The overlay node records it after broadcasting. This is stored
via a separate `WriteCovenantTxID(l2BlockNum, bsvTxID)` in the ChainDB.

## Chain Database

We need to store L2 blocks, headers, receipts, and tx lookup indices:

```go
// pkg/block/chaindb.go

type ChainDB interface {
    // Headers
    WriteHeader(header *L2Header) error
    ReadHeader(hash Hash, number uint64) *L2Header
    ReadHeaderByNumber(number uint64) *L2Header
    ReadHeaderByHash(hash Hash) *L2Header
    
    // Bodies (transactions)
    WriteBody(hash Hash, number uint64, body *L2Block) error
    ReadBody(hash Hash, number uint64) *L2Block
    
    // Receipts
    WriteReceipts(hash Hash, number uint64, receipts []*Receipt) error
    ReadReceipts(hash Hash, number uint64) []*Receipt
    
    // Canonical chain
    WriteCanonicalHash(hash Hash, number uint64) error
    ReadCanonicalHash(number uint64) Hash
    WriteHeadBlockHash(hash Hash) error
    ReadHeadBlockHash() Hash
    
    // Transaction lookup
    WriteTxLookup(txHash Hash, blockHash Hash, blockNumber uint64, index uint64) error
    ReadTxLookup(txHash Hash) (*TxLookupEntry, error)

    // Head header (used by overlay node)
    ReadHeadHeader() *L2Header

    // Anchor records (BSV covenant tracking, stored separately from L2Header)
    WriteAnchorRecord(rec *AnchorRecord) error
    ReadAnchorRecord(l2BlockNum uint64) (*AnchorRecord, error)

    // Covenant txid tracking
    WriteCovenantTxID(l2BlockNum uint64, bsvTxID Hash) error
    ReadCovenantTxID(l2BlockNum uint64) (Hash, error)

    // Block write (convenience: writes header + body + canonical hash)
    WriteBlock(block *L2Block) error
}
```

**Speculative execution limit**: The overlay node (Spec 11) limits speculative batch depth to `MaxSpeculativeDepth` (default: 16). If unproven blocks reach this limit, the batcher pauses until the oldest unproven block completes proving. The BlockExecutor itself has no depth limit -- the limit is enforced by the overlay node's batcher.

### ChainDB Key Encoding

Keys use prefix-based encoding for LevelDB:

| Key Pattern | Value |
|---|---|
| `h<blockNum8><blockHash32>` | RLP-encoded L2Header |
| `H<blockNum8>` | Canonical block hash (32 bytes) |
| `b<blockNum8><blockHash32>` | RLP-encoded block body (transaction list) |
| `r<blockNum8><blockHash32>` | RLP-encoded receipt list |
| `a<blockNum8><blockHash32>` | RLP-encoded AnchorRecord |
| `l` | Latest block number (8 bytes, big-endian) |

`blockNum8` is the block number as 8-byte big-endian. All writes within a block (header + body + receipts + anchor) use a single LevelDB `WriteBatch` for atomicity. If the process crashes mid-write, incomplete data is detected on startup by comparing the `l` key against the latest header.

## Deliverables

1. `pkg/block/types.go` — L2 block and header types
2. `pkg/block/executor.go` — Block execution engine
3. `pkg/block/apply.go` — Single transaction application
4. `pkg/block/state_transition.go` — EVM message execution (gas buying, refunds)
5. `pkg/block/producer.go` — Block production logic
6. `pkg/block/chaindb.go` — Block/receipt storage
7. `pkg/types/transaction.go` — Transaction types (Legacy, EIP-2930, EIP-1559)
8. `pkg/types/receipt.go` — Receipt type with bloom filter
9. `pkg/types/log.go` — Event log type

## Acceptance Criteria

- [ ] Execute ethereum/tests GeneralStateTests fixtures and verify post-state root matches expected. This is the correctness oracle.
- [ ] Receipts include correct gas used, status, logs, bloom filter
- [ ] Contract creation produces correct contract addresses
- [ ] Nonce validation rejects out-of-order transactions
- [ ] Gas pool correctly limits total gas per block
- [ ] Intrinsic gas matches geth's `IntrinsicGas()` for: zero-byte calldata, non-zero-byte calldata, contract creation, access list entries. Verified via table-driven tests against geth's output.
- [ ] State transition matches geth behavior for identical inputs
- [ ] Overlay node can produce valid blocks from a set of transactions
