# Spec 05: Ethereum JSON-RPC Gateway (Milestone 6)

## Goal
Expose a standard Ethereum JSON-RPC API so that existing tools (MetaMask, ethers.js, Hardhat, Foundry, web3.js) work with the BSVM L2 with zero or minimal configuration changes.

## Supported Namespaces and Methods

### `eth_` namespace (core — must implement)

| Method | Priority | Notes |
|---|---|---|
| `eth_chainId` | P0 | Return our L2 chain ID |
| `eth_blockNumber` | P0 | Latest L2 block number |
| `eth_getBalance` | P0 | Query StateDB |
| `eth_getTransactionCount` | P0 | Nonce from StateDB |
| `eth_getCode` | P0 | Contract code from StateDB |
| `eth_getStorageAt` | P0 | Storage slot from StateDB |
| `eth_call` | P0 | Execute tx against current state without committing |
| `eth_estimateGas` | P0 | Binary search for gas limit |
| `eth_sendRawTransaction` | P0 | Submit signed tx to mempool |
| `eth_getTransactionByHash` | P0 | Lookup from ChainDB |
| `eth_getTransactionReceipt` | P0 | Lookup from ChainDB |
| `eth_getBlockByNumber` | P0 | Return L2 block |
| `eth_getBlockByHash` | P0 | Return L2 block |
| `eth_gasPrice` | P0 | Return current gas price |
| `eth_getLogs` | P0 | Filter logs by address/topics |
| `eth_getBlockTransactionCountByNumber` | P1 | |
| `eth_getBlockTransactionCountByHash` | P1 | |
| `eth_getTransactionByBlockHashAndIndex` | P1 | |
| `eth_getTransactionByBlockNumberAndIndex` | P1 | |
| `eth_feeHistory` | P1 | EIP-1559 fee history |
| `eth_maxPriorityFeePerGas` | P1 | Suggested tip |
| `eth_syncing` | P1 | Sync status |
| `eth_getBlockReceipts` | P0 | Return all receipts for a block (needed by indexers, The Graph, block explorers) |
| `eth_accounts` | P2 | Empty (no local accounts) |
| `eth_sign` | P2 | Not supported (client-side signing) |
| `eth_sendTransaction` | P2 | Not supported (use sendRawTransaction) |
| `eth_createAccessList` | P2 | EIP-2930 access list generation |
| `eth_getProof` | P1 | EIP-1186: account + storage Merkle proofs (needed for bridges, light clients). Uses `StateDB.GetProof()` and `StateDB.GetStorageProof()` (see spec 02). |

### `eth_subscribe` / `eth_unsubscribe` (WebSocket)

| Subscription | Priority | Notes |
|---|---|---|
| `newHeads` | P0 | New L2 block headers |
| `logs` | P0 | Real-time log filtering |
| `newPendingTransactions` | N/A | **Not supported.** Transactions are not "pending" — they execute immediately upon submission to the overlay node. |

### `net_` namespace

| Method | Priority |
|---|---|
| `net_version` | P0 |
| `net_listening` | P1 |
| `net_peerCount` | P2 |

### `web3_` namespace

| Method | Priority |
|---|---|
| `web3_clientVersion` | P0 |
| `web3_sha3` | P1 |

### `bsv_` namespace (BSV-specific)

| Method | Priority | Notes |
|--------|----------|-------|
| `bsv_getCovenantTip` | P1 | Current covenant UTXO txid, L2 block number, state root |
| `bsv_getConfirmationStatus` | P1 | BSV confirmations for an L2 block |
| `bsv_getCachedChainLength` | P2 | Unconfirmed covenant txs in cache |
| `bsv_shardInfo` | P1 | Shard ID, chain ID, covenant genesis txid, node count |
| `bsv_peerCount` | P2 | Number of peer nodes in this shard |
| `bsv_feeWalletBalance` | P2 | Prover's BSV fee wallet balance in satoshis (for operational monitoring) |
| `bsv_getGovernanceState` | P1 | Governance mode, frozen status, governance key info |
| `bsv_buildWithdrawalClaim` | P1 | Returns unsigned BSV withdrawal-claim tx + Merkle proof for a given withdrawal nonce |

#### `bsv_` Response Formats

```go
// bsv_getCovenantTip response
type CovenantTipResult struct {
    BSVTxID     Hash           `json:"bsvTxId"`
    L2BlockNum  hexutil.Uint64 `json:"l2BlockNumber"`
    StateRoot   Hash           `json:"stateRoot"`
    Confirmed   bool           `json:"confirmed"`
    BSVHeight   hexutil.Uint64 `json:"bsvBlockHeight,omitempty"` // set if confirmed
}

// bsv_getConfirmationStatus response
type ConfirmationStatusResult struct {
    L2BlockNum     hexutil.Uint64 `json:"l2BlockNumber"`
    BSVTxID        Hash           `json:"bsvTxId"`
    Confirmations  hexutil.Uint64 `json:"confirmations"`
    Confirmed      bool           `json:"confirmed"`
    Safe           bool           `json:"safe"`      // >= ConfirmationsSafe (1)
    Finalized      bool           `json:"finalized"` // >= ConfirmationsFinalized (6)
}

// bsv_shardInfo response
type ShardInfoResult struct {
    ShardID            hexutil.Uint64  `json:"shardId"`
    ChainID            hexutil.Uint64  `json:"chainId"`
    GenesisCovenantTxID Hash           `json:"genesisCovenantTxId"`
    PeerCount          hexutil.Uint64  `json:"peerCount"`
    ExecutionTip       hexutil.Uint64  `json:"executionTip"`
    ProvenTip          hexutil.Uint64  `json:"provenTip"`
    CachedChainLength  hexutil.Uint64  `json:"cachedChainLength"`
    Governance         GovernanceInfo  `json:"governance"`
}

// GovernanceInfo exposes the shard's governance model and current state.
// Users and dApps should query this before depositing to understand the
// shard's trust model. Wallets should display a warning if mode is
// "single_key" (high trust in one party) and a different indicator if
// "none" (no recovery possible).
type GovernanceInfo struct {
    Mode      string         `json:"mode"`      // "none", "single_key", or "multisig"
    Threshold hexutil.Uint64 `json:"threshold,omitempty"` // M-of-N (multisig only)
    KeyCount  hexutil.Uint64 `json:"keyCount,omitempty"`  // N (multisig only)
    Frozen    bool           `json:"frozen"`    // Current frozen state
}

// bsv_feeWalletBalance response
type FeeWalletBalanceResult struct {
    Balance hexutil.Uint64 `json:"balance"` // In satoshis
    Address string         `json:"address"` // P2PKH address of the fee wallet
}

// bsv_buildWithdrawalClaim response
type WithdrawalClaimResult struct {
    UnsignedTx    hexutil.Bytes  `json:"unsignedTx"`    // Serialized unsigned BSV tx
    MerkleProof   []hexutil.Bytes `json:"merkleProof"`   // SHA256 Merkle authentication path
    WithdrawalRoot Hash           `json:"withdrawalRoot"` // From the batch's STARK public values
    Nonce         hexutil.Uint64 `json:"nonce"`
    Amount        hexutil.Uint64 `json:"amountSatoshis"`
    BSVAddress    string         `json:"bsvAddress"`     // Recipient P2PKH address
}
```

### `bsv_` WebSocket subscription

| Subscription | Priority | Notes |
|-------------|----------|-------|
| `bsvConfirmation` | P1 | Fires when an L2 block's BSV tx is confirmed |

### `debug_` namespace (for developers)

| Method | Priority |
|---|---|
| `debug_traceTransaction` | P2 |
| `debug_traceCall` | P2 |
| `debug_traceBlockByNumber` | P2 |
| `debug_traceBlockByHash` | P2 |
| `debug_evmDisagreement` | P2 | Returns diagnostic data when Go EVM and SP1 revm disagree on state roots |

## Architecture

```go
// pkg/rpc/server.go

type RPCServer struct {
    httpServer  *http.Server
    wsServer    *http.Server  // WebSocket upgrade handler
    
    ethAPI      *EthAPI
    netAPI      *NetAPI
    web3API     *Web3API
    
    chainDB     block.ChainDB
    stateReader StateReader
    overlay     *overlay.OverlayNode
}

type RPCConfig struct {
    HTTPAddr    string // e.g., "0.0.0.0:8545"
    WSAddr      string // e.g., "0.0.0.0:8546"
    CORSOrigins []string
    MaxConns    int
    
    // Rate limiting
    RequestsPerSecond int
    BurstSize         int
}
```

## EthAPI Implementation

```go
// pkg/rpc/eth_api.go

type EthAPI struct {
    chainConfig *vm.ChainConfig
    chainDB     block.ChainDB
    stateReader StateReader  // Read-only state access
    overlay     *overlay.OverlayNode  // Transactions route directly to the overlay node
    vmConfig    vm.Config
    gasConfig   block.GasConfig
}

// Note: there is no TxPool. Transactions are not "pending" in the overlay
// model — they execute immediately upon submission to the overlay node.

// StateReader provides read-only access to the state at any block.
type StateReader interface {
    StateAt(root Hash) (*state.StateDB, error)
    StateAtBlock(blockNumber uint64) (*state.StateDB, error)
    LatestState() (*state.StateDB, error)
}

// --- P0 Methods ---

func (api *EthAPI) ChainId() *hexutil.Big {
    return (*hexutil.Big)(api.chainConfig.ChainID)
}

func (api *EthAPI) BlockNumber() (hexutil.Uint64, error) {
    head := api.chainDB.ReadHeadBlockHash()
    header := api.chainDB.ReadHeaderByHash(head)
    return hexutil.Uint64(header.Number.Uint64()), nil
}

func (api *EthAPI) GetBalance(address Address, blockNrOrHash BlockNumberOrHash) (*hexutil.Big, error) {
    statedb, header, err := api.stateAndHeaderByNumberOrHash(blockNrOrHash)
    if err != nil {
        return nil, err
    }
    balance := statedb.GetBalance(address)
    return (*hexutil.Big)(balance.ToBig()), nil
}

func (api *EthAPI) Call(args TransactionArgs, blockNrOrHash BlockNumberOrHash) (hexutil.Bytes, error) {
    // 1. Load state at the requested block
    // 2. Create EVM with the block's context
    // 3. Execute the call (without committing)
    // 4. Return the result bytes
}

func (api *EthAPI) EstimateGas(args TransactionArgs, blockNrOrHash *BlockNumberOrHash) (hexutil.Uint64, error) {
    // Binary search between 21000 (min) and block gas limit
    // to find the minimum gas that doesn't cause OOG
}

func (api *EthAPI) SendRawTransaction(encodedTx hexutil.Bytes) (Hash, error) {
    // eth_sendRawTransaction:
    //   1. Decode RLP-encoded EVM transaction
    //   2. Validate signature, nonce range, gas price minimum
    //   3. Add to the Batcher's pending list
    //   4. Return EVM tx hash to caller immediately
    //
    // The Batcher flushes pending transactions to ProcessBatch when
    // either the target batch size (128 txs) is reached or the flush
    // timer expires (2s). The receipt becomes available in ChainDB
    // after the batch executes. Proving and BSV broadcast happen
    // asynchronously in the background.
    //
    // Users poll eth_getTransactionReceipt to get the receipt. The
    // typical wait is < 2 seconds (the Batcher's max flush delay).
    evmTx, err := DecodeTransaction(encodedTx)
    if err != nil {
        return Hash{}, err
    }
    if err := api.overlay.ValidateTransaction(evmTx); err != nil {
        return Hash{}, err
    }
    api.overlay.Batcher().Add(evmTx)
    return evmTx.Hash(), nil
}

func (api *EthAPI) GetLogs(filter FilterQuery) ([]*Log, error) {
    // Query the log index for matching logs
    // Filter by block range, addresses, topics
}
```

## Log Indexing

`eth_getLogs` requires efficient log querying. We need a bloom-based index:

```go
// pkg/rpc/log_index.go

type LogIndex struct {
    db db.Database
}

// IndexBlockLogs stores the logs from a block in the index.
func (idx *LogIndex) IndexBlockLogs(blockNumber uint64, blockHash Hash, logs []*Log) error {
    // Store logs keyed by:
    // - Block number
    // - Address (for address-filtered queries)
    // - Topic[0] (for event signature filtering)
}

// FilterLogs returns all logs matching the given filter criteria.
func (idx *LogIndex) FilterLogs(filter FilterQuery) ([]*Log, error) {
    // 1. Determine block range
    // 2. For each block, check bloom filter first (fast rejection)
    // 3. For bloom-matching blocks, scan actual logs
    // 4. Apply address + topic filters
}

type FilterQuery struct {
    FromBlock *big.Int
    ToBlock   *big.Int
    Addresses []Address
    Topics    [][]Hash // outer = position, inner = OR'd values
}
```

### Log Index Persistence

The log index is persisted to the same database backend as ChainDB
(LevelDB/Pebble). Log entries are written atomically with the block
they belong to — `WriteBlock` triggers `IndexBlockLogs`. On node
restart, the log index is already on disk and does not need to be
rebuilt from the chain.

If the log index becomes corrupted (e.g., unclean shutdown during a
write), it can be rebuilt by iterating all blocks from genesis and
re-indexing their logs. This is a repair operation, not the normal
startup path:

```go
func (idx *LogIndex) Rebuild(chainDB ChainDB) error {
    // Iterate all blocks from genesis to head
    // For each block, read receipts and index their logs
    // This is O(chain_length) and only needed after corruption
}
```

### Rollback-Aware Receipts

When blocks are rolled back (see spec 11, Rollback), their log index
entries are removed. Receipts for rolled-back transactions are updated
with a rollback marker:

```go
// ChainDB additions for rollback tracking
func (db ChainDB) MarkBlockRolledBack(blockNum uint64, rolledBackAtBlock uint64) error
func (db ChainDB) IsBlockRolledBack(blockNum uint64) (bool, uint64, error) // returns (rolledBack, rolledBackAtBlock)
```

When a client queries a receipt for a rolled-back transaction, the
receipt is returned with an additional non-standard field:

```json
{
    "status": "0x1",
    "rolledBack": true,
    "rolledBackAtBlock": "0x1a4"
}
```

Standard Ethereum fields remain unchanged. `rolledBack` is a non-standard
extension that aware clients can check. Unaware clients see a normal receipt.

### BSV Confirmation Status Extension

The receipt object includes a non-standard extension field
`bsvConfirmationStatus` that indicates the receipt's finality level in
the proof pipeline:

```json
{
    "status": "0x1",
    "blockNumber": "0x1a4",
    "bsvConfirmationStatus": "speculative"
}
```

Values:

| Status | Meaning |
|---|---|
| `"speculative"` | Executed locally, not yet proven. May be invalidated if this node loses the proving race (see spec 11, "Speculative Receipts"). |
| `"proven"` | STARK proof generated and BSV transaction broadcast. Cryptographically committed. Permanent unless BSV reorg. |
| `"confirmed"` | BSV transaction confirmed in at least 1 BSV block. |
| `"finalized"` | BSV transaction has >= 6 BSV confirmations. |

Standard Ethereum receipt fields remain unchanged. Wallets and dApps
that do not check `bsvConfirmationStatus` behave as they do today --
they see the receipt immediately and treat it as confirmed, which is
the same UX as Arbitrum or Optimism.

Wallets that DO check this field can display appropriate UI:
- `"speculative"`: Show a spinner or "pending" indicator.
- `"proven"`: Show "confirmed" (the proof guarantees correctness).
- `"finalized"`: Show "finalized" with a checkmark.

The block tags `latest`, `safe`, and `finalized` (defined in the Block
Tag Mapping section above) return receipts at the corresponding
confirmation level.

## WebSocket Subscriptions

```go
// pkg/rpc/ws_subscriptions.go

type SubscriptionManager struct {
    mu          sync.RWMutex
    subscribers map[string]*Subscription // subscription ID → subscriber
    
    // Channels fed by the block producer
    newHeadsCh chan *L2Header
    logsCh     chan []*Log
    pendingTxCh chan Hash
}

type Subscription struct {
    ID     string
    Type   string          // "newHeads", "logs"
    Filter *FilterQuery    // Only for "logs" subscriptions
    Conn   *websocket.Conn
    Done   chan struct{}
}

// Subscription limits (prevent resource exhaustion / DDoS):
//   - Max subscriptions per connection: 100
//   - Max event queue depth per subscription: 1,000 events
//   - Slow consumer timeout: 30 seconds (if queue is full and consumer
//     hasn't drained, drop oldest events)
//   - Max concurrent WebSocket connections: configurable, default 1,000
//
// Config:
//   [rpc]
//   ws_max_connections = 1000
//   ws_max_subscriptions_per_conn = 100
//   ws_event_queue_depth = 1000
//   ws_slow_consumer_timeout = "30s"

func (sm *SubscriptionManager) HandleSubscribe(conn *websocket.Conn, subType string, params json.RawMessage) (string, error) {
    sub := &Subscription{
        ID:   generateSubID(),
        Type: subType,
        Conn: conn,
        Done: make(chan struct{}),
    }
    
    if subType == "logs" {
        var filter FilterQuery
        json.Unmarshal(params, &filter)
        sub.Filter = &filter
    }
    
    sm.mu.Lock()
    sm.subscribers[sub.ID] = sub
    sm.mu.Unlock()
    
    go sm.feedSubscription(sub)
    
    return sub.ID, nil
}
```

## JSON-RPC Transport

Support both HTTP and WebSocket:

```go
// pkg/rpc/transport.go

// HTTP handler
func (s *RPCServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
    // 1. Read JSON-RPC request body
    // 2. Parse method + params
    // 3. Route to appropriate API method
    // 4. Return JSON-RPC response
    // Support batch requests (array of requests)
}

// WebSocket handler
func (s *RPCServer) handleWS(w http.ResponseWriter, r *http.Request) {
    // 1. Upgrade to WebSocket
    // 2. Read JSON-RPC requests in a loop
    // 3. Route to API methods (including eth_subscribe)
    // 4. Push subscription events
}
```

## Encoding Compatibility

We must use the exact same hex encoding conventions as Ethereum:
- All quantities encoded as hex strings with "0x" prefix
- No leading zeros (except "0x0" for zero)
- Block numbers accept "latest", "earliest", "pending", "safe", "finalized"
  mapped to BSV confirmation depth (see below)
- Addresses are 20-byte hex with EIP-55 checksum capitalization

```go
// pkg/rpc/encoding.go

type BlockNumberOrHash struct {
    BlockNumber *big.Int
    BlockHash   *Hash
    RequireCanonical bool
}

// UnmarshalJSON handles "latest", "earliest", "pending", hex numbers, and {blockHash: ...}
func (b *BlockNumberOrHash) UnmarshalJSON(data []byte) error { ... }
```

### Block Tag Mapping

The standard Ethereum block tags map to the overlay node's chain tips
and BSV confirmation depth. These definitions are authoritative —
spec 12 defers to this section for block tag semantics.

```
"latest"    → Execution tip (most recent executed L2 block, may be unproven)
"safe"      → Proven tip: last L2 block with a completed SP1 proof broadcast to BSV
              (may have 0 BSV confirmations — "safe" means "proven correct")
"finalized" → Last L2 block whose covenant-advance BSV tx has ≥6 BSV confirmations
"earliest"  → Genesis block (L2 block 0)
"pending"   → Same as "latest" (no separate pending state)
```

**Rationale**: On Ethereum mainnet, "safe" means ≥2/3 of validators
attested. On our L2, "safe" means a STARK proof of correct execution
exists and has been broadcast to BSV — this is a stronger guarantee
than attestation. "Finalized" adds BSV reorg protection (6 confirmations
≈ 1 hour). DApps that wait for "finalized" are protected against BSV
reorgs. DApps using "safe" trust the STARK proof but accept BSV reorg
risk (negligible in practice).

```go
const (
    ConfirmationsFinalized = 6  // At least 6 BSV confirmations
)
```

The overlay node tracks three chain tips:
- `ExecutionTip`: latest executed L2 block number
- `ProvenTip`: latest L2 block with completed SP1 proof broadcast to BSV
- `FinalizedTip`: latest L2 block with ≥6 BSV confirmations

```go
func (api *EthAPI) resolveBlockTag(tag string) (uint64, error) {
    switch tag {
    case "latest", "pending":
        return api.overlay.ExecutionTip(), nil
    case "safe":
        return api.overlay.ProvenTip(), nil
    case "finalized":
        return api.overlay.FinalizedTip(), nil
    case "earliest":
        return 0, nil
    default:
        return parseHexUint64(tag)
    }
}
```

DApps that check `finalized` before displaying balances will naturally
wait for BSV confirmation depth. DApps using `latest` will see immediate
results with the understanding that a BSV reorg (extremely unlikely)
could invalidate unconfirmed state.

### Receipt Stability During Speculative Execution

Receipts returned for transactions in speculative (unproven) blocks may change if the block is re-executed during cascade rollback (Spec 11). Specifically:

- `blockHash`, `transactionIndex`, `gasUsed`, `cumulativeGasUsed`, `logs`, and `status` may all change.
- Transactions may be dropped entirely if they fail re-execution after state changes.

The RPC layer does NOT retroactively notify clients of receipt changes. Clients that require stability should:
1. Query only `safe` or `finalized` block tags.
2. Poll `eth_getTransactionReceipt` until the block reaches `safe` (proven) status.

The `latest` tag returns the execution tip, which is speculative. The `safe` tag returns the proven tip. The `finalized` tag returns the last block with >= `ConfirmationsFinalized` (6) BSV confirmations.

## TransactionArgs (for eth_call and eth_estimateGas)

```go
// pkg/rpc/args.go

type TransactionArgs struct {
    From     *Address      `json:"from"`
    To       *Address      `json:"to"`
    Gas      *hexutil.Uint64 `json:"gas"`
    GasPrice *hexutil.Big  `json:"gasPrice"`
    MaxFeePerGas *hexutil.Big `json:"maxFeePerGas"`
    MaxPriorityFeePerGas *hexutil.Big `json:"maxPriorityFeePerGas"`
    Value    *hexutil.Big  `json:"value"`
    Data     *hexutil.Bytes `json:"data"`
    Input    *hexutil.Bytes `json:"input"` // alias for data
    Nonce    *hexutil.Uint64 `json:"nonce"`
    AccessList *AccessList `json:"accessList"`
    ChainID  *hexutil.Big  `json:"chainId"`
}
```

## Deliverables

1. `pkg/rpc/server.go` — HTTP + WebSocket RPC server
2. `pkg/rpc/eth_api.go` — `eth_*` method implementations
3. `pkg/rpc/net_api.go` — `net_*` methods
4. `pkg/rpc/web3_api.go` — `web3_*` methods
5. `pkg/rpc/log_index.go` — Log indexing and `eth_getLogs` support
6. `pkg/rpc/ws_subscriptions.go` — WebSocket subscription manager
7. `pkg/rpc/encoding.go` — Hex encoding, BlockNumberOrHash, etc.
8. `pkg/rpc/args.go` — Request argument types

## Acceptance Criteria

- [ ] MetaMask can connect, display chain ID, show balances
- [ ] ethers.js can send transactions and query receipts
- [ ] Hardhat `npx hardhat test` works against local L2 node
- [ ] `eth_call` returns correct results for view function calls
- [ ] `eth_estimateGas` returns usable gas estimates
- [ ] `eth_getLogs` correctly filters by address, topics, and block range
- [ ] WebSocket `newHeads` subscription receives new block headers in real-time
- [ ] WebSocket `logs` subscription receives matching events in real-time
- [ ] Batch JSON-RPC requests are supported
- [ ] Error codes match Ethereum conventions (-32600, -32601, -32602, -32603, -32000)
