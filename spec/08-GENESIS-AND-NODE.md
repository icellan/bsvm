# Genesis Configuration & Node Startup

## Goal
Define the per-shard genesis state, chain configuration, and the main node binary that ties all components together.

## Shard Genesis

Genesis creates a new shard:
1. Choose a chain ID (unique per shard)
2. Define genesis allocations (predeploy bridge contract, initial balances)
3. Initialize local state DB with genesis state → compute genesis state root
4. Compile the Rúnar covenant (STARK verifier + state management)
5. Create and broadcast the genesis BSV transaction:
   - Output 0: covenant UTXO with genesis state root
   - Output 1: OP_RETURN with shard config (chain ID, genesis hash, etc.)
6. Create and broadcast the bridge covenant genesis UTXO
7. Store genesis covenant txid in local config

The `bsvm init` command does all of this.

## Node Startup

The `bsvm run` command starts a node that joins an existing shard:

1. Load shard config (chain ID, genesis covenant txid)
2. Open local state DB
3. Sync state: replay the covenant UTXO chain from BSV to catch up
   - Read each covenant-advance tx from BSV
   - Extract batch data from OP_RETURN
   - Re-execute EVM transactions to rebuild local state
   - Verify state roots match the covenant chain
4. Start `OverlayNode` (execute, prove, advance)
5. Start `NetworkManager` (connect to peer nodes in the shard)
6. Start `DoubleSpendMonitor`
7. Start `RPCServer`

## Genesis Block

The genesis block defines the initial state of the L2 chain:

```go
// pkg/block/genesis.go

type Genesis struct {
    Config       *vm.ChainConfig            `json:"config"`
    HashFunction string                     `json:"hashFunction"` // "keccak256" (only valid value; SP1's keccak256 precompile makes alternatives unnecessary)
    Timestamp    uint64                     `json:"timestamp"`
    GasLimit     uint64                     `json:"gasLimit"`
    Coinbase     Address                    `json:"coinbase"`
    Alloc        map[Address]GenesisAccount `json:"alloc"`
    
    // Bridge config
    BridgeAddress Address              `json:"bridgeAddress"`
    
    // Governance config — determines the shard's trust model
    Governance   GovernanceConfig       `json:"governance"`
    
    // BSV anchor genesis
    BSVAnchorTxID Hash                 `json:"bsvAnchorTxId,omitempty"` // BSV tx that establishes the L2
}

type GenesisAccount struct {
    Code    []byte                    `json:"code,omitempty"`
    Storage map[Hash]Hash             `json:"storage,omitempty"`
    Balance *uint256.Int              `json:"balance"`
    Nonce   uint64                    `json:"nonce,omitempty"`
}
```

### Default Genesis

```json
{
  "config": {
    "chainId": 8453111,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "shanghaiTime": 0,
    "cancunTime": 0,
    "pragueTime": 0
  },
  "timestamp": 0,
  "gasLimit": 30000000,
  "governance": {
    "mode": "none"
  },
  "alloc": {
    "0x4200000000000000000000000000000000000010": {
      "code": "0x...",
      "storage": {},
      "balance": "0x0"
    }
  }
}
```

**Chain ID**: Pick a unique chain ID and register it at chainlist.org.
Suggested format: start with something memorable that isn't taken.

**WARNING: Chain ID uniqueness is critical for security.** If two
shards share the same chain ID, EIP-155 replay protection fails —
a signed transaction on Shard A can be replayed on Shard B. The
`bsvm init` command SHOULD query chainlist.org to verify the
chosen chain ID is not already registered. Until the on-chain shard
registry (spec 09, Milestone 10) is deployed, uniqueness is
enforced only by convention. Shard creators MUST verify manually.

### Prover Bootstrap

**Prover bootstrap**: The shard creator must fund the prover node's
BSV wallet with enough satoshis to cover initial covenant advance fees.
At 100 sats/KB and ~200KB per advance, each advance costs ~20,000 sats.
A bootstrap fund of 0.01 BSV (1,000,000 sats) funds ~50 advances.

The prover earns wBSV on L2 as coinbase fees from gas. Periodically,
the prover withdraws accumulated wBSV via the bridge to replenish the
BSV operating wallet.

No genesis allocation of wBSV to the prover is needed or created.
The prover's L2 coinbase balance starts at zero and grows from gas fees.

### Genesis Initialization

```go
func InitGenesis(db db.Database, genesis *Genesis) (*L2Header, error) {
    // 1. Create empty state
    statedb, err := state.New(EmptyRootHash, db)
    if err != nil {
        return nil, err
    }
    
    // 2. Apply genesis allocations
    for addr, account := range genesis.Alloc {
        statedb.CreateAccount(addr)
        statedb.SetBalance(addr, account.Balance)
        statedb.SetNonce(addr, account.Nonce)
        if len(account.Code) > 0 {
            statedb.SetCode(addr, account.Code)
        }
        for key, value := range account.Storage {
            statedb.SetState(addr, key, value)
        }
    }
    
    // 3. Commit state → get genesis state root
    stateRoot, err := statedb.Commit(false)
    if err != nil {
        return nil, err
    }
    
    // 4. Create genesis header
    // Coinbase is explicitly set to the zero address for genesis.
    // No transactions execute in the genesis block, so no gas fees
    // are credited. The zero address is a burn address — any accidental
    // value sent to it is irrecoverable.
    header := &L2Header{
        ParentHash: Hash{},
        Coinbase:   Address{}, // Zero address — no coinbase recipient for genesis
        StateRoot:  stateRoot,
        Number:     big.NewInt(0),
        GasLimit:   genesis.GasLimit,
        Timestamp:  genesis.Timestamp,
        BaseFee:    big.NewInt(0),
    }
    
    // 5. Store genesis block
    // ...
    
    return header, nil
}
```

## Node Configuration

```go
// cmd/bsvm/config.go

type NodeConfig struct {
    // Chain
    DataDir    string          `toml:"datadir"`
    Genesis    string          `toml:"genesis"`    // Path to genesis.json
    
    // Shard
    Shard      ShardConfig     `toml:"shard"`
    
    // Overlay
    Overlay    OverlayConfig   `toml:"overlay"`
    
    // Network
    Network    NetworkConfig   `toml:"network"`
    
    // Prover
    Prover     ProverConfig    `toml:"prover"`
    
    // RPC
    RPC        RPCConfig       `toml:"rpc"`
    
    // BSV
    BSV        BSVConfig       `toml:"bsv"`
    
    // Bridge
    Bridge     BridgeConfig    `toml:"bridge"`
    
    // Governance
    Governance GovernanceConfig `toml:"governance"`
    
    // Database
    DB         DBConfig        `toml:"database"`
    
    // Logging
    LogLevel   string          `toml:"log_level"` // debug, info, warn, error
    LogFormat  string          `toml:"log_format"` // json, text
}

type ShardConfig struct {
    ChainID              int64  `toml:"chain_id"`
    GenesisCovenantTxID  string `toml:"genesis_covenant_txid"`
    GenesisCovenantVout  uint32 `toml:"genesis_covenant_vout"`
    CovenantSats         uint64 `toml:"covenant_sats"`
}

type OverlayConfig struct {
    Coinbase              string `toml:"coinbase"`                // L2 fee recipient address
    BlockGasLimit         uint64 `toml:"block_gas_limit"`
    BatchSize             int    `toml:"batch_size"`              // EVM txs per L2 block
    MaxBatchFlushDelay    string `toml:"max_batch_flush_delay"`   // e.g., "200ms"
    // MaxBatchFlushDelay is NOT a block production timer. It only fires
    // when there are pending transactions. If no transactions arrive,
    // nothing happens. Empty batches are never produced.
}

type NetworkConfig struct {
    ListenAddr     string   `toml:"listen_addr"`     // libp2p multiaddr format: "/ip4/0.0.0.0/tcp/9945"
    BootstrapPeers []string `toml:"bootstrap_peers"` // libp2p multiaddr format with peer ID
    MaxPeers       int      `toml:"max_peers"`
}

type ProverConfig struct {
    Workers int `toml:"workers"` // Parallel proving goroutines
}

type BSVConfig struct {
    NodeURL        string `toml:"node_url"`
    ARCURL         string `toml:"arc_url"`
    Network        string `toml:"network"`       // mainnet, testnet, regtest
    FeeWalletKey   string `toml:"fee_wallet_key"` // Path to WIF key file for miner fee funding
                                                    // The fee wallet has no covenant authority —
                                                    // it only signs fee-funding inputs.
    // Fee wallet security: This key does NOT control the covenant state
    // or the bridge — it only pays BSV mining fees. If compromised:
    //   - The attacker can spend the prover's BSV balance (operational funds, not user funds)
    //   - The attacker cannot advance the covenant (needs a valid STARK proof)
    //   - The attacker cannot access bridge funds or modify L2 state
    // Mitigation: use a dedicated hot wallet with a small balance. Refill from
    // bridge withdrawals. Key rotation: generate a new key, update config, restart node.
    // For production deployments, consider HSM or threshold signing.
    Confirmations  int    `toml:"confirmations"`
}

type BridgeConfig struct {
    MinDeposit     uint64 `toml:"min_deposit_satoshis"`
    MinWithdrawal  uint64 `toml:"min_withdrawal_satoshis"`
    BSVConfirmations int  `toml:"bsv_confirmations"` // Confirmations before withdrawal release
}

type DBConfig struct {
    Engine    string `toml:"engine"` // "leveldb" or "pebble"
    CacheSize int    `toml:"cache_mb"`
}
```

### Example config file (`bsvm.toml`)

```toml
datadir = "/data/bsvm"
genesis = "/data/bsvm/genesis.json"
log_level = "info"
log_format = "json"

[shard]
chain_id = 8453111
genesis_covenant_txid = "abc123..."   # Set after `bsvm init`
genesis_covenant_vout = 0
covenant_sats = 10000

[overlay]
coinbase = "0xYOUR_L2_ADDRESS"         # L2 address for coinbase fees
gas_price_gwei = 1                     # Minimum gas price in gwei
block_gas_limit = 30000000
batch_size = 100                       # EVM txs per L2 block
max_batch_flush_delay = "200ms"       # NOT a block production timer — only fires
                                       # when pending txs exist. No empty batches.
min_profitable_batch_gas = 200000      # Don't advance covenant unless
                                       # batch gas exceeds this (anti-loss)

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9945"          # libp2p multiaddr format
bootstrap_peers = [
    "/ip4/1.2.3.4/tcp/9945/p2p/QmPeerID1",     # libp2p multiaddr with peer ID
    "/ip4/5.6.7.8/tcp/9945/p2p/QmPeerID2",
]
max_peers = 50

[prover]
workers = 4                            # Parallel proving goroutines

[rpc]
http_addr = "0.0.0.0:8545"
ws_addr = "0.0.0.0:8546"
cors_origins = ["*"]

[bsv]
node_url = "http://localhost:8332"
arc_url = "https://arc.taal.com"
network = "mainnet"
confirmations = 6

[governance]
mode = "none"                      # "none", "single_key", or "multisig"
# keys = ["02abc...", "03def..."]  # Hex-encoded compressed public keys
# threshold = 3                    # M-of-N (multisig only)

[bridge]
# No challenge period — STARK proofs guarantee correctness.
# bsv_confirmations protects against BSV reorgs only.
min_deposit_satoshis = 10000
min_withdrawal_satoshis = 10000

[database]
engine = "leveldb"
cache_mb = 512
```

Note: There is no `[sequencer]` section, no `block_interval`, no `empty_blocks`,
and no `sequencer_key_file`. There is no sequencer key.

## Main Node Binary

```go
// cmd/bsvm/main.go

func main() {
    app := &cli.App{
        Name:  "bsvm",
        Usage: "BSVM Layer 2 Node",
        Commands: []*cli.Command{
            {
                Name:  "init",
                Usage: "Initialize a new L2 chain from genesis",
                Action: initGenesis,
            },
            {
                Name:  "run",
                Usage: "Start the L2 node",
                Action: runNode,
            },
            {
                Name:  "recover",
                Usage: "Recover shard state from BSV covenant chain (disaster recovery)",
                Flags: []cli.Flag{
                    &cli.StringFlag{Name: "genesis-txid", Required: true, Usage: "Genesis covenant transaction ID"},
                    &cli.StringFlag{Name: "datadir", Required: true, Usage: "Data directory for recovered state"},
                },
                Action: recoverFromBSV,
            },
            {
                Name:  "version",
                Usage: "Print version information",
                Action: printVersion,
            },
        },
    }
    app.Run(os.Args)
}

func runNode(ctx *cli.Context) error {
    // 1. Load config
    config := loadConfig(ctx)
    
    // 2. Open database
    database := openDB(config.DB)
    
    // 3. Load chain state
    chainDB := block.NewChainDB(database)
    headHash := chainDB.ReadHeadBlockHash()
    headHeader := chainDB.ReadHeaderByHash(headHash)
    
    // 4. Initialize components
    stateDB, _ := state.New(headHeader.StateRoot, database)
    bsvClient := bsv.NewRPCClient(config.BSV)
    feeWallet := covenant.NewFeeWallet(config.BSV.FeeWalletKey, bsvClient)
    
    covenantMgr := covenant.NewCovenantManager(bsvClient, feeWallet, config.Shard)
    prover := prover.NewParallelProver(config.Prover.Workers)
    
    overlayNode := overlay.NewOverlayNode(
        config.Overlay, chainDB, stateDB, covenantMgr, bsvClient, prover,
    )
    
    dsMonitor := overlay.NewDoubleSpendMonitor(bsvClient, overlayNode)
    networkMgr := network.NewManager(config.Network, overlayNode)
    bridgeMon := bridge.NewBridgeMonitor(config.Bridge, bsvClient, overlayNode)
    
    rpcServer := rpc.NewRPCServer(config.RPC, chainDB, stateDB, overlayNode)
    
    // 5. Sync state from BSV covenant chain (if behind)
    if err := overlayNode.SyncFromBSV(config.Shard.GenesisCovenantTxID); err != nil {
        return fmt.Errorf("state sync failed: %w", err)
    }
    
    // 6. Start all services
    gctx, cancel := context.WithCancel(context.Background())
    g, gctx := errgroup.WithContext(gctx)
    
    g.Go(func() error { return overlayNode.Run(gctx) })
    g.Go(func() error { return dsMonitor.Run(gctx) })
    g.Go(func() error { return networkMgr.Run(gctx) })
    g.Go(func() error { return bridgeMon.Run(gctx) })
    g.Go(func() error { return prover.Run(gctx) })
    g.Go(func() error { return rpcServer.Start() })
    
    // 7. Wait for shutdown signal
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    
    <-sigCh
    slog.Info("shutting down...")
    cancel()
    
    // 8. Graceful shutdown
    rpcServer.Stop()
    if err := g.Wait(); err != nil && err != context.Canceled {
        slog.Error("service error during shutdown", "err", err)
    }
    database.Close()
    
    return nil
}

// recoverFromBSV reconstructs the complete shard state from BSV data alone.
// This is the disaster recovery procedure — it works even with zero peer
// nodes available. BSV is the only input.
//
// Steps:
//   1. Walk the BSV covenant UTXO chain from genesis txid
//   2. For each covenant-advance tx, extract batch data from OP_RETURN
//   3. Decode and re-execute all EVM transactions
//   4. Verify computed state roots match the covenant chain
//   5. Produce a fully synced local state DB
//   6. Node is ready to resume normal operation via `bsvm run`
func recoverFromBSV(ctx *cli.Context) error {
    // Implementation delegates to overlay.SyncFromBSV with the genesis txid
}
```

## CLI Tool (debugging)

```go
// cmd/evm-cli/main.go
// Standalone EVM execution tool for debugging

// Usage:
//   evm-cli run --code 0x6060... --input 0x... --gas 1000000
//   evm-cli run --codefile contract.bin --input 0x... --gas 1000000
//   evm-cli disasm --code 0x6060...
//   evm-cli state --datadir /data/bsvm --address 0x...
```

## Deliverables

1. `cmd/bsvm/main.go` — Main node binary
2. `cmd/bsvm/config.go` — Configuration loading
3. `cmd/evm-cli/main.go` — CLI debugging tool
4. `pkg/block/genesis.go` — Genesis initialization
5. `genesis.json` — Default genesis configuration
6. `bsvm.toml.example` — Example configuration file
7. `Dockerfile` — Container image
8. `Makefile` — Build targets

## Governance Configuration

The governance mode is a critical security decision made at genesis.
It cannot be changed after the shard is created (it is embedded in the
covenant script as compile-time properties).

### Trade-offs

| Mode | Trust | Recoverability | Recommended For |
|------|-------|----------------|-----------------|
| `none` | Fully trustless | No recovery from bugs | Battle-tested, audited covenants |
| `single_key` | Trust one operator | Full recovery | Development, testing, single-operator |
| `multisig` | Trust M-of-N holders | Recovery with quorum | Production shards with significant TVL |

**`none`**: Fully trustless. No freeze, no upgrade, no recovery. If the
FRI verifier has a bug, the shard is permanently compromised. The only
upgrade path is the proof-authorized `migrate` method (spec 09,
Milestone 10), which requires a valid STARK proof of the current state.
Recommended only after the covenant code is battle-tested and formally
verified.

**`single_key`**: Single operator control. Can freeze, upgrade, and
unfreeze. Maximum flexibility. Maximum trust in one party. The operator
can pause the shard at any time and replace the covenant script. Suitable
for development, testing, and single-operator shards where the operator
is trusted by all users.

**`multisig`**: Distributed governance. M-of-N keys required for all
governance operations. No single key holder can act unilaterally.
Recommended for production shards holding significant value. Balances
recoverability with trust distribution. Example: 3-of-5 multisig held
by reputable, geographically distributed entities.

The governance config is included in the genesis OP_RETURN (message
type `0x01`) so all nodes and users know the shard's trust model from
genesis. The `bsv_shardInfo` RPC method (spec 05) exposes the
governance mode and frozen status for programmatic access.

## Shard Bootstrap Procedure

### Creating a new shard (`bsvm init`)

1. **Choose parameters**:
   - Chain ID (unique, register at chainlist.org)
   - Hash function: keccak256 (SP1's precompile makes this efficient to prove)
   - SP1 parameters (security level, proving mode: local or network)
   - Gas price (in gwei)
   - Bridge configuration (min deposit, withdrawal tiers)
   - Governance mode (`none`, `single_key`, or `multisig`) and keys

2. **Build SP1 guest program and generate verifying key**:
   - Compile the Rust revm guest program for SP1 (`cargo prove build`)
   - The SP1 verifying key is derived deterministically from the guest ELF
   - No trusted setup — anyone can rebuild the guest and verify the key
   - Store guest ELF and verifying key in shard config

3. **Compile the covenant**:
   - Import `runar-go`
   - Compile `RollupContract(sp1VerifyingKey, chainID, governanceConfig)` to Bitcoin Script
   - Compile `BridgeCovenant()` to Bitcoin Script
   - Compile `InboxCovenant()` to Bitcoin Script (if forced inclusion enabled)
   - Save ANF artifacts for audit
   - Cross-verify with Rust/TS Runar compiler if available

4. **Initialize L2 genesis state**:
   - Create genesis.json with config, allocations, bridge predeploy
   - Initialize local StateDB with genesis state
   - Compute genesis state root

5. **Fund the genesis**:
   - Prover provides a BSV UTXO with sufficient satoshis:
     - Covenant UTXO: 10,000 sats (carried forward permanently)
     - Bridge sub-covenants: 10,000 sats each (N sub-covenants)
     - Inbox covenant: 10,000 sats (if enabled)
     - Prover operating balance: >=1,000,000 sats recommended
   - Total: ~0.05 BSV minimum

6. **Broadcast genesis transactions**:
   - BSV tx 1: create state covenant UTXO (output 0 = covenant,
     output 1 = OP_RETURN with genesis config)
   - BSV tx 2: create bridge covenant UTXOs
   - BSV tx 3: create inbox covenant UTXO (if enabled)
   - Record all txids in shard config

   **Funding key lifecycle**: The funding key (used to sign the genesis transactions above) is used SOLELY for the genesis covenant creation transaction. After the genesis UTXO is confirmed on BSV, the funding key has NO further role -- it cannot advance, modify, or control the covenant in any way. Operators SHOULD discard or archive the key after genesis. The covenant is governed exclusively by STARK proofs from that point forward.

7. **Write shard config**:
   ```toml
   [shard]
   chain_id = 8453111
   genesis_covenant_txid = "abc123..."
   genesis_bridge_txids = ["def456...", "ghi789..."]
   genesis_inbox_txid = "jkl012..."
   sp1_guest_elf = "guest.elf"
   sp1_verifying_key = "vk.bin"
   hash_function = "keccak256"
   governance_mode = "multisig"
   governance_keys = ["02abc...", "03def...", "04ghi...", "05jkl...", "06mno..."]
   governance_threshold = 3
   ```

8. **Start the first node**: `bsvm run` reads shard config. Node is
   ready to process transactions.

### Joining an existing shard (`bsvm run` on a new machine)

1. Obtain the shard config file from an existing operator
2. Run `bsvm run --config shard.toml`
3. Node syncs by replaying the covenant chain from BSV (spec 11)
4. Once synced, node connects to peers and begins participating

## Acceptance Criteria

- [ ] `bsvm init` creates a new chain from genesis.json
- [ ] `bsvm run` starts all services and begins producing blocks
- [ ] Node survives restart and resumes from last committed state
- [ ] Graceful shutdown commits pending state and closes DB cleanly
- [ ] Configuration via both file and CLI flags
- [ ] Docker image builds and runs
