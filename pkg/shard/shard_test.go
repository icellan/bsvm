package shard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const testChainID = int64(8453111)

// testKey returns a fake 33-byte compressed public key with the given seed.
func testKey(seed byte) []byte {
	key := make([]byte, 33)
	key[0] = 0x02
	key[1] = seed
	h := sha256.Sum256([]byte{seed})
	copy(key[2:], h[:31])
	return key
}

// testStateRoot returns a deterministic hash for testing.
func testStateRoot() types.Hash {
	h := sha256.Sum256([]byte("test-state-root"))
	return types.BytesToHash(h[:])
}

// validConfig returns a minimal valid ShardConfig for testing.
func validConfig() *ShardConfig {
	return &ShardConfig{
		ChainID:             testChainID,
		ShardID:             "abc123",
		GenesisCovenantTxID: "abc123",
		GenesisCovenantVout: 0,
		CovenantSats:        10000,
		SP1VerifyingKey:     hex.EncodeToString([]byte("test-vk")),
		GovernanceMode:      "none",
		VerificationMode:    "groth16",
		GenesisStateRoot:    testStateRoot().Hex(),
		HashFunction:        "keccak256",
	}
}

// initGenesisDB creates a MemoryDB with genesis state and returns the
// genesis state root and the database.
func initGenesisDB(t *testing.T) (db.Database, types.Hash) {
	t.Helper()
	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     make(map[types.Address]block.GenesisAccount),
	}
	header, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}
	return database, header.StateRoot
}

// ---------------------------------------------------------------------------
// TestShardConfigValidation
// ---------------------------------------------------------------------------

func TestShardConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*ShardConfig)
		wantErr string
	}{
		{
			name:   "valid config",
			modify: func(c *ShardConfig) {},
		},
		{
			name:    "missing chain ID",
			modify:  func(c *ShardConfig) { c.ChainID = 0 },
			wantErr: "chain ID must not be zero",
		},
		{
			name:    "missing covenant txid",
			modify:  func(c *ShardConfig) { c.GenesisCovenantTxID = "" },
			wantErr: "genesis covenant txid must not be empty",
		},
		{
			name:    "invalid governance mode",
			modify:  func(c *ShardConfig) { c.GovernanceMode = "invalid" },
			wantErr: "governance mode must be none, single_key, or multisig",
		},
		{
			name: "governance none with keys",
			modify: func(c *ShardConfig) {
				c.GovernanceMode = "none"
				c.GovernanceKeys = []string{"02abcdef"}
			},
			wantErr: "governance mode none must have no keys",
		},
		{
			name: "governance none with threshold",
			modify: func(c *ShardConfig) {
				c.GovernanceMode = "none"
				c.GovernanceThreshold = 1
			},
			wantErr: "governance mode none must have threshold 0",
		},
		{
			name: "single_key missing key",
			modify: func(c *ShardConfig) {
				c.GovernanceMode = "single_key"
				c.GovernanceKeys = nil
			},
			wantErr: "governance mode single_key requires exactly 1 key",
		},
		{
			name: "single_key with threshold",
			modify: func(c *ShardConfig) {
				c.GovernanceMode = "single_key"
				c.GovernanceKeys = []string{hex.EncodeToString(testKey(1))}
				c.GovernanceThreshold = 1
			},
			wantErr: "governance mode single_key must have threshold 0",
		},
		{
			name: "multisig too few keys",
			modify: func(c *ShardConfig) {
				c.GovernanceMode = "multisig"
				c.GovernanceKeys = []string{hex.EncodeToString(testKey(1))}
				c.GovernanceThreshold = 1
			},
			wantErr: "governance mode multisig requires at least 2 keys",
		},
		{
			name: "multisig threshold too high",
			modify: func(c *ShardConfig) {
				c.GovernanceMode = "multisig"
				c.GovernanceKeys = []string{
					hex.EncodeToString(testKey(1)),
					hex.EncodeToString(testKey(2)),
				}
				c.GovernanceThreshold = 5
			},
			wantErr: "governance mode multisig threshold 5 exceeds key count 2",
		},
		{
			name: "multisig zero threshold",
			modify: func(c *ShardConfig) {
				c.GovernanceMode = "multisig"
				c.GovernanceKeys = []string{
					hex.EncodeToString(testKey(1)),
					hex.EncodeToString(testKey(2)),
				}
				c.GovernanceThreshold = 0
			},
			wantErr: "governance mode multisig threshold must be at least 1",
		},
		{
			name:    "missing verification mode",
			modify:  func(c *ShardConfig) { c.VerificationMode = "" },
			wantErr: "verification mode must not be empty",
		},
		{
			name:    "invalid verification mode",
			modify:  func(c *ShardConfig) { c.VerificationMode = "blake3" },
			wantErr: "verification mode must be groth16 or basefold",
		},
		{
			name:    "missing hash function",
			modify:  func(c *ShardConfig) { c.HashFunction = "" },
			wantErr: "hash function must not be empty",
		},
		{
			name:    "invalid hash function",
			modify:  func(c *ShardConfig) { c.HashFunction = "sha256" },
			wantErr: "hash function must be keccak256",
		},
		{
			name:    "missing genesis state root",
			modify:  func(c *ShardConfig) { c.GenesisStateRoot = "" },
			wantErr: "genesis state root must not be empty",
		},
		{
			name:    "empty governance mode",
			modify:  func(c *ShardConfig) { c.GovernanceMode = "" },
			wantErr: "governance mode must not be empty",
		},
		{
			name: "shard ID does not match genesis covenant txid",
			modify: func(c *ShardConfig) {
				c.ShardID = "different-id"
				c.GenesisCovenantTxID = "abc123"
			},
			wantErr: "shard ID must equal genesis covenant txid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if got := err.Error(); !containsStr(got, tt.wantErr) {
				t.Fatalf("error %q does not contain %q", got, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestShardConfigSaveLoad
// ---------------------------------------------------------------------------

func TestShardConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shard.json")

	original := validConfig()
	original.BootstrapPeers = []string{"/ip4/1.2.3.4/tcp/9945/p2p/QmTest"}
	original.SP1GuestELF = "/path/to/guest.elf"
	original.CovenantSats = 20000

	if err := original.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.ChainID != original.ChainID {
		t.Errorf("ChainID: got %d, want %d", loaded.ChainID, original.ChainID)
	}
	if loaded.ShardID != original.ShardID {
		t.Errorf("ShardID: got %q, want %q", loaded.ShardID, original.ShardID)
	}
	if loaded.GenesisCovenantTxID != original.GenesisCovenantTxID {
		t.Errorf("GenesisCovenantTxID: got %q, want %q", loaded.GenesisCovenantTxID, original.GenesisCovenantTxID)
	}
	if loaded.GenesisCovenantVout != original.GenesisCovenantVout {
		t.Errorf("GenesisCovenantVout: got %d, want %d", loaded.GenesisCovenantVout, original.GenesisCovenantVout)
	}
	if loaded.CovenantSats != original.CovenantSats {
		t.Errorf("CovenantSats: got %d, want %d", loaded.CovenantSats, original.CovenantSats)
	}
	if loaded.SP1VerifyingKey != original.SP1VerifyingKey {
		t.Errorf("SP1VerifyingKey: got %q, want %q", loaded.SP1VerifyingKey, original.SP1VerifyingKey)
	}
	if loaded.GovernanceMode != original.GovernanceMode {
		t.Errorf("GovernanceMode: got %q, want %q", loaded.GovernanceMode, original.GovernanceMode)
	}
	if loaded.VerificationMode != original.VerificationMode {
		t.Errorf("VerificationMode: got %q, want %q", loaded.VerificationMode, original.VerificationMode)
	}
	if loaded.GenesisStateRoot != original.GenesisStateRoot {
		t.Errorf("GenesisStateRoot: got %q, want %q", loaded.GenesisStateRoot, original.GenesisStateRoot)
	}
	if loaded.HashFunction != original.HashFunction {
		t.Errorf("HashFunction: got %q, want %q", loaded.HashFunction, original.HashFunction)
	}
	if loaded.SP1GuestELF != original.SP1GuestELF {
		t.Errorf("SP1GuestELF: got %q, want %q", loaded.SP1GuestELF, original.SP1GuestELF)
	}
	if len(loaded.BootstrapPeers) != len(original.BootstrapPeers) {
		t.Errorf("BootstrapPeers length: got %d, want %d", len(loaded.BootstrapPeers), len(original.BootstrapPeers))
	} else {
		for i := range loaded.BootstrapPeers {
			if loaded.BootstrapPeers[i] != original.BootstrapPeers[i] {
				t.Errorf("BootstrapPeers[%d]: got %q, want %q", i, loaded.BootstrapPeers[i], original.BootstrapPeers[i])
			}
		}
	}

	// DataDir should NOT be serialized.
	if loaded.DataDir != "" {
		t.Errorf("DataDir should not be serialized, got %q", loaded.DataDir)
	}
}

// ---------------------------------------------------------------------------
// TestShardConfigGovernanceConversion
// ---------------------------------------------------------------------------

func TestShardConfigGovernanceConversion(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		keys      []string
		threshold int
		wantMode  covenant.GovernanceMode
		wantKeys  int
	}{
		{
			name:     "none",
			mode:     "none",
			wantMode: covenant.GovernanceNone,
			wantKeys: 0,
		},
		{
			name:     "single_key",
			mode:     "single_key",
			keys:     []string{hex.EncodeToString(testKey(1))},
			wantMode: covenant.GovernanceSingleKey,
			wantKeys: 1,
		},
		{
			name: "multisig",
			mode: "multisig",
			keys: []string{
				hex.EncodeToString(testKey(1)),
				hex.EncodeToString(testKey(2)),
				hex.EncodeToString(testKey(3)),
			},
			threshold: 2,
			wantMode:  covenant.GovernanceMultiSig,
			wantKeys:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.GovernanceMode = tt.mode
			cfg.GovernanceKeys = tt.keys
			cfg.GovernanceThreshold = tt.threshold

			gc, err := cfg.GovernanceConfig()
			if err != nil {
				t.Fatalf("GovernanceConfig failed: %v", err)
			}
			if gc.Mode != tt.wantMode {
				t.Errorf("Mode: got %v, want %v", gc.Mode, tt.wantMode)
			}
			if len(gc.Keys) != tt.wantKeys {
				t.Errorf("Keys count: got %d, want %d", len(gc.Keys), tt.wantKeys)
			}
			if gc.Threshold != tt.threshold {
				t.Errorf("Threshold: got %d, want %d", gc.Threshold, tt.threshold)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestInitShard
// ---------------------------------------------------------------------------

func TestInitShard(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping InitShard test in short mode (requires runar compiler)")
	}

	dir := t.TempDir()
	fundedAddr := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	balance := new(uint256.Int)
	balance.SetUint64(1_000_000_000_000_000_000) // 1 ETH equivalent

	cfg, header, err := InitShard(&InitShardParams{
		ChainID:  testChainID,
		DataDir:  dir,
		GasLimit: 0, // Use default.
		Alloc: map[types.Address]block.GenesisAccount{
			fundedAddr: {
				Balance: balance,
			},
		},
		Governance:      covenant.GovernanceConfig{Mode: covenant.GovernanceNone},
		Verification:    covenant.VerifyGroth16,
		SP1VerifyingKey: []byte("test-verifying-key"),
	})
	if err != nil {
		t.Fatalf("InitShard failed: %v", err)
	}

	// Verify the config was written.
	configPath := filepath.Join(dir, "shard.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("shard.json not created")
	}

	// Verify genesis state root is set.
	if cfg.GenesisStateRoot == "" {
		t.Fatal("genesis state root not set")
	}
	if header.StateRoot == (types.Hash{}) {
		t.Fatal("header state root is zero")
	}
	if cfg.GenesisStateRoot != header.StateRoot.Hex() {
		t.Errorf("config state root %s != header state root %s", cfg.GenesisStateRoot, header.StateRoot.Hex())
	}

	// Verify config fields.
	if cfg.ChainID != testChainID {
		t.Errorf("ChainID: got %d, want %d", cfg.ChainID, testChainID)
	}
	if cfg.GovernanceMode != "none" {
		t.Errorf("GovernanceMode: got %q, want %q", cfg.GovernanceMode, "none")
	}
	if cfg.VerificationMode != "groth16" {
		t.Errorf("VerificationMode: got %q, want %q", cfg.VerificationMode, "groth16")
	}
	if cfg.HashFunction != "keccak256" {
		t.Errorf("HashFunction: got %q, want %q", cfg.HashFunction, "keccak256")
	}

	// Verify the config can be loaded back.
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.ChainID != cfg.ChainID {
		t.Errorf("loaded ChainID: got %d, want %d", loaded.ChainID, cfg.ChainID)
	}
}

// ---------------------------------------------------------------------------
// TestInitShardDefaultGasLimit
// ---------------------------------------------------------------------------

func TestInitShardDefaultGasLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping InitShard test in short mode (requires runar compiler)")
	}

	dir := t.TempDir()
	_, header, err := InitShard(&InitShardParams{
		ChainID:         testChainID,
		DataDir:         dir,
		GasLimit:        0, // Should default to 30M.
		Alloc:           nil,
		Governance:      covenant.GovernanceConfig{Mode: covenant.GovernanceNone},
		Verification:    covenant.VerifyGroth16,
		SP1VerifyingKey: []byte("test-vk"),
	})
	if err != nil {
		t.Fatalf("InitShard failed: %v", err)
	}
	if header.GasLimit != block.DefaultGasLimit {
		t.Errorf("GasLimit: got %d, want %d", header.GasLimit, block.DefaultGasLimit)
	}
}

// ---------------------------------------------------------------------------
// TestJoinShard
// ---------------------------------------------------------------------------

func TestJoinShard(t *testing.T) {
	// Create a config file on disk.
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")

	// First, initialize a genesis DB so we know the state root.
	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     make(map[types.Address]block.GenesisAccount),
	}
	header, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	cfg := validConfig()
	cfg.GenesisStateRoot = header.StateRoot.Hex()

	configPath := filepath.Join(dir, "shard.json")
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	result, err := JoinShard(configPath, dataDir)
	if err != nil {
		t.Fatalf("JoinShard failed: %v", err)
	}
	defer result.DB.Close()

	if result.Config == nil {
		t.Fatal("Config is nil")
	}
	if result.DB == nil {
		t.Fatal("DB is nil")
	}
	if result.ChainDB == nil {
		t.Fatal("ChainDB is nil")
	}
	if result.StateDB == nil {
		t.Fatal("StateDB is nil")
	}
	if result.ChainConfig == nil {
		t.Fatal("ChainConfig is nil")
	}
	if result.ChainConfig.ChainID.Int64() != testChainID {
		t.Errorf("ChainConfig.ChainID: got %d, want %d", result.ChainConfig.ChainID.Int64(), testChainID)
	}

	// After join, the head block should be genesis (block 0).
	headHeader := result.ChainDB.ReadHeadHeader()
	if headHeader == nil {
		t.Fatal("no head header after join")
	}
	// RLP encodes *big.Int(0) as 0x80 which decodes back as nil.
	// A nil Number means block 0, which is what we expect.
	headNum := int64(0)
	if headHeader.Number != nil {
		headNum = headHeader.Number.Int64()
	}
	if headNum != 0 {
		t.Errorf("head block number: got %d, want 0", headNum)
	}
}

// ---------------------------------------------------------------------------
// TestJoinShardMissingConfig
// ---------------------------------------------------------------------------

func TestJoinShardMissingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nonexistent.json")

	_, err := JoinShard(configPath, dir)
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

// ---------------------------------------------------------------------------
// TestSyncFromBSV
// ---------------------------------------------------------------------------

// mockBSVClient implements BSVClient for testing. It simulates a covenant
// UTXO chain with a configurable number of advances.
type mockBSVClient struct {
	// chain maps txid -> spending transaction. If the value is nil, the
	// output is unspent.
	chain map[types.Hash]*BSVTransaction
}

func newMockBSVClient() *mockBSVClient {
	return &mockBSVClient{
		chain: make(map[types.Hash]*BSVTransaction),
	}
}

func (m *mockBSVClient) GetTransaction(txid types.Hash) (*BSVTransaction, error) {
	tx, ok := m.chain[txid]
	if !ok {
		return nil, fmt.Errorf("transaction %s not found", txid.Hex())
	}
	return tx, nil
}

func (m *mockBSVClient) GetSpendingTx(txid types.Hash, vout uint32) (*BSVTransaction, error) {
	// We use txid as the key. The mock stores the spending tx directly.
	key := spendingKey(txid, vout)
	tx, ok := m.chain[key]
	if !ok {
		return nil, nil // Unspent.
	}
	return tx, nil
}

// addAdvance adds a covenant advance to the mock chain. The advance spends
// the previous covenant output and creates a new one.
func (m *mockBSVClient) addAdvance(prevTxID types.Hash, prevVout uint32, newTxID types.Hash, batchData []byte) {
	tx := &BSVTransaction{
		TxID: newTxID,
		Outputs: []BSVOutput{
			{Script: []byte{0x00}, Value: 10000}, // Output 0: new covenant UTXO.
			{Script: batchData, Value: 0},        // Output 1: OP_RETURN with batch.
		},
	}
	key := spendingKey(prevTxID, prevVout)
	m.chain[key] = tx
}

// spendingKey creates a unique hash key for a spending lookup.
func spendingKey(txid types.Hash, vout uint32) types.Hash {
	// Combine txid and vout into a unique key.
	data := make([]byte, 36)
	copy(data[:32], txid.Bytes())
	data[32] = byte(vout)
	data[33] = byte(vout >> 8)
	data[34] = byte(vout >> 16)
	data[35] = byte(vout >> 24)
	h := sha256.Sum256(data)
	return types.BytesToHash(h[:])
}

func TestSyncFromBSV(t *testing.T) {
	// Set up a genesis database.
	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     make(map[types.Address]block.GenesisAccount),
	}
	_, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	chainDB := block.NewChainDB(database)
	executor := block.NewBlockExecutor(vm.DefaultL2Config(testChainID), vm.Config{})

	// Create a mock BSV client with 3 covenant advances, each with empty
	// batches (no EVM transactions). This tests the sync mechanism without
	// requiring real transaction execution.
	client := newMockBSVClient()
	genesisTxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")

	// Chain: genesis -> advance1 -> advance2 -> advance3 (unspent)
	advance1TxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")
	advance2TxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000003")
	advance3TxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004")

	// Empty batches: OP_RETURN with no data.
	emptyBatch := []byte{0x6a, 0x00} // OP_RETURN OP_0

	client.addAdvance(genesisTxID, 0, advance1TxID, emptyBatch)
	client.addAdvance(advance1TxID, 0, advance2TxID, emptyBatch)
	client.addAdvance(advance2TxID, 0, advance3TxID, emptyBatch)

	err = SyncFromBSV(client, chainDB, database, executor, genesisTxID)
	if err != nil {
		t.Fatalf("SyncFromBSV failed: %v", err)
	}

	// Verify we synced 3 blocks (genesis + 3 advances = head at block 3).
	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		t.Fatal("no head header after sync")
	}
	headNum := int64(0)
	if headHeader.Number != nil {
		headNum = headHeader.Number.Int64()
	}
	if headNum != 3 {
		t.Errorf("head block number: got %d, want 3", headNum)
	}
}

// ---------------------------------------------------------------------------
// TestSyncFromBSVNilClient
// ---------------------------------------------------------------------------

func TestSyncFromBSVNilClient(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := block.NewChainDB(database)
	executor := block.NewBlockExecutor(vm.DefaultL2Config(testChainID), vm.Config{})

	err := SyncFromBSV(nil, chainDB, database, executor, types.Hash{})
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

// ---------------------------------------------------------------------------
// TestDiscoverShardsEmpty
// ---------------------------------------------------------------------------

func TestDiscoverShardsEmpty(t *testing.T) {
	shards, err := DiscoverShards(nil)
	if err != nil {
		t.Fatalf("DiscoverShards failed: %v", err)
	}
	if len(shards) != 0 {
		t.Errorf("expected 0 shards, got %d", len(shards))
	}

	shards, err = DiscoverShards([]string{})
	if err != nil {
		t.Fatalf("DiscoverShards failed: %v", err)
	}
	if len(shards) != 0 {
		t.Errorf("expected 0 shards, got %d", len(shards))
	}
}

// ---------------------------------------------------------------------------
// TestShardConfigChainConfig
// ---------------------------------------------------------------------------

func TestShardConfigChainConfig(t *testing.T) {
	cfg := validConfig()
	chainCfg := cfg.ChainConfig()

	if chainCfg == nil {
		t.Fatal("ChainConfig returned nil")
	}
	if chainCfg.ChainID.Int64() != testChainID {
		t.Errorf("ChainID: got %d, want %d", chainCfg.ChainID.Int64(), testChainID)
	}

	// All hardforks should be enabled from genesis.
	zero := big.NewInt(0)
	if chainCfg.HomesteadBlock == nil || chainCfg.HomesteadBlock.Cmp(zero) != 0 {
		t.Error("HomesteadBlock not set to 0")
	}
	if chainCfg.ByzantiumBlock == nil || chainCfg.ByzantiumBlock.Cmp(zero) != 0 {
		t.Error("ByzantiumBlock not set to 0")
	}
	if chainCfg.LondonBlock == nil || chainCfg.LondonBlock.Cmp(zero) != 0 {
		t.Error("LondonBlock not set to 0")
	}
	if chainCfg.ShanghaiTime == nil || *chainCfg.ShanghaiTime != 0 {
		t.Error("ShanghaiTime not set to 0")
	}
	if chainCfg.CancunTime == nil || *chainCfg.CancunTime != 0 {
		t.Error("CancunTime not set to 0")
	}
	if chainCfg.PragueTime == nil || *chainCfg.PragueTime != 0 {
		t.Error("PragueTime not set to 0")
	}
}

// ---------------------------------------------------------------------------
// TestShardConfigSaveLoadJSON
// ---------------------------------------------------------------------------

func TestShardConfigSaveLoadJSON(t *testing.T) {
	cfg := validConfig()

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var loaded ShardConfig
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if loaded.ChainID != cfg.ChainID {
		t.Errorf("ChainID: got %d, want %d", loaded.ChainID, cfg.ChainID)
	}
	if loaded.GovernanceMode != cfg.GovernanceMode {
		t.Errorf("GovernanceMode: got %q, want %q", loaded.GovernanceMode, cfg.GovernanceMode)
	}
}

// ---------------------------------------------------------------------------
// TestStripOpReturn
// ---------------------------------------------------------------------------

func TestStripOpReturn(t *testing.T) {
	tests := []struct {
		name   string
		script []byte
		want   []byte
	}{
		{
			name:   "empty",
			script: nil,
			want:   nil,
		},
		{
			name:   "OP_RETURN with direct push",
			script: []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef},
			want:   []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:   "OP_FALSE OP_RETURN with direct push",
			script: []byte{0x00, 0x6a, 0x02, 0xab, 0xcd},
			want:   []byte{0xab, 0xcd},
		},
		{
			name:   "OP_RETURN with OP_0 (empty push)",
			script: []byte{0x6a, 0x00},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripOpReturn(tt.script)
			if len(got) == 0 && len(tt.want) == 0 {
				return // Both empty/nil, pass.
			}
			if len(got) != len(tt.want) {
				t.Fatalf("length: got %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// TestSyncFromBSV_BSVMBatchFormat
// ---------------------------------------------------------------------------

func TestSyncFromBSV_BSVMBatchFormat(t *testing.T) {
	// Set up a genesis database.
	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     make(map[types.Address]block.GenesisAccount),
	}
	_, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	chainDB := block.NewChainDB(database)
	executor := block.NewBlockExecutor(vm.DefaultL2Config(testChainID), vm.Config{})

	client := newMockBSVClient()
	genesisTxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000010")
	advance1TxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000011")

	// Build a BSVM\x02 batch with no transactions.
	genesisHeader := chainDB.ReadHeadHeader()
	if genesisHeader == nil {
		t.Fatal("no genesis header")
	}
	coinbase := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	batchData := &block.BatchData{
		Version:        block.BatchVersion,
		Timestamp:      1000,
		Coinbase:       coinbase,
		ParentHash:     genesisHeader.Hash(),
		Transactions:   nil,
		DepositHorizon: 0,
	}
	encoded, err := block.EncodeBatchData(batchData)
	if err != nil {
		t.Fatalf("EncodeBatchData failed: %v", err)
	}

	// Wrap in OP_RETURN script.
	script := wrapInOpReturn(encoded)
	client.addAdvance(genesisTxID, 0, advance1TxID, script)

	err = SyncFromBSV(client, chainDB, database, executor, genesisTxID)
	if err != nil {
		t.Fatalf("SyncFromBSV failed: %v", err)
	}

	// Verify head is at block 1.
	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		t.Fatal("no head header after sync")
	}
	headNum := uint64(0)
	if headHeader.Number != nil {
		headNum = headHeader.Number.Uint64()
	}
	if headNum != 1 {
		t.Errorf("head block number: got %d, want 1", headNum)
	}

	// Verify the block used the batch data's timestamp and coinbase.
	if headHeader.Timestamp != 1000 {
		t.Errorf("block timestamp: got %d, want 1000", headHeader.Timestamp)
	}
	if headHeader.Coinbase != coinbase {
		t.Errorf("block coinbase: got %s, want %s", headHeader.Coinbase.Hex(), coinbase.Hex())
	}
}

// ---------------------------------------------------------------------------
// TestSyncFromBSV_LegacyFormat
// ---------------------------------------------------------------------------

func TestSyncFromBSV_LegacyFormat(t *testing.T) {
	// Set up a genesis database.
	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     make(map[types.Address]block.GenesisAccount),
	}
	_, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	chainDB := block.NewChainDB(database)
	executor := block.NewBlockExecutor(vm.DefaultL2Config(testChainID), vm.Config{})

	client := newMockBSVClient()
	genesisTxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000020")
	advance1TxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000021")

	// Legacy format: RLP-encode an empty transaction list.
	emptyTxList, err := rlp.EncodeToBytes([]*types.Transaction{})
	if err != nil {
		t.Fatalf("encoding empty tx list: %v", err)
	}
	script := wrapInOpReturn(emptyTxList)
	client.addAdvance(genesisTxID, 0, advance1TxID, script)

	err = SyncFromBSV(client, chainDB, database, executor, genesisTxID)
	if err != nil {
		t.Fatalf("SyncFromBSV failed: %v", err)
	}

	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		t.Fatal("no head header after sync")
	}
	headNum := uint64(0)
	if headHeader.Number != nil {
		headNum = headHeader.Number.Uint64()
	}
	if headNum != 1 {
		t.Errorf("head block number: got %d, want 1", headNum)
	}
}

// ---------------------------------------------------------------------------
// TestSyncFromBSV_Checkpoint
// ---------------------------------------------------------------------------

func TestSyncFromBSV_Checkpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping checkpoint test in short mode")
	}

	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     make(map[types.Address]block.GenesisAccount),
	}
	_, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	chainDB := block.NewChainDB(database)
	executor := block.NewBlockExecutor(vm.DefaultL2Config(testChainID), vm.Config{})

	client := newMockBSVClient()
	genesisTxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000030")

	// Build a chain of 2000 empty-batch covenant advances.
	prevTxID := genesisTxID
	emptyBatch := []byte{0x6a, 0x00}
	for i := 0; i < 2000; i++ {
		h := sha256.Sum256(append(prevTxID.Bytes(), byte(i), byte(i>>8)))
		nextTxID := types.BytesToHash(h[:])
		client.addAdvance(prevTxID, 0, nextTxID, emptyBatch)
		prevTxID = nextTxID
	}

	err = SyncFromBSV(client, chainDB, database, executor, genesisTxID)
	if err != nil {
		t.Fatalf("SyncFromBSV failed: %v", err)
	}

	// Verify head is at block 2000.
	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		t.Fatal("no head header")
	}
	headNum := uint64(0)
	if headHeader.Number != nil {
		headNum = headHeader.Number.Uint64()
	}
	if headNum != 2000 {
		t.Errorf("head block number: got %d, want 2000", headNum)
	}

	// Verify a checkpoint was written at block 1000.
	cp := chainDB.ReadSyncCheckpoint()
	if cp == nil {
		t.Fatal("no checkpoint written")
	}
	// The checkpoint should be at block 1000 or 2000 (the last
	// multiple of checkpointInterval). Since 2000 is also a multiple,
	// the checkpoint should be at 2000.
	if cp.L2BlockNum != 2000 {
		t.Errorf("checkpoint block: got %d, want 2000", cp.L2BlockNum)
	}
	if cp.CovenantTxID == (types.Hash{}) {
		t.Error("checkpoint covenant txid is zero")
	}
}

// ---------------------------------------------------------------------------
// TestSyncFromBSV_ResumeFromCheckpoint
// ---------------------------------------------------------------------------

func TestSyncFromBSV_ResumeFromCheckpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resume test in short mode")
	}

	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     make(map[types.Address]block.GenesisAccount),
	}
	_, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	chainDB := block.NewChainDB(database)
	executor := block.NewBlockExecutor(vm.DefaultL2Config(testChainID), vm.Config{})

	// Build a counting client so we can verify fewer BSV calls on resume.
	client := newCountingMockBSVClient()
	genesisTxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000040")

	// Build a chain of 1500 empty-batch covenant advances.
	prevTxID := genesisTxID
	emptyBatch := []byte{0x6a, 0x00}
	for i := 0; i < 1500; i++ {
		h := sha256.Sum256(append(prevTxID.Bytes(), byte(i), byte(i>>8)))
		nextTxID := types.BytesToHash(h[:])
		client.addAdvance(prevTxID, 0, nextTxID, emptyBatch)
		prevTxID = nextTxID
	}

	// First sync: sync all 1500 blocks.
	err = SyncFromBSV(client, chainDB, database, executor, genesisTxID)
	if err != nil {
		t.Fatalf("first SyncFromBSV failed: %v", err)
	}

	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		t.Fatal("no head header")
	}
	headNum := uint64(0)
	if headHeader.Number != nil {
		headNum = headHeader.Number.Uint64()
	}
	if headNum != 1500 {
		t.Fatalf("head block number: got %d, want 1500", headNum)
	}

	// Verify checkpoint exists.
	cp := chainDB.ReadSyncCheckpoint()
	if cp == nil {
		t.Fatal("no checkpoint after first sync")
	}

	// Reset call count and sync again. Since we're already synced,
	// the checkpoint should let us skip to the checkpoint position
	// and only walk from there.
	client.resetCounts()
	err = SyncFromBSV(client, chainDB, database, executor, genesisTxID)
	if err != nil {
		t.Fatalf("second SyncFromBSV failed: %v", err)
	}

	// With checkpoint at block 1000, we should skip 1000 spending tx
	// lookups that we'd otherwise need to walk from genesis.
	// The second sync should make fewer GetSpendingTx calls than the
	// full 1501 (1500 advances + 1 for unspent tip).
	if client.getSpendingTxCalls >= 1501 {
		t.Errorf("expected fewer than 1501 GetSpendingTx calls on resume, got %d",
			client.getSpendingTxCalls)
	}
}

// ---------------------------------------------------------------------------
// TestSyncIfNeeded_NilClient
// ---------------------------------------------------------------------------

func TestSyncIfNeeded_NilClient(t *testing.T) {
	database, _ := initGenesisDB(t)
	chainDB := block.NewChainDB(database)
	chainConfig := vm.DefaultL2Config(testChainID)
	stateRoot := chainDB.ReadHeadHeader().StateRoot
	stateDB, err := state.New(stateRoot, database)
	if err != nil {
		t.Fatalf("state.New failed: %v", err)
	}

	joinResult := &JoinResult{
		Config:      validConfig(),
		DB:          database,
		ChainDB:     chainDB,
		StateDB:     stateDB,
		ChainConfig: chainConfig,
		Synced:      true,
	}

	err = SyncIfNeeded(nil, joinResult, types.Hash{})
	if err != nil {
		t.Fatalf("SyncIfNeeded with nil client should not error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestSyncIfNeeded_AlreadySynced
// ---------------------------------------------------------------------------

func TestSyncIfNeeded_AlreadySynced(t *testing.T) {
	database, _ := initGenesisDB(t)
	chainDB := block.NewChainDB(database)
	chainConfig := vm.DefaultL2Config(testChainID)
	stateRoot := chainDB.ReadHeadHeader().StateRoot
	stateDB, err := state.New(stateRoot, database)
	if err != nil {
		t.Fatalf("state.New failed: %v", err)
	}

	joinResult := &JoinResult{
		Config:      validConfig(),
		DB:          database,
		ChainDB:     chainDB,
		StateDB:     stateDB,
		ChainConfig: chainConfig,
		Synced:      true,
	}

	// Create a mock client where the genesis covenant output is unspent
	// (meaning no advances have happened, so we're already synced).
	client := newMockBSVClient()
	genesisTxID := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000050")

	err = SyncIfNeeded(client, joinResult, genesisTxID)
	if err != nil {
		t.Fatalf("SyncIfNeeded should succeed when already synced, got: %v", err)
	}

	// Head should still be at genesis (block 0).
	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		t.Fatal("no head header")
	}
	headNum := uint64(0)
	if headHeader.Number != nil {
		headNum = headHeader.Number.Uint64()
	}
	if headNum != 0 {
		t.Errorf("head block number: got %d, want 0", headNum)
	}
}

// ---------------------------------------------------------------------------
// countingMockBSVClient wraps mockBSVClient with call counters.
// ---------------------------------------------------------------------------

type countingMockBSVClient struct {
	*mockBSVClient
	getSpendingTxCalls  int
	getTransactionCalls int
}

func newCountingMockBSVClient() *countingMockBSVClient {
	return &countingMockBSVClient{
		mockBSVClient: newMockBSVClient(),
	}
}

func (c *countingMockBSVClient) GetTransaction(txid types.Hash) (*BSVTransaction, error) {
	c.getTransactionCalls++
	return c.mockBSVClient.GetTransaction(txid)
}

func (c *countingMockBSVClient) GetSpendingTx(txid types.Hash, vout uint32) (*BSVTransaction, error) {
	c.getSpendingTxCalls++
	return c.mockBSVClient.GetSpendingTx(txid, vout)
}

func (c *countingMockBSVClient) resetCounts() {
	c.getSpendingTxCalls = 0
	c.getTransactionCalls = 0
}

// wrapInOpReturn wraps data in a simple OP_RETURN script with OP_PUSHDATA2.
func wrapInOpReturn(data []byte) []byte {
	if len(data) == 0 {
		return []byte{0x6a, 0x00}
	}
	// Use OP_PUSHDATA2 for larger data.
	if len(data) > 0x4b {
		script := make([]byte, 0, 4+len(data))
		script = append(script, 0x6a)      // OP_RETURN
		script = append(script, 0x4d)      // OP_PUSHDATA2
		script = append(script, byte(len(data)&0xff), byte(len(data)>>8)) // Little-endian length
		script = append(script, data...)
		return script
	}
	// Direct push for small data.
	script := make([]byte, 0, 2+len(data))
	script = append(script, 0x6a)           // OP_RETURN
	script = append(script, byte(len(data))) // Push length
	script = append(script, data...)
	return script
}

// Suppress unused import warnings. These are used in tests that may be
// skipped in short mode.
var (
	_ = rlp.EncodeToBytes
	_ = state.New
	_ = uint256.NewInt
)
