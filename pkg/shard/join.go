package shard

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// JoinResult holds the components produced by JoinShard. The caller uses
// these to wire up the overlay node, network manager, and RPC server.
type JoinResult struct {
	// Config is the loaded and validated shard configuration.
	Config *ShardConfig
	// DB is the opened key-value database.
	DB db.Database
	// ChainDB provides typed read/write access to block data.
	ChainDB *block.ChainDB
	// StateDB is the state database rooted at the current head.
	StateDB *state.StateDB
	// ChainConfig is the EVM chain configuration for this shard.
	ChainConfig *vm.ChainConfig
	// Synced is true when the local head matches the genesis state root
	// recorded in the shard config. Full sync from BSV may still be
	// required to catch up with the latest covenant state.
	Synced bool
}

// JoinShard loads an existing shard configuration from disk, opens (or
// creates) the local database, and returns the components needed to start
// the node. If the database already contains blocks, the state is opened
// at the current head. Otherwise a fresh genesis is initialized from the
// shard config.
//
// The dataDir parameter overrides the shard config's DataDir field so
// that the same config file can be used on different machines with
// different local storage paths.
func JoinShard(configPath string, dataDir string) (*JoinResult, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading shard config: %w", err)
	}

	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("data directory must not be empty")
	}

	// Initialize the KZG trusted setup for the point evaluation precompile
	// (EIP-4844). This is a no-op if already initialized. The go-kzg-4844
	// library embeds the Ethereum ceremony data, so no external file is needed.
	if err := vm.InitKZGTrustedSetup(""); err != nil {
		return nil, fmt.Errorf("initializing KZG trusted setup: %w", err)
	}

	// Open the database.
	dbPath := filepath.Join(cfg.DataDir, "chaindata")
	database, err := db.NewLevelDB(dbPath, 256, 256)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	chainDB := block.NewChainDB(database)
	chainConfig := cfg.ChainConfig()

	// Check whether the database already has a head block.
	headHash := chainDB.ReadHeadBlockHash()
	var stateRoot types.Hash
	synced := false

	if headHash != (types.Hash{}) {
		// Database has existing blocks. Open state at the head.
		headHeader := chainDB.ReadHeadHeader()
		if headHeader == nil {
			database.Close()
			return nil, fmt.Errorf("head block hash set but header not found")
		}
		stateRoot = headHeader.StateRoot
		// The node is synced to genesis if the state root matches the
		// config's genesis state root.
		if stateRoot.Hex() == cfg.GenesisStateRoot {
			synced = true
		}
	} else {
		// No existing data. Initialize genesis from the shard config.
		genesis := &block.Genesis{
			Config:    chainConfig,
			Timestamp: 0,
			GasLimit:  block.DefaultGasLimit,
			Alloc:     make(map[types.Address]block.GenesisAccount),
		}
		header, initErr := block.InitGenesis(database, genesis)
		if initErr != nil {
			database.Close()
			return nil, fmt.Errorf("initializing genesis: %w", initErr)
		}
		stateRoot = header.StateRoot
		synced = stateRoot.Hex() == cfg.GenesisStateRoot
	}

	stateDB, err := state.New(stateRoot, database)
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("opening state at root %s: %w", stateRoot.Hex(), err)
	}

	return &JoinResult{
		Config:      cfg,
		DB:          database,
		ChainDB:     chainDB,
		StateDB:     stateDB,
		ChainConfig: chainConfig,
		Synced:      synced,
	}, nil
}

// SyncIfNeeded checks if the local chain is behind the covenant chain
// and syncs up by replaying covenant advances from BSV. Pass nil for
// bsvClient to skip sync (offline mode).
func SyncIfNeeded(
	bsvClient BSVClient,
	joinResult *JoinResult,
	genesisCovenantTxID types.Hash,
) error {
	if bsvClient == nil {
		slog.Info("BSV client is nil, skipping sync (offline mode)")
		return nil
	}
	if joinResult == nil {
		return fmt.Errorf("join result must not be nil")
	}

	executor := block.NewBlockExecutor(joinResult.ChainConfig, vm.Config{})

	return SyncFromBSV(
		bsvClient,
		joinResult.ChainDB,
		joinResult.DB,
		executor,
		genesisCovenantTxID,
	)
}
