package shard

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// InitShardParams holds parameters for creating a new shard. All fields
// except Alloc are required. If GasLimit is zero, the default 30M gas
// limit is used.
type InitShardParams struct {
	// ChainID is the EIP-155 chain identifier for the new shard.
	ChainID int64
	// DataDir is the local directory where shard data will be stored.
	DataDir string
	// GasLimit is the genesis block gas limit. Zero means use the default
	// (30,000,000).
	GasLimit uint64
	// Alloc maps addresses to their genesis account state.
	Alloc map[types.Address]block.GenesisAccount
	// Governance defines the shard's trust model.
	Governance covenant.GovernanceConfig
	// Verification selects the on-chain proof verification strategy.
	Verification covenant.VerificationMode
	// SP1VerifyingKey is the raw SP1 verifying key bytes.
	SP1VerifyingKey []byte
	// Groth16VK is the decomposed Groth16 verification key. Required when
	// Verification == VerifyGroth16. Ignored in other modes.
	Groth16VK *covenant.Groth16VK
	// Groth16WAVKPath is the absolute path to the SP1-format vk.json file
	// baked into the witness-assisted Groth16 preamble. Required when
	// Verification == VerifyGroth16WA. Ignored in other modes.
	Groth16WAVKPath string
}

// InitShard creates a new shard by initializing the L2 genesis state,
// compiling the covenant, and writing the shard configuration to disk.
//
// The BSV transaction broadcast (which creates the on-chain covenant UTXO)
// is NOT performed here because it requires a BSV client. After calling
// InitShard, the caller must broadcast the genesis transaction separately
// and update the config with the resulting txid.
//
// Steps performed:
//  1. Open a new LevelDB database in the data directory.
//  2. Initialize the L2 genesis state (genesis block and state root).
//  3. Compile the Rúnar covenant with the SP1 verifying key, chain ID,
//     and governance config.
//  4. Write the shard config to disk as JSON.
func InitShard(params *InitShardParams) (*ShardConfig, *block.L2Header, error) {
	if params == nil {
		return nil, nil, fmt.Errorf("init shard params must not be nil")
	}
	if params.ChainID == 0 {
		return nil, nil, fmt.Errorf("chain ID must not be zero")
	}
	if params.DataDir == "" {
		return nil, nil, fmt.Errorf("data directory must not be empty")
	}
	if err := params.Governance.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid governance config: %w", err)
	}

	// Fail fast on missing mode-specific verification-key inputs. The
	// covenant layer rejects these too, but catching them here yields a
	// clearer, earlier error from the shard-level API. Error strings are
	// stable so callers (and the _MissingVK tests in this package) can
	// key off them.
	switch params.Verification {
	case covenant.VerifyGroth16:
		if params.Groth16VK == nil {
			return nil, nil, fmt.Errorf("groth16 VK must be provided when Verification is VerifyGroth16")
		}
	case covenant.VerifyGroth16WA:
		if params.Groth16WAVKPath == "" {
			return nil, nil, fmt.Errorf("groth16 WA vk.json path must be provided when Verification is VerifyGroth16WA")
		}
	}

	// Determine gas limit.
	gasLimit := params.GasLimit
	if gasLimit == 0 {
		gasLimit = block.DefaultGasLimit
	}

	// Open or create the database.
	dbPath := filepath.Join(params.DataDir, "chaindata")
	database, err := db.NewLevelDB(dbPath, 256, 256)
	if err != nil {
		return nil, nil, fmt.Errorf("opening database: %w", err)
	}
	defer database.Close()

	// Build the genesis configuration.
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(params.ChainID),
		Timestamp: 0,
		GasLimit:  gasLimit,
		Alloc:     params.Alloc,
	}
	if genesis.Alloc == nil {
		genesis.Alloc = make(map[types.Address]block.GenesisAccount)
	}

	// Initialize genesis state and write genesis block.
	header, err := block.InitGenesis(database, genesis)
	if err != nil {
		return nil, nil, fmt.Errorf("initializing genesis: %w", err)
	}

	// Compile the covenant. The compiled artifact is stored in the config
	// directory for reference but is not needed for node operation.
	genesisResult, err := covenant.PrepareGenesis(&covenant.GenesisConfig{
		ChainID:          uint64(params.ChainID),
		SP1VerifyingKey:  params.SP1VerifyingKey,
		InitialStateRoot: header.StateRoot,
		Governance:       params.Governance,
		Verification:     params.Verification,
		Groth16VK:        params.Groth16VK,
		Groth16WAVKPath:  params.Groth16WAVKPath,
		CovenantSats:     covenant.DefaultCovenantSats,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("preparing covenant genesis: %w", err)
	}

	// Build governance keys as hex strings for the config.
	govKeys := make([]string, len(params.Governance.Keys))
	for i, key := range params.Governance.Keys {
		govKeys[i] = hex.EncodeToString(key)
	}

	// The genesis covenant txid is not yet known because the BSV
	// transaction has not been broadcast. We use a placeholder that
	// the operator fills in after broadcasting.
	placeholderTxID := header.StateRoot.Hex()

	cfg := &ShardConfig{
		ChainID:             params.ChainID,
		ShardID:             placeholderTxID,
		GenesisCovenantTxID: placeholderTxID,
		GenesisCovenantVout: 0,
		CovenantSats:        covenant.DefaultCovenantSats,
		SP1VerifyingKey:     hex.EncodeToString(params.SP1VerifyingKey),
		GovernanceMode:      params.Governance.Mode.String(),
		GovernanceKeys:      govKeys,
		GovernanceThreshold: params.Governance.Threshold,
		VerificationMode:    params.Verification.String(),
		GenesisStateRoot:    header.StateRoot.Hex(),
		HashFunction:        "keccak256",
		DataDir:             params.DataDir,
	}

	// Save the compiled covenant ANF for audit.
	if genesisResult.ANF != nil {
		anfPath := filepath.Join(params.DataDir, "covenant.anf.json")
		if writeErr := writeFileBytes(anfPath, genesisResult.ANF); writeErr != nil {
			// Non-fatal: log but do not fail initialization.
			_ = writeErr
		}
	}

	// Write the shard config.
	configPath := filepath.Join(params.DataDir, "shard.json")
	if err := cfg.Save(configPath); err != nil {
		return nil, nil, fmt.Errorf("saving shard config: %w", err)
	}

	return cfg, header, nil
}

// writeFileBytes writes raw bytes to a file, creating parent directories
// as needed.
func writeFileBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
