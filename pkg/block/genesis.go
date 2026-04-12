package block

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// Genesis represents the genesis configuration for an L2 shard.
type Genesis struct {
	Config        *vm.ChainConfig                  `json:"config"`
	HashFunction  string                           `json:"hashFunction"`
	Timestamp     uint64                           `json:"timestamp"`
	GasLimit      uint64                           `json:"gasLimit"`
	Coinbase      types.Address                    `json:"coinbase"`
	Alloc         map[types.Address]GenesisAccount `json:"alloc"`
	BridgeAddress types.Address                    `json:"bridgeAddress"`
	Governance    covenant.GovernanceConfig         `json:"governance"`
	BSVAnchorTxID types.Hash                       `json:"bsvAnchorTxId,omitempty"`
}

// GenesisAccount is a genesis allocation entry specifying the initial state
// of an account.
type GenesisAccount struct {
	Code    []byte                    `json:"code,omitempty"`
	Storage map[types.Hash]types.Hash `json:"storage,omitempty"`
	Balance *uint256.Int              `json:"balance"`
	Nonce   uint64                    `json:"nonce,omitempty"`
}

// ValidateGenesis checks that a genesis configuration is valid. It returns
// an error if any field violates the spec constraints.
func ValidateGenesis(genesis *Genesis) error {
	if genesis.Config == nil {
		return errors.New("genesis config must not be nil")
	}
	// HashFunction must be "keccak256" if set. Empty string is treated as
	// the default (keccak256).
	if genesis.HashFunction != "" && genesis.HashFunction != "keccak256" {
		return fmt.Errorf("unsupported hash function %q, must be \"keccak256\"", genesis.HashFunction)
	}
	if err := genesis.Governance.Validate(); err != nil {
		return fmt.Errorf("invalid governance config: %w", err)
	}
	return nil
}

// InitGenesis initializes the genesis state, writes the genesis block to the
// database, and returns the genesis header. This must be called exactly once
// when creating a new shard.
func InitGenesis(database db.Database, genesis *Genesis) (*L2Header, error) {
	if err := ValidateGenesis(genesis); err != nil {
		return nil, fmt.Errorf("invalid genesis: %w", err)
	}

	// Create an empty state.
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		return nil, fmt.Errorf("failed to create genesis state: %w", err)
	}

	// Apply genesis allocations.
	for addr, account := range genesis.Alloc {
		statedb.CreateAccount(addr)
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance, tracing.BalanceIncreaseDeposit)
		}
		if account.Nonce > 0 {
			statedb.SetNonce(addr, account.Nonce, tracing.NonceChangeUnspecified)
		}
		if len(account.Code) > 0 {
			statedb.SetCode(addr, account.Code, tracing.CodeChangeCreation)
		}
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}

	// Deploy the bridge predeploy contract.
	bridge.DeployBridgePredeploy(statedb)

	// Commit state to get the genesis root.
	genesisRoot, err := statedb.Commit(true)
	if err != nil {
		return nil, fmt.Errorf("failed to commit genesis state: %w", err)
	}

	// Determine gas limit.
	gasLimit := genesis.GasLimit
	if gasLimit == 0 {
		gasLimit = DefaultGasLimit
	}

	// Create genesis header. Coinbase is explicitly set to the zero address
	// for genesis. No transactions execute in the genesis block.
	header := &L2Header{
		ParentHash:  types.Hash{},
		Coinbase:    types.Address{},
		StateRoot:   genesisRoot,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Number:      big.NewInt(0),
		GasLimit:    gasLimit,
		GasUsed:     0,
		Timestamp:   genesis.Timestamp,
		BaseFee:     new(big.Int), // BaseFee is always 0.
	}

	// Create genesis block.
	block := NewBlock(header, nil, nil)

	// Write to chain database.
	chainDB := NewChainDB(database)
	if err := chainDB.WriteBlock(block, nil); err != nil {
		return nil, fmt.Errorf("failed to write genesis block: %w", err)
	}

	return header, nil
}

// DefaultGenesis returns the default genesis configuration for an L2 shard
// with the given chain ID. It has all hardforks enabled from genesis and
// no initial allocations.
func DefaultGenesis(chainID int64) *Genesis {
	return &Genesis{
		Config:       vm.DefaultL2Config(chainID),
		HashFunction: "keccak256",
		Timestamp:    0,
		GasLimit:     DefaultGasLimit,
		Alloc:        make(map[types.Address]GenesisAccount),
		Governance:   covenant.GovernanceConfig{Mode: covenant.GovernanceNone},
	}
}

// LoadGenesisFromFile reads a genesis configuration from a JSON file.
func LoadGenesisFromFile(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading genesis file %s: %w", path, err)
	}
	var genesis Genesis
	if err := json.Unmarshal(data, &genesis); err != nil {
		return nil, fmt.Errorf("parsing genesis file %s: %w", path, err)
	}
	return &genesis, nil
}
