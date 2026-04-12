package shard

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/vm"
)

// ShardConfig holds the complete configuration for a shard instance. It
// captures identity, covenant parameters, SP1 prover settings, governance
// mode, genesis state, networking, and local paths. ShardConfig is
// serialized as JSON for storage and exchange between nodes.
type ShardConfig struct {
	// ChainID is the EIP-155 chain identifier, unique per shard.
	ChainID int64 `json:"chainId"`
	// ShardID is the globally unique shard identifier, equal to the genesis
	// covenant transaction ID.
	ShardID string `json:"shardId"`

	// GenesisCovenantTxID is the BSV transaction ID that created the
	// covenant UTXO.
	GenesisCovenantTxID string `json:"genesisCovenantTxId"`
	// GenesisCovenantVout is the output index of the covenant UTXO in the
	// genesis transaction.
	GenesisCovenantVout uint32 `json:"genesisCovenantVout"`
	// CovenantSats is the satoshi amount carried by the covenant UTXO.
	CovenantSats uint64 `json:"covenantSats"`

	// SP1GuestELF is the path to the SP1 guest program ELF binary.
	SP1GuestELF string `json:"sp1GuestElf"`
	// SP1VerifyingKey is the hex-encoded SP1 verifying key derived from
	// the guest ELF.
	SP1VerifyingKey string `json:"sp1VerifyingKey"`

	// GovernanceMode is the shard's trust model: "none", "single_key",
	// or "multisig".
	GovernanceMode string `json:"governanceMode"`
	// GovernanceKeys holds hex-encoded compressed public keys for
	// governance operations (empty for mode "none").
	GovernanceKeys []string `json:"governanceKeys,omitempty"`
	// GovernanceThreshold is the M-of-N threshold for multisig governance.
	GovernanceThreshold int `json:"governanceThreshold,omitempty"`

	// VerificationMode selects the on-chain proof verification strategy:
	// "groth16" or "basefold".
	VerificationMode string `json:"verificationMode"`

	// GenesisStateRoot is the hex-encoded state root after genesis
	// initialization.
	GenesisStateRoot string `json:"genesisStateRoot"`
	// HashFunction is the hash function used for state tries. Currently
	// only "keccak256" is supported.
	HashFunction string `json:"hashFunction"`

	// BootstrapPeers lists libp2p multiaddrs of bootstrap nodes for the
	// shard's peer network.
	BootstrapPeers []string `json:"bootstrapPeers,omitempty"`

	// DataDir is the local filesystem path for shard data. It is not
	// serialized because it is machine-specific.
	DataDir string `json:"-"`
}

// LoadConfig reads a shard configuration from a JSON file at the given
// path. It validates the loaded configuration before returning.
func LoadConfig(path string) (*ShardConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg ShardConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

// Save writes the shard configuration to a JSON file at the given path.
// Parent directories are created if they do not exist.
func (c *ShardConfig) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	return nil
}

// Validate checks that all required fields are present and consistent.
// It returns an error describing the first validation failure found.
func (c *ShardConfig) Validate() error {
	if c.ChainID == 0 {
		return fmt.Errorf("chain ID must not be zero")
	}
	if c.GenesisCovenantTxID == "" {
		return fmt.Errorf("genesis covenant txid must not be empty")
	}
	if c.ShardID != "" && c.ShardID != c.GenesisCovenantTxID {
		return fmt.Errorf("shard ID must equal genesis covenant txid (got %q, want %q)", c.ShardID, c.GenesisCovenantTxID)
	}
	if c.VerificationMode == "" {
		return fmt.Errorf("verification mode must not be empty")
	}
	if c.VerificationMode != "groth16" && c.VerificationMode != "basefold" {
		return fmt.Errorf("verification mode must be groth16 or basefold, got %q", c.VerificationMode)
	}
	if c.HashFunction == "" {
		return fmt.Errorf("hash function must not be empty")
	}
	if c.HashFunction != "keccak256" {
		return fmt.Errorf("hash function must be keccak256, got %q", c.HashFunction)
	}
	if c.GenesisStateRoot == "" {
		return fmt.Errorf("genesis state root must not be empty")
	}
	switch c.GovernanceMode {
	case "none":
		if len(c.GovernanceKeys) != 0 {
			return fmt.Errorf("governance mode none must have no keys")
		}
		if c.GovernanceThreshold != 0 {
			return fmt.Errorf("governance mode none must have threshold 0")
		}
	case "single_key":
		if len(c.GovernanceKeys) != 1 {
			return fmt.Errorf("governance mode single_key requires exactly 1 key, got %d", len(c.GovernanceKeys))
		}
		if c.GovernanceThreshold != 0 {
			return fmt.Errorf("governance mode single_key must have threshold 0")
		}
	case "multisig":
		if len(c.GovernanceKeys) < 2 {
			return fmt.Errorf("governance mode multisig requires at least 2 keys, got %d", len(c.GovernanceKeys))
		}
		if c.GovernanceThreshold < 1 {
			return fmt.Errorf("governance mode multisig threshold must be at least 1")
		}
		if c.GovernanceThreshold > len(c.GovernanceKeys) {
			return fmt.Errorf("governance mode multisig threshold %d exceeds key count %d", c.GovernanceThreshold, len(c.GovernanceKeys))
		}
	case "":
		return fmt.Errorf("governance mode must not be empty")
	default:
		return fmt.Errorf("governance mode must be none, single_key, or multisig, got %q", c.GovernanceMode)
	}
	return nil
}

// GovernanceConfig converts the shard config's string-based governance
// fields into the typed covenant.GovernanceConfig used by the covenant
// compiler.
func (c *ShardConfig) GovernanceConfig() (covenant.GovernanceConfig, error) {
	var gc covenant.GovernanceConfig

	switch c.GovernanceMode {
	case "none":
		gc.Mode = covenant.GovernanceNone
	case "single_key":
		gc.Mode = covenant.GovernanceSingleKey
	case "multisig":
		gc.Mode = covenant.GovernanceMultiSig
	default:
		return gc, fmt.Errorf("unknown governance mode %q", c.GovernanceMode)
	}

	for i, keyHex := range c.GovernanceKeys {
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			return gc, fmt.Errorf("decoding governance key %d: %w", i, err)
		}
		gc.Keys = append(gc.Keys, keyBytes)
	}

	gc.Threshold = c.GovernanceThreshold
	return gc, nil
}

// ChainConfig returns a vm.ChainConfig derived from the shard's chain ID,
// with all hardforks enabled from genesis.
func (c *ShardConfig) ChainConfig() *vm.ChainConfig {
	return vm.DefaultL2Config(c.ChainID)
}
