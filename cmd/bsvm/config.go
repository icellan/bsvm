package main

import (
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/icellan/bsvm/pkg/network"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/rpc"
	"github.com/icellan/bsvm/pkg/types"
)

// NodeConfig holds the complete node configuration loaded from a TOML config
// file. It groups settings for all node subsystems: overlay execution, RPC,
// proving, networking, bridge, database, governance, BSV, and logging.
type NodeConfig struct {
	DataDir    string            `toml:"datadir"`
	Genesis    string            `toml:"genesis"`
	Shard      ShardSection      `toml:"shard"`
	Overlay    OverlaySection    `toml:"overlay"`
	RPC        RPCSection        `toml:"rpc"`
	Prover     ProverSection     `toml:"prover"`
	Network    NetworkSection    `toml:"network"`
	BSV        BSVSection        `toml:"bsv"`
	Bridge     BridgeSection     `toml:"bridge"`
	Database   DatabaseSection   `toml:"database"`
	Governance GovernanceSection `toml:"governance"`
	LogLevel   string            `toml:"log_level"`
	LogFormat  string            `toml:"log_format"`
}

// ShardSection holds shard identification.
type ShardSection struct {
	ChainID             int64  `toml:"chain_id"`
	GenesisCovenantTxID string `toml:"genesis_covenant_txid"`
	GenesisCovenantVout uint32 `toml:"genesis_covenant_vout"`
	CovenantSats        uint64 `toml:"covenant_sats"`
}

// OverlaySection holds overlay node configuration.
type OverlaySection struct {
	Coinbase            string `toml:"coinbase"`
	BlockGasLimit       uint64 `toml:"block_gas_limit"`
	MaxBatchSize        int    `toml:"batch_size"`
	MaxBatchFlushDelay  string `toml:"max_batch_flush_delay"`
	MinGasPrice         string `toml:"min_gas_price"`
	MaxSpeculativeDepth int    `toml:"max_speculative_depth"`
}

// RPCSection holds JSON-RPC server configuration.
type RPCSection struct {
	HTTPAddr    string   `toml:"http_addr"`
	WSAddr      string   `toml:"ws_addr"`
	CORSOrigins []string `toml:"cors_origins"`
}

// ProverSection holds SP1 prover configuration.
type ProverSection struct {
	Mode    string `toml:"mode"` // "mock", "local", "network"
	Workers int    `toml:"workers"`
}

// NetworkSection holds P2P networking configuration.
type NetworkSection struct {
	ListenAddr     string   `toml:"listen_addr"`
	BootstrapPeers []string `toml:"bootstrap_peers"`
	MaxPeers       int      `toml:"max_peers"`
}

// BSVSection holds BSV node connection configuration.
type BSVSection struct {
	NodeURL       string `toml:"node_url"`
	ARCURL        string `toml:"arc_url"`
	Network       string `toml:"network"`        // mainnet, testnet, regtest
	FeeWalletKey  string `toml:"fee_wallet_key"` // Path to WIF key file
	Confirmations int    `toml:"confirmations"`
}

// BridgeSection holds BSV bridge configuration.
type BridgeSection struct {
	MinDepositSatoshis    uint64 `toml:"min_deposit_satoshis"`
	MinWithdrawalSatoshis uint64 `toml:"min_withdrawal_satoshis"`
	BSVConfirmations      int    `toml:"bsv_confirmations"`
}

// DatabaseSection holds database configuration.
type DatabaseSection struct {
	Engine  string `toml:"engine"`   // "leveldb" (default) or "pebble"
	CacheMB int    `toml:"cache_mb"` // database cache size in MB
}

// GovernanceSection holds governance configuration for the node.
type GovernanceSection struct {
	Mode      string   `toml:"mode"`      // "none", "single_key", "multisig"
	Keys      []string `toml:"keys"`      // hex-encoded compressed public keys
	Threshold int      `toml:"threshold"` // M-of-N threshold for multisig
}

// DefaultNodeConfig returns a NodeConfig with sensible defaults for local
// development and testing.
func DefaultNodeConfig() *NodeConfig {
	return &NodeConfig{
		DataDir:   "./data",
		LogLevel:  "info",
		LogFormat: "text",
		Overlay: OverlaySection{
			Coinbase:            "0x0000000000000000000000000000000000000000",
			BlockGasLimit:       30_000_000,
			MaxBatchSize:        128,
			MaxBatchFlushDelay:  "2s",
			MinGasPrice:         "1000000000", // 1 gwei
			MaxSpeculativeDepth: 16,
		},
		RPC: RPCSection{
			HTTPAddr:    "0.0.0.0:8545",
			WSAddr:      "0.0.0.0:8546",
			CORSOrigins: []string{"*"},
		},
		Prover: ProverSection{
			Mode:    "mock",
			Workers: 1,
		},
		Network: NetworkSection{
			ListenAddr:     "/ip4/0.0.0.0/tcp/9945",
			BootstrapPeers: []string{},
			MaxPeers:       50,
		},
		BSV: BSVSection{
			Network:       "mainnet",
			Confirmations: 6,
		},
		Bridge: BridgeSection{
			MinDepositSatoshis:    10000,
			MinWithdrawalSatoshis: 10000,
			BSVConfirmations:      6,
		},
		Database: DatabaseSection{
			Engine:  "leveldb",
			CacheMB: 256,
		},
		// Governance defaults to zero value (Mode "", no keys, threshold 0)
		// which is treated as "none" -- fully trustless, no governance keys.
	}
}

// LoadNodeConfig reads a node configuration from a TOML file at the given
// path. Missing fields are filled with defaults.
func LoadNodeConfig(path string) (*NodeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg := DefaultNodeConfig()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}
	return cfg, nil
}

// ToOverlayConfig converts the node config's overlay section into an
// overlay.OverlayConfig suitable for passing to overlay.NewOverlayNode.
func (c *NodeConfig) ToOverlayConfig(chainID int64) overlay.OverlayConfig {
	oc := overlay.DefaultOverlayConfig()
	oc.ChainID = chainID

	if c.Overlay.Coinbase != "" {
		oc.Coinbase = types.HexToAddress(c.Overlay.Coinbase)
	}
	if c.Overlay.BlockGasLimit > 0 {
		oc.BlockGasLimit = c.Overlay.BlockGasLimit
	}
	if c.Overlay.MaxBatchSize > 0 {
		oc.MaxBatchSize = c.Overlay.MaxBatchSize
	}
	if c.Overlay.MaxBatchFlushDelay != "" {
		if d, err := time.ParseDuration(c.Overlay.MaxBatchFlushDelay); err == nil {
			oc.MaxBatchFlushDelay = d
		}
	}
	if c.Overlay.MinGasPrice != "" {
		if gp, ok := new(big.Int).SetString(c.Overlay.MinGasPrice, 10); ok {
			oc.MinGasPrice = gp
		}
	}
	if c.Overlay.MaxSpeculativeDepth > 0 {
		oc.MaxSpeculativeDepth = c.Overlay.MaxSpeculativeDepth
	}

	return oc
}

// ToRPCConfig converts the node config's RPC section into an rpc.RPCConfig.
func (c *NodeConfig) ToRPCConfig() rpc.RPCConfig {
	rc := rpc.DefaultRPCConfig()

	if c.RPC.HTTPAddr != "" {
		rc.HTTPAddr = c.RPC.HTTPAddr
	}
	if c.RPC.WSAddr != "" {
		rc.WSAddr = c.RPC.WSAddr
	}
	if len(c.RPC.CORSOrigins) > 0 {
		rc.CORSOrigins = c.RPC.CORSOrigins
	}

	return rc
}

// ToProverConfig converts the node config's prover section into a
// prover.Config.
func (c *NodeConfig) ToProverConfig() prover.Config {
	pc := prover.DefaultConfig()

	switch strings.ToLower(c.Prover.Mode) {
	case "local":
		pc.Mode = prover.ProverLocal
	case "network":
		pc.Mode = prover.ProverNetwork
	default:
		pc.Mode = prover.ProverMock
	}

	return pc
}

// ToNetworkConfig converts the node config's network section into a
// network.Config.
func (c *NodeConfig) ToNetworkConfig(chainID int64) network.Config {
	nc := network.DefaultConfig()
	nc.ChainID = chainID

	if c.Network.ListenAddr != "" {
		nc.ListenAddr = c.Network.ListenAddr
	}
	if len(c.Network.BootstrapPeers) > 0 {
		nc.BootstrapPeers = c.Network.BootstrapPeers
	}
	if c.Network.MaxPeers > 0 {
		nc.MaxPeers = c.Network.MaxPeers
	}

	return nc
}
