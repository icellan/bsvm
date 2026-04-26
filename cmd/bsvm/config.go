package main

import (
	"encoding/hex"
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
	Indexer    IndexerSection    `toml:"indexer"`
	BEEF       BEEFSection       `toml:"beef"`
	LogLevel   string            `toml:"log_level"`
	LogFormat  string            `toml:"log_format"`
}

// BEEFSection configures the spec-17 BEEF gossip + ARC callback HTTP
// endpoints exposed under /bsvm/* on the JSON-RPC HTTP server.
//
// AcceptUnverifiedBridgeDeposits is the security-critical knob: when
// false (the default) the /bsvm/bridge/deposit endpoint stores the
// envelope but never credits the deposit on L2 — full BRC-62 ancestry
// + script re-execution lands in W6-4 and is the only thing trusted
// to advance bridge balances. Operators running a devnet-style setup
// who want to pre-flight the wiring can flip this to true to allow
// deposits to be funneled into the bridge monitor's pending list
// without ancestry verification.
type BEEFSection struct {
	// Enabled toggles the BEEF endpoints. Default true; set to false
	// on nodes that should not expose the spec-17 surface (e.g.
	// hermetic test deployments or shards that haven't yet onboarded
	// BEEF-producing wallets).
	Enabled bool `toml:"enabled"`
	// AcceptUnverifiedBridgeDeposits relaxes the bridge-deposit
	// anchor-depth requirement only. After W6-4 the BEEF verifier
	// always runs ancestry + script + BUMP checks; this knob, when
	// true, lowers the required confirmations on the target tx to
	// zero so devnet harnesses that mine on demand can credit a
	// deposit immediately. Leave false for production.
	AcceptUnverifiedBridgeDeposits bool `toml:"accept_unverified_bridge_deposits"`
	// MaxDepth caps the longest ancestor chain a BEEF may carry.
	// Default 32; raise only if a wallet legitimately produces deeper
	// envelopes.
	MaxDepth int `toml:"max_depth"`
	// MaxWidth caps the total ancestor count a BEEF may carry across
	// all levels. Default 10000; rejects unbounded envelopes from a
	// malicious peer.
	MaxWidth int `toml:"max_width"`
	// AnchorDepth is the minimum BSV confirmations required on the
	// target tx of a bridge-deposit BEEF before it credits L2.
	// Default 6 — spec 07's "≥ 6 confirmations" rule. Set to 0 only
	// when AcceptUnverifiedBridgeDeposits is also true.
	AnchorDepth uint64 `toml:"anchor_depth"`
	// ValidatedCacheSize is the LRU bound on the validated-tx cache
	// the verifier uses to skip re-execution of common ancestors.
	// Default 4096; ≤0 disables caching.
	ValidatedCacheSize int `toml:"validated_cache_size"`
}

// IndexerSection configures the per-address transaction indexer.
// Operators can disable the indexer entirely to avoid the extra disk
// cost — at the price of the explorer's Address page tx-history panel
// showing "indexer disabled".
type IndexerSection struct {
	// Enabled toggles the indexer. Default true.
	Enabled bool `toml:"enabled"`
	// CacheMB is the LevelDB cache size in megabytes. 16 is plenty for
	// an append-mostly index.
	CacheMB int `toml:"cache_mb"`
	// MaxResults caps the per-query response size. Defaults to 500;
	// 0 means use the default. Hard ceiling is 1000 in pkg/indexer.
	MaxResults int `toml:"max_results"`
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
	// IdentitySeedHex is a 64-char hex-encoded 32-byte seed used to
	// deterministically derive the libp2p peer ID. Leave blank for a
	// fresh random identity at each startup (pre-spec-16 behaviour).
	IdentitySeedHex string `toml:"identity_seed_hex"`
}

// BSVSection holds BSV node connection configuration. The Chaintracks
// sub-section configures the SPV header oracle including W6-2 multi-
// upstream quorum.
type BSVSection struct {
	// NodeURL is the legacy single-endpoint BSV-node JSON-RPC URL.
	// Retained for backward compatibility. New deployments SHOULD
	// list one or more entries under NodeURLs instead; when both are
	// set NodeURLs takes precedence and NodeURL is ignored. When only
	// NodeURL is set, the failover wrapper is constructed with a
	// single-element list (effectively single-node behaviour).
	NodeURL string `toml:"node_url"`
	// NodeURLs lists BSV-node JSON-RPC endpoints in preference order
	// for the W6-11 failover wrapper (pkg/bsvclient.MultiRPCProvider).
	// Index 0 is the primary; subsequent entries are backups consulted
	// on transport / 5xx failures. Application-level RPC errors are
	// NOT retried.
	NodeURLs []string `toml:"node_urls"`
	// NodeMaxConsecutiveFailures parks a node after this many
	// consecutive transport / 5xx failures. Default 3.
	NodeMaxConsecutiveFailures int `toml:"node_max_consecutive_failures"`
	// NodeCooldown is how long a parked node stays out of rotation.
	// Parsed via time.ParseDuration. Default "30s".
	NodeCooldown string `toml:"node_cooldown"`
	// ARCURL is the legacy single-endpoint ARC URL. Retained for
	// backward compatibility with existing deployments. New deployments
	// SHOULD configure one or more entries under ARCEndpoints instead;
	// when both are set ARCEndpoints takes precedence.
	ARCURL string `toml:"arc_url"`
	// ARCEndpoints lists ARC providers for the W6-3 multi-endpoint
	// fan-out broadcaster. See pkg/arc.MultiClient.
	ARCEndpoints []ARCEndpointSection `toml:"arc_endpoint"`
	// ARCStrategy is the fan-out strategy: "first_success" (default)
	// or "quorum".
	ARCStrategy string `toml:"arc_strategy"`
	// ARCQuorum is the minimum endpoint successes required when
	// ARCStrategy is "quorum". Ignored otherwise.
	ARCQuorum int `toml:"arc_quorum"`
	// ARCDefaultTimeout caps each ARC request when an endpoint does
	// not specify its own. Parsed via time.ParseDuration. Defaults
	// to 30s.
	ARCDefaultTimeout string `toml:"arc_default_timeout"`
	// ARCCallbackURL is the per-deployment X-CallbackUrl ARC posts
	// status updates to. Same value across endpoints.
	ARCCallbackURL string `toml:"arc_callback_url"`
	// ARCCallbackToken is the legacy X-CallbackToken auth secret.
	// Used for backward-compat ingress on the callback handler.
	ARCCallbackToken string `toml:"arc_callback_token"`
	// ARCBRC104 configures BRC-104 mutual-auth verification on the
	// inbound callback handler (W6-10). When at least one identity is
	// configured, BRC-104 verification is enabled; the legacy token
	// path is retained based on AllowToken.
	ARCBRC104     ARCBRC104Section `toml:"arc_brc104"`
	Network       string           `toml:"network"`        // mainnet, testnet, regtest
	FeeWalletKey  string           `toml:"fee_wallet_key"` // Path to WIF key file
	Confirmations int              `toml:"confirmations"`
	// WoCCacheSize bounds the in-process LRU cache that wraps the
	// WhatsOnChain client (W6-8). Cached methods are content-addressed
	// and immutable (e.g. GetTx by txid); mutable lookups (chain tip,
	// UTXO sets) bypass the cache. Default 1000 entries. Set to 0 to
	// disable caching entirely (every call hits WoC upstream).
	WoCCacheSize int `toml:"woc_cache_size"`
	// Chaintracks configures the SPV header oracle including the
	// W6-2 multi-upstream quorum. See pkg/chaintracks.MultiClient and
	// docs/decisions/header-oracle-quorum.md.
	Chaintracks ChaintracksSection `toml:"chaintracks"`
}

// EffectiveNodeURLs returns the BSV-node URL list to use for the
// W6-11 failover wrapper. Resolution order:
//
//  1. NodeURLs (when non-empty) — multi-endpoint deployments.
//  2. NodeURL (when non-empty)  — legacy single-endpoint deployments.
//  3. nil                       — node operates without a BSV-node
//     RPC backup (chaintracks + ARC + WoC carry the load).
//
// The slice is returned in preference order: index 0 is primary.
func (b BSVSection) EffectiveNodeURLs() []string {
	if len(b.NodeURLs) > 0 {
		return b.NodeURLs
	}
	if b.NodeURL != "" {
		return []string{b.NodeURL}
	}
	return nil
}

// ARCEndpointSection describes a single ARC endpoint within the
// fan-out broadcaster (W6-3). All fields except URL are optional.
type ARCEndpointSection struct {
	Name          string `toml:"name"`
	URL           string `toml:"url"`
	AuthToken     string `toml:"auth_token"`
	CallbackURL   string `toml:"callback_url"`
	CallbackToken string `toml:"callback_token"`
	// Timeout is parsed via time.ParseDuration. Empty inherits
	// ARCDefaultTimeout.
	Timeout    string `toml:"timeout"`
	MaxRetries int    `toml:"max_retries"`
	// RetryBackoff is parsed via time.ParseDuration. Defaults to 100ms.
	RetryBackoff string `toml:"retry_backoff"`
}

// ARCBRC104Section configures BRC-104 mutual-auth on the inbound
// ARC callback handler (W6-10). When Identities is empty BRC-104 is
// disabled and the handler authenticates against the legacy token.
type ARCBRC104Section struct {
	// Enabled toggles the BRC-104 verifier. When false, callback
	// auth uses the legacy X-CallbackToken path only.
	Enabled bool `toml:"enabled"`
	// Identities lists the trusted ARC server identities. Each entry
	// pins one server's secp256k1 identity public key.
	Identities []ARCBRC104IdentitySection `toml:"identity"`
	// TimestampWindow is parsed via time.ParseDuration. Defaults to
	// 60s. Callbacks outside this window from server clock are rejected.
	TimestampWindow string `toml:"timestamp_window"`
	// NonceCacheSize bounds the in-memory replay-suppression cache.
	// Defaults to 8192. Set negative to disable replay caching
	// (NOT recommended).
	NonceCacheSize int `toml:"nonce_cache_size"`
	// AllowToken keeps the legacy X-CallbackToken path active for
	// ARC servers that have not yet migrated to BRC-104. Defaults
	// to false on new deployments per spec 17 §"ARC callbacks are
	// authenticated".
	AllowToken bool `toml:"allow_token"`
}

// ARCBRC104IdentitySection pins one ARC server's BRC-104 identity.
type ARCBRC104IdentitySection struct {
	// Name is a human-readable label for logs and metrics.
	Name string `toml:"name"`
	// PublicKeyHex is the hex-encoded 33-byte compressed (or 65-byte
	// uncompressed) secp256k1 public key the ARC server signs
	// callbacks with.
	PublicKeyHex string `toml:"public_key_hex"`
}

// ChaintracksSection configures the chaintracks header oracle.
// Single-provider configs (the default) supply exactly one entry in
// Providers and leave QuorumM at zero (defaults to 1). Quorum is
// opt-in: operators add additional [[bsv.chaintracks.providers]]
// blocks and bump QuorumM to enable multi-upstream cross-checking.
// See docs/decisions/header-oracle-quorum.md.
type ChaintracksSection struct {
	// Providers lists the upstream BHS endpoints. At least one
	// entry is required when chaintracks is enabled.
	Providers []ChaintracksProvider `toml:"providers"`
	// QuorumStrategy selects the policy: "hybrid" (default) or
	// "m_of_n".
	QuorumStrategy string `toml:"quorum_strategy"`
	// QuorumM is the minimum number of agreeing providers. Defaults
	// to 1 (no cross-check). Mainnet shards should set this to >=2.
	QuorumM int `toml:"quorum_m"`
	// DisagreementAction is "log" (default), "drop", or "halt".
	DisagreementAction string `toml:"disagreement_action"`
	// DisagreementCooldown is how long a deviant provider stays
	// suspended after ActionDrop. Default "10m".
	DisagreementCooldown string `toml:"disagreement_cooldown"`
	// ResponseTimeout caps each fan-out call. Default "5s".
	ResponseTimeout string `toml:"response_timeout"`
	// StreamSkewWindow is how long stream events buffer per child
	// before quorum is resolved. Default "750ms".
	StreamSkewWindow string `toml:"stream_skew_window"`
	// StreamBufferMax bounds the per-child reorg buffer. Default 32.
	StreamBufferMax int `toml:"stream_buffer_max"`
}

// ChaintracksProvider configures one upstream BHS endpoint.
type ChaintracksProvider struct {
	Name    string `toml:"name"`
	URL     string `toml:"url"`
	APIKey  string `toml:"api_key"`
	Weight  uint   `toml:"weight"`
	Timeout string `toml:"timeout"`
	Enabled bool   `toml:"enabled"`
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
			Network:                    "mainnet",
			Confirmations:              6,
			WoCCacheSize:               1000,
			NodeMaxConsecutiveFailures: 3,
			NodeCooldown:               "30s",
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
		Indexer: IndexerSection{
			Enabled:    true,
			CacheMB:    16,
			MaxResults: 500,
		},
		BEEF: BEEFSection{
			// Endpoints on by default — spec 17 makes them part of
			// the standard surface. Bridge-deposit verification is
			// always strict (ancestry + script + BUMP); the anchor-
			// depth knob below is the only thing relaxed by
			// AcceptUnverifiedBridgeDeposits.
			Enabled:                        true,
			AcceptUnverifiedBridgeDeposits: false,
			MaxDepth:                       32,
			MaxWidth:                       10000,
			AnchorDepth:                    6,
			ValidatedCacheSize:             4096,
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
	if c.Network.IdentitySeedHex != "" {
		seed, err := hex.DecodeString(c.Network.IdentitySeedHex)
		if err == nil && len(seed) == 32 {
			nc.IdentitySeed = seed
		}
	}

	return nc
}
