package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/icellan/bsvm/pkg/network"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/proofmode"
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
	EVM        EVMSection        `toml:"evm"`
	Metrics    MetricsSection    `toml:"metrics"`
	LogLevel   string            `toml:"log_level"`
	LogFormat  string            `toml:"log_format"`
}

// MetricsSection configures the standalone Prometheus /metrics HTTP
// endpoint. The endpoint runs on its own listener (kept separate from
// the JSON-RPC HTTP server) so operators can firewall it independently
// — the JSON-RPC port faces user wallets while /metrics faces the
// internal monitoring network.
//
// When Enabled is false the endpoint is skipped entirely; subsystems
// still construct their counters against a no-op registry so .Inc() /
// .Observe() calls remain safe but the values are never scraped.
type MetricsSection struct {
	// Enabled toggles the standalone /metrics listener. Defaults to
	// true via DefaultNodeConfig — operators have to explicitly opt
	// out, since metrics are cheap and the alternative ("we relied on
	// slog only") is exactly the gap this section closes.
	Enabled bool `toml:"enabled"`
	// ListenAddr is the host:port the metrics HTTP server binds to.
	// Default "127.0.0.1:9100" — loopback-only by default so a fresh
	// install doesn't leak metrics to the public internet. Operators
	// who want their monitoring host to scrape directly can override
	// to "0.0.0.0:9100" (and arrange firewalling via the host).
	ListenAddr string `toml:"listen_addr"`
	// Namespace overrides the metric-name prefix the Counters layer
	// (pkg/metrics/counters.go) builds names under. Defaults to
	// "bsvm" — yields bsvm_bridge_deposits_total, bsvm_arc_broadcast_*,
	// etc. Set to e.g. "myshard" to brand every Counters-owned metric
	// as myshard_*. The spec-17 NetworkMetrics layer (pkg/metrics/
	// network.go) keeps its bsvevm_ prefix because those metric
	// names are part of the public spec-17 surface and cannot be
	// rebranded per deployment without breaking dashboards.
	Namespace string `toml:"namespace"`
}

// EVMSection pins the EVM hardfork the node executes under. Both the
// Go EVM (pkg/vm) and the SP1 guest's revm currently target Cancun;
// this knob exists to make the active fork explicit in operator config
// and to fail fast at startup if a future binary is asked to run a
// fork it doesn't yet implement. The default is "cancun".
//
// Validation is enforced by ValidateFork at config-load time. Adding a
// future fork (Prague delta is the planned post-v1 step, tracked under
// the WW-prague-fork-bump hook in spec 01 §"Source") requires updating
// the supported set here AND wiring the matching jump-table activation
// in pkg/vm AND bumping the SP1 guest's SpecId pin in
// prover/guest/src/main.rs so the public-values layout stays
// byte-identical between the two EVMs.
type EVMSection struct {
	// Fork is the EVM hardfork rule set the node runs under. Only
	// "cancun" is supported in v1 (Prague is deferred under
	// WW-prague-fork-bump). The Rust SP1 guest pins
	// SpecId::CANCUN; the Go EVM defaults DefaultL2Config to
	// CancunTime=0 (active from genesis). Mismatches between this
	// config knob and the binary's compiled fork are a startup
	// error.
	Fork string `toml:"fork"`
}

// supportedEVMForks lists the EVM hardfork names the binary implements.
// The Rust guest in prover/guest/src/main.rs pins SpecId::CANCUN; the
// Go EVM's DefaultL2Config activates Cancun from genesis. EOF (Fusaka)
// and the Prague delta are explicitly excluded per spec 01 — Prague
// is tracked under the WW-prague-fork-bump hook.
var supportedEVMForks = map[string]bool{
	"cancun": true,
}

// ValidateFork confirms the configured EVM fork is one this binary
// implements. Returns nil for empty (default) so older configs without
// the [evm] block continue to load. Any non-empty unsupported value is
// a hard error — better to fail at startup than to silently run on
// the wrong rule set.
func (e EVMSection) ValidateFork() error {
	if e.Fork == "" {
		return nil
	}
	if !supportedEVMForks[strings.ToLower(e.Fork)] {
		return fmt.Errorf("unsupported [evm].fork %q: only \"cancun\" is supported in this binary", e.Fork)
	}
	return nil
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
	// CatchUpPeers are HTTP base URLs for peer JSON-RPC listeners that
	// expose GET /bsvm/beef/covenant-chain. When non-empty, a follower
	// periodically pulls confirmed covenant-advance BEEFs from these
	// peers and replays them through the local covenant consumer.
	CatchUpPeers []string `toml:"catch_up_peers"`
	// CatchUpInterval is the polling cadence for the covenant-chain
	// catch-up loop. Empty defaults to 30s.
	CatchUpInterval string `toml:"catch_up_interval"`
	// CatchUpLimit caps envelopes requested from a peer per HTTP call.
	// Empty/zero defaults to 100; values above 500 are clamped to the
	// server-side maximum.
	CatchUpLimit int `toml:"catch_up_limit"`
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

// ProverSection holds SP1 prover configuration. The fields fall into
// two groups:
//
//  1. Backend selection (Mode, Workers, NetworkURL, Timeout) — picks
//     where and how the SP1 prover runs.
//  2. Proof shape (HostBridgeBinary, GuestELFPath, ProofMode,
//     SP1ProofMode) — picks which artefacts the prover loads and which
//     verification path the produced proof targets on-chain.
//
// All non-Mode/Workers fields default to empty so older configs that
// only set [prover].mode + [prover].workers continue to load. The
// downstream wiring in ToProverConfig() applies the prover package's
// own defaults when fields are blank, and Validate() refuses
// non-mock backends that lack the binary/ELF paths the host bridge
// needs to actually run.
//
// The Workers field is plumbed through OverlayConfig.ProverWorkers
// into the overlay's ParallelProver constructor (see
// pkg/overlay/node.go::NewOverlayNodeWithObservability). Setting >1
// genuinely fans out batch proving across that many concurrent SP1
// invocations.
type ProverSection struct {
	// Mode picks the backend the SP1 host uses: "mock" (default;
	// synthetic proof bytes, no Rust subprocess), "execute" (invoke
	// the host bridge in execute mode — runs revm in SP1's RISC-V
	// emulator, produces real public values + cycle counts but no
	// STARK proof; spec 16's `execute` devnet preset), "local"
	// (invoke the host-bridge binary as a subprocess and produce a
	// real STARK), or "network" (submit to the SP1 prover network —
	// currently returns an error from the host until the SDK
	// subscription path lands).
	Mode string `toml:"mode"`
	// Workers is the maximum number of concurrent proving operations.
	// Plumbed through OverlayConfig.ProverWorkers into the overlay
	// ParallelProver constructor. Zero / negative values are clamped
	// to 1 (single-prover boot path).
	Workers int `toml:"workers"`
	// HostBridgeBinary is the absolute path to the bsvm-host-bridge
	// Rust binary the local-mode prover invokes as a subprocess.
	// Empty falls back to the prover package default (currently
	// empty — the build script's emitted path is consumed by tests
	// directly). Required for Mode != "mock"; Validate() enforces.
	HostBridgeBinary string `toml:"host_bridge_binary"`
	// GuestELFPath is the absolute path to the compiled SP1 guest
	// ELF the host bridge loads. Empty falls back to the in-tree
	// path (or the docker-image rebuild per spec 16's Phase 2 logic).
	// Required for Mode != "mock"; Validate() enforces.
	GuestELFPath string `toml:"guest_elf_path"`
	// NetworkURL is the SP1 prover-network endpoint used when
	// Mode == "network". Empty defers to the SP1 SDK default
	// (https://rpc.succinct.xyz at the time of writing). Required
	// for Mode == "network".
	NetworkURL string `toml:"network_url"`
	// Timeout caps a single Prove() invocation. Parsed via
	// time.ParseDuration. Empty leaves the prover package default
	// (10 minutes) in place. Set to "0s" to disable the timeout
	// entirely (only useful for offline batch proving).
	Timeout string `toml:"timeout"`
	// ProofMode selects the on-chain verification path the produced
	// proof targets: "fri", "groth16", or "groth16-wa" (legacy
	// "groth16-generic" / "groth16-witness" aliases also accepted by
	// the proofmode parser). Empty defaults to "fri" for backward
	// compatibility with the prover package's DefaultConfig. Mock
	// mode ignores this field (mock proofs are not on-chain
	// verifiable); a "groth16" / "groth16-wa" value combined with
	// Mode == "mock" is rejected by Validate() as contradictory.
	ProofMode string `toml:"proof_mode"`
	// SP1ProofMode picks the SP1 proof envelope format the host
	// bridge produces: "compressed" (default), "core", "groth16",
	// or "execute" (no STARK — the bridge's execute branch). This is
	// distinct from ProofMode: SP1ProofMode is the wire-format flag
	// passed to the Rust subprocess, ProofMode is the on-chain
	// verification contract. Empty falls back to the prover
	// package's "compressed" default.
	SP1ProofMode string `toml:"sp1_proof_mode"`
}

// validSP1ProofModes lists the SP1 proof envelope formats the host
// bridge accepts. See pkg/prover/host.go's bridgeInput.Mode handling
// — "execute" is the no-STARK execute branch, the rest map to SP1's
// proof types.
var validSP1ProofModes = map[string]bool{
	"compressed": true,
	"core":       true,
	"groth16":    true,
	"execute":    true,
}

// Validate checks the prover section for ill-formed combinations
// before the node boots. It returns the first problem encountered
// so the operator's error log doesn't have to be parsed top-down.
//
// Rules enforced:
//   - Mode must be empty / "mock" / "local" / "network" (everything
//     else falls through to mock today, but we want a loud error
//     rather than silent fallback for typos like "Local" → already
//     handled, "lcoal" → caught here).
//   - Mode "local" requires HostBridgeBinary AND GuestELFPath; both
//     must point at files that exist on disk.
//   - Mode "network" requires NetworkURL OR an empty value (the SP1
//     SDK has its own default endpoint); when set, the URL must be
//     a parseable absolute URL. We don't try to dial it here — that
//     would couple config validation to network reachability.
//   - Mode "mock" combined with a non-FRI ProofMode is contradictory
//     (mock proofs can't be on-chain verified by Groth16 contracts)
//     and is rejected.
//   - ProofMode must parse via proofmode.Parse if non-empty.
//   - SP1ProofMode must be one of compressed/core/groth16/execute.
//   - Timeout must parse via time.ParseDuration if non-empty.
func (p ProverSection) Validate() error {
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	switch mode {
	case "", "mock", "local", "network", "execute":
		// ok
	default:
		return fmt.Errorf("[prover].mode = %q: expected mock, local, network, or execute", p.Mode)
	}

	if p.Timeout != "" {
		if _, err := time.ParseDuration(p.Timeout); err != nil {
			return fmt.Errorf("[prover].timeout = %q: %w", p.Timeout, err)
		}
	}

	if p.SP1ProofMode != "" {
		key := strings.ToLower(strings.TrimSpace(p.SP1ProofMode))
		if !validSP1ProofModes[key] {
			return fmt.Errorf("[prover].sp1_proof_mode = %q: expected one of compressed, core, groth16, execute",
				p.SP1ProofMode)
		}
	}

	var parsedProofMode proofmode.ProofMode
	if p.ProofMode != "" {
		pm, err := proofmode.Parse(p.ProofMode)
		if err != nil {
			return fmt.Errorf("[prover].proof_mode = %q: %w", p.ProofMode, err)
		}
		parsedProofMode = pm
	}

	switch mode {
	case "local", "execute":
		if p.HostBridgeBinary == "" {
			return fmt.Errorf("[prover].mode = %q requires [prover].host_bridge_binary to be set", p.Mode)
		}
		if p.GuestELFPath == "" {
			return fmt.Errorf("[prover].mode = %q requires [prover].guest_elf_path to be set", p.Mode)
		}
		if _, err := os.Stat(p.HostBridgeBinary); err != nil {
			return fmt.Errorf("[prover].host_bridge_binary %q: %w", p.HostBridgeBinary, err)
		}
		if _, err := os.Stat(p.GuestELFPath); err != nil {
			return fmt.Errorf("[prover].guest_elf_path %q: %w", p.GuestELFPath, err)
		}
	case "network":
		// The SP1 SDK supplies a default endpoint when NetworkURL is
		// empty, so we don't insist on a value here. We only sanity-
		// check format when one is supplied.
		if p.NetworkURL != "" {
			if u, err := url.Parse(p.NetworkURL); err != nil || !u.IsAbs() {
				if err == nil {
					err = fmt.Errorf("not an absolute URL")
				}
				return fmt.Errorf("[prover].network_url = %q: %w", p.NetworkURL, err)
			}
		}
	case "", "mock":
		// Mock mode never invokes the Rust subprocess; binary / ELF
		// paths are accepted but not required. The contradictory
		// combination is mock + Groth16 proof mode (mock proofs can't
		// satisfy a Groth16 on-chain verifier).
		if p.ProofMode != "" && parsedProofMode != proofmode.FRI {
			return fmt.Errorf(
				"[prover].mode = %q with [prover].proof_mode = %q is contradictory: "+
					"mock proofs cannot satisfy a Groth16 on-chain verifier; "+
					"either drop proof_mode or switch to mode = \"local\" / \"network\"",
				p.Mode, p.ProofMode,
			)
		}
	}

	return nil
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
	// WoCBlockTxFanoutMax caps the per-block tx-fetch fan-out used by
	// the chaintracks-only block-scan path (cmd/bsvm/bridge_bsv_client.go).
	// Default 1_000_000 — well above any block ever mined and trivial
	// in memory cost. Operators with strict WoC rate-limit budgets may
	// dial it lower; operators on a paid tier with high-throughput
	// shards may raise it. Set to 0 to use the package default.
	WoCBlockTxFanoutMax int `toml:"woc_block_tx_fanout_max"`
	// WoCBlockPageFetchWorkers caps the per-block page-fetch concurrency
	// used by the paginated GetBlockTxIDs path (pkg/whatsonchain).
	// Default 4 — balances throughput against burst-load on the WoC
	// API. Operators on a paid tier may raise this for faster cold-
	// start scans; operators on the free tier should keep it low. Set
	// to 0 to use the package default.
	WoCBlockPageFetchWorkers int `toml:"woc_block_page_fetch_workers"`
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
	// BridgeScriptHex is the hex-encoded BSV-side bridge covenant
	// locking script the deposit verifier matches against. Operators
	// derive this from the deployed bridge covenant transaction once
	// the L1 bridge is provisioned. When empty the BEEF bridge
	// consumer falls through to the pre-Item-3 fail-closed path:
	// envelopes are stored but no L2 credit is applied.
	BridgeScriptHex string `toml:"bridge_script_hex"`

	// BridgeScriptHexHistory is the ordered list of PRIOR bridge
	// covenant locking scripts (oldest first). When the bridge
	// covenant is upgraded mid-walk via governance freeze+upgrade the
	// cold-boot recovery's chain walker matches outputs against ANY
	// of these hashes plus the current BridgeScriptHex; the most
	// recent (newest version) match wins, and the upgrade boundary is
	// logged loudly. Leaving this empty means "no upgrades" (the
	// walker matches BridgeScriptHex only). Each entry is the hex
	// encoding of a complete locking script — same format as
	// BridgeScriptHex.
	BridgeScriptHexHistory []string `toml:"bridge_script_hex_history"`

	// BridgeUTXOTxIDHex / BridgeUTXOVout / BridgeUTXOBalanceSat seed the
	// live bridge UTXO snapshot the BridgeMonitor exposes via
	// CurrentBridgeUTXO. Operators set these once at boot from the most
	// recent on-chain bridge UTXO; subsequent advances + claim broadcasts
	// roll the snapshot forward in memory. When empty the snapshot stays
	// nil and the withdrawal-claim loop runs idle.
	BridgeUTXOTxIDHex    string `toml:"bridge_utxo_txid_hex"`
	BridgeUTXOVout       uint32 `toml:"bridge_utxo_vout"`
	BridgeUTXOBalanceSat uint64 `toml:"bridge_utxo_balance_sat"`
	// BridgeUTXOLastClaimedNonce mirrors the bridge covenant's
	// lastClaimedNonce slot. New deployments leave it 0; recovery boots
	// (after a node DB wipe) set it to the highest already-claimed nonce
	// so the Withdrawer doesn't re-attempt completed claims.
	BridgeUTXOLastClaimedNonce uint64 `toml:"bridge_utxo_last_claimed_nonce"`

	// ClaimFeeSatPerByte is the BSV miner fee rate applied to withdrawal
	// claim transactions. The fee is subtracted from the bridge UTXO's
	// change output (Output 0) so the user receives the full
	// withdrawal amount. Defaults to 1 sat/byte. Set to 0 to disable
	// fee subtraction (only useful for hermetic tests where the BSV
	// miner-fee path is irrelevant).
	ClaimFeeSatPerByte int64 `toml:"claim_fee_sat_per_byte"`
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
			WoCBlockTxFanoutMax:        1_000_000,
			WoCBlockPageFetchWorkers:   4,
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
			CatchUpInterval:                "30s",
			CatchUpLimit:                   100,
		},
		EVM: EVMSection{
			// Cancun is the active fork in v1 — both the Go EVM
			// (pkg/vm.DefaultL2Config) and the SP1 guest's revm
			// (prover/guest/src/main.rs) execute Cancun rules.
			// Document the active fork in operator config so future
			// fork bumps are visible.
			Fork: "cancun",
		},
		Metrics: MetricsSection{
			// Default-on: the operator runbook relied on slog alone
			// before this gap was closed; turning the endpoint off
			// requires explicit opt-out so a fresh install always has
			// /metrics available.
			Enabled:    true,
			ListenAddr: "127.0.0.1:9100",
			Namespace:  "bsvm",
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
	// Validate the [evm].fork knob early so an unsupported value (e.g.
	// "prague" against a Cancun-only binary) fails before any state is
	// touched.
	if err := cfg.EVM.ValidateFork(); err != nil {
		return nil, err
	}
	// Validate the [prover] section so an operator who set
	// mode = "local" without a host_bridge_binary path (or who
	// combined mock with a Groth16 proof_mode) fails at startup
	// rather than silently falling back to mock proving — see the
	// "mainnet blast radius" note in
	// docs/decisions/spec-review-triage-2026-05.md (Claim 1).
	if err := cfg.Prover.Validate(); err != nil {
		return nil, err
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

	// Plumb [prover].workers through to the overlay so
	// NewOverlayNodeWithObservability constructs the ParallelProver with
	// the operator's chosen concurrency. Zero / negative values fall
	// back to the overlay's single-prover default.
	if c.Prover.Workers > 0 {
		oc.ProverWorkers = c.Prover.Workers
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
// prover.Config. Empty TOML fields fall back to the values
// prover.DefaultConfig() supplies; Validate() (called from
// LoadNodeConfig) is responsible for rejecting ill-formed
// combinations before this conversion runs.
func (c *NodeConfig) ToProverConfig() prover.Config {
	pc := prover.DefaultConfig()

	switch strings.ToLower(strings.TrimSpace(c.Prover.Mode)) {
	case "local":
		pc.Mode = prover.ProverLocal
	case "network":
		pc.Mode = prover.ProverNetwork
	case "execute":
		pc.Mode = prover.ProverExecute
	default:
		pc.Mode = prover.ProverMock
	}

	if c.Prover.HostBridgeBinary != "" {
		pc.HostBridgeBinary = c.Prover.HostBridgeBinary
	}
	if c.Prover.GuestELFPath != "" {
		pc.GuestELFPath = c.Prover.GuestELFPath
	}
	if c.Prover.NetworkURL != "" {
		pc.NetworkURL = c.Prover.NetworkURL
	}
	if c.Prover.Timeout != "" {
		// Validate() already proved this parses; ignore the residual
		// error here so a programmatic caller that bypasses
		// LoadNodeConfig + Validate still gets the default rather
		// than a silent zero.
		if d, err := time.ParseDuration(c.Prover.Timeout); err == nil {
			pc.Timeout = d
		}
	}
	if c.Prover.ProofMode != "" {
		// Same rationale: Validate() already accepted this string.
		if pm, err := proofmode.Parse(c.Prover.ProofMode); err == nil {
			pc.ProofMode = pm
		}
	}
	if c.Prover.SP1ProofMode != "" {
		pc.SP1ProofMode = strings.ToLower(strings.TrimSpace(c.Prover.SP1ProofMode))
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
