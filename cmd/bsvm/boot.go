// Shared bootstrap glue for `bsvm run`. Phase 8 replaced the
// shard.json-driven boot with a genesis-txid-driven boot where all
// shard identity comes straight from the covenant deploy transaction.
// Both paths converge on the same runtime surface — this file defines
// the convergent struct (bootResult) and implements the two boot
// helpers:
//
//   - bootFromGenesisTxID:  fetch covenant tx from BSV, derive
//     config, run local InitGenesis.
//   - bootFromShardConfig:  legacy path — load a shard.json and a
//     per-node DB seeded by init-local (or a single-node init).
//
// Callers downstream of boot — covenant manager, overlay node, RPC
// server, gossip — take the same inputs regardless of which path
// produced them.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/bsvclient"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/shard"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// genesisCacheFile is where bootFromGenesisTxID persists the raw tx
// hex the first time it successfully fetches/receives it. Subsequent
// restarts read the cache first, skipping the P2P / RPC round-trip.
const genesisCacheFile = "genesis.cache"

// bootResult is the common state bsvm run needs from either boot
// path. Everything downstream (overlay node, covenant manager, RPC,
// networking) is parameterised on these fields and doesn't care
// whether they came from a shard.json or a genesis-tx derivation.
type bootResult struct {
	// DB is the opened per-node key-value database.
	DB db.Database
	// ChainDB is the typed read/write facade around DB for block
	// data.
	ChainDB *block.ChainDB
	// StateDB is opened at the current head's state root.
	StateDB *state.StateDB
	// ChainConfig is the EVM chain configuration (chainID + forks).
	ChainConfig *vm.ChainConfig

	// ChainID is the EIP-155 chain ID.
	ChainID int64
	// GenesisCovenantTxID identifies the shard on BSV.
	GenesisCovenantTxID types.Hash
	// GenesisCovenantVout is the covenant UTXO output index (0
	// today).
	GenesisCovenantVout uint32
	// CovenantSats is the satoshi amount carried by the covenant
	// UTXO.
	CovenantSats uint64
	// GenesisStateRoot is the state root the covenant binds at
	// genesis. Used by the covenant manager's initial CovenantState
	// and by the Synced check below.
	GenesisStateRoot types.Hash
	// Verification is the detected/declared verification mode.
	Verification covenant.VerificationMode
	// Governance is the typed governance config (mode + keys +
	// threshold).
	Governance covenant.GovernanceConfig
	// SP1VerifyingKey is the full VK bytes. Empty-on-error tolerated
	// because the FRI / DevKey scripts don't consult it on-chain.
	SP1VerifyingKey []byte

	// Synced is true when the local head matches the derived genesis
	// state root. Callers use this to decide whether to kick off a
	// P2P / BSV sync.
	Synced bool

	// LegacyShardConfig is set only when the boot came from a
	// shard.json file. wireBSVBroadcast's legacy rollup-source helper
	// consumes this; the new derived-from-txid path produces a nil
	// value here.
	LegacyShardConfig *shard.ShardConfig

	// GenesisRawTxHex is the hex-encoded raw genesis covenant tx
	// this node resolved during boot. Populated on the
	// genesis-txid path so the main gossip manager can answer
	// GenesisRequest streams from other peers that are still
	// trying to bootstrap. Empty on the legacy shard.json path.
	GenesisRawTxHex string
}

// RawTxSource is a pluggable function that yields the raw genesis
// transaction hex the boot layer will derive the shard from. Each
// source is tried in turn (file → local cache → BSV RPC → P2P) and
// the first one that returns a non-empty hex string wins. Hash
// verification happens AFTER source selection, not inside the
// source itself — so every source produces raw bytes under the
// same set of guarantees.
type RawTxSource func(ctx context.Context) (rawTxHex string, err error)

// bootGenesisOpts gathers the optional inputs bootFromGenesisTxID
// considers when resolving the raw genesis tx. All fields are
// optional; the boot layer tries them in the order listed in the
// field docstrings and errors only after every non-nil source has
// been exhausted.
type bootGenesisOpts struct {
	// TxFilePath points at a file on disk containing the raw
	// genesis tx hex (the file --genesis-tx-file points at).
	// Precedence: FIRST (operator-provided bytes are trusted over
	// any cached or remote source).
	TxFilePath string
	// Provider is a live BSV RPC provider. When non-nil, the boot
	// layer can fetch the raw tx via getrawtransaction if file /
	// cache are unavailable.
	Provider *bsvclient.RPCProvider
	// PeerSync, when non-nil, is called to sync the raw tx from
	// peers over libp2p as a last-resort fallback. Typically this
	// wraps GossipManager.RequestGenesisFromPeers.
	PeerSync RawTxSource
}

// bootFromGenesisTxID is the Phase 8/9 boot path. It resolves the raw
// genesis covenant transaction hex from any of: a local file, a
// persistent on-disk cache, a BSV RPC provider, or a P2P peer. Every
// source is subject to the same hash check: double_sha256(rawBytes)
// reversed MUST equal the configured genesisTxIDHex. After resolution
// it runs shard.DeriveShardFromRawTx to recover every config
// dimension, then opens (or initialises) the per-node LevelDB so the
// local head matches the covenant's genesis state root.
//
// The caller is no longer required to supply a BSV RPC provider:
// follower nodes with no RPC access can pass nil and rely on
// bootGenesisOpts.PeerSync instead. At least one source MUST be
// supplied or the boot aborts.
func bootFromGenesisTxID(
	ctx context.Context,
	genesisTxIDHex string,
	dataDir string,
	gasLimit uint64,
	opts bootGenesisOpts,
) (*bootResult, error) {
	// Ensure KZG trusted setup loaded (point evaluation precompile).
	if err := vm.InitKZGTrustedSetup(""); err != nil {
		return nil, fmt.Errorf("initializing KZG trusted setup: %w", err)
	}

	// 1. Resolve + hash-verify the raw genesis tx.
	rawTxHex, source, err := resolveRawGenesisTx(ctx, genesisTxIDHex, dataDir, opts)
	if err != nil {
		return nil, fmt.Errorf("resolve genesis tx %s: %w", genesisTxIDHex, err)
	}
	slog.Info("genesis tx resolved",
		"source", source,
		"txid", genesisTxIDHex,
		"rawBytes", len(rawTxHex)/2,
	)

	// 2. Cache the raw hex for future restarts. Best-effort — a
	// cache write failure is logged but not fatal.
	if source != "cache" {
		if werr := writeGenesisCache(dataDir, rawTxHex); werr != nil {
			slog.Warn("genesis cache write failed (non-fatal)", "error", werr)
		}
	}

	// 3. Derive the shard from the verified raw bytes.
	derived, err := shard.DeriveShardFromRawTx(rawTxHex)
	if err != nil {
		return nil, fmt.Errorf("derive shard from raw tx: %w", err)
	}
	// Pin the txid to the exact string the operator configured so
	// downstream log lines show the same txid across all nodes.
	// genesisTxIDHex is a BSV txid (big-endian display form) —
	// BSVHashFromHex reverses into chainhash little-endian storage.
	derived.GenesisTxID = types.BSVHashFromHex(genesisTxIDHex)
	slog.Info("shard derived from covenant",
		"txid", derived.GenesisTxID.BSVString(),
		"chainID", derived.ChainID,
		"verification", derived.Verification.String(),
		"governanceMode", derived.Governance.Mode.String(),
		"governanceThreshold", derived.Governance.Threshold,
		"governanceKeys", len(derived.Governance.Keys),
		"alloc", len(derived.Alloc),
		"covenantSats", derived.CovenantSats,
	)

	// 2. Open the local DB.
	dbPath := filepath.Join(dataDir, "chaindata")
	database, err := db.NewLevelDB(dbPath, 256, 256)
	if err != nil {
		return nil, fmt.Errorf("opening database at %s: %w", dbPath, err)
	}

	chainDB := block.NewChainDB(database)
	chainConfig := vm.DefaultL2Config(derived.ChainID)

	// 3. Run genesis if the DB is empty, otherwise open at the head.
	effectiveGasLimit := gasLimit
	if effectiveGasLimit == 0 {
		if derived.GasLimit > 0 {
			effectiveGasLimit = derived.GasLimit
		} else {
			effectiveGasLimit = block.DefaultGasLimit
		}
	}
	var stateRoot types.Hash
	synced := false

	if head := chainDB.ReadHeadBlockHash(); head != (types.Hash{}) {
		headHeader := chainDB.ReadHeadHeader()
		if headHeader == nil {
			database.Close()
			return nil, fmt.Errorf("head block hash set but header not found")
		}
		stateRoot = headHeader.StateRoot
		if stateRoot == derived.GenesisStateRoot {
			synced = true
		}
		slog.Info("boot: local DB already initialized",
			"headBlock", headHeader.Number, "stateRoot", stateRoot.Hex(),
			"matchesGenesis", stateRoot == derived.GenesisStateRoot)
	} else {
		header, initErr := block.InitGenesis(database, &block.Genesis{
			Config:    chainConfig,
			Timestamp: uint64(derived.GenesisTimestamp),
			GasLimit:  effectiveGasLimit,
			Alloc:     derived.Alloc,
		})
		if initErr != nil {
			database.Close()
			return nil, fmt.Errorf("initialize genesis: %w", initErr)
		}
		stateRoot = header.StateRoot
		// Refuse to boot if the local InitGenesis produced a state
		// root different from what the covenant binds — a mismatch
		// means the manifest's alloc is out of sync with the
		// deployed covenant and every subsequent advance would fail
		// on-chain anyway.
		if stateRoot != derived.GenesisStateRoot {
			database.Close()
			return nil, fmt.Errorf(
				"local InitGenesis produced state root %s; covenant binds %s — manifest alloc out of sync with deploy",
				stateRoot.Hex(), derived.GenesisStateRoot.Hex(),
			)
		}
		synced = true
		slog.Info("boot: local genesis initialised", "stateRoot", stateRoot.Hex())
	}

	sdb, err := state.New(stateRoot, database)
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("open state at %s: %w", stateRoot.Hex(), err)
	}

	return &bootResult{
		DB:                  database,
		ChainDB:             chainDB,
		StateDB:             sdb,
		ChainConfig:         chainConfig,
		ChainID:             derived.ChainID,
		GenesisCovenantTxID: derived.GenesisTxID,
		GenesisCovenantVout: derived.GenesisCovenantVout,
		CovenantSats:        derived.CovenantSats,
		GenesisStateRoot:    derived.GenesisStateRoot,
		Verification:        derived.Verification,
		Governance:          derived.Governance,
		SP1VerifyingKey:     derived.SP1VerifyingKey,
		Synced:              synced,
		GenesisRawTxHex:     rawTxHex,
	}, nil
}

// bootFromShardConfig is the legacy shard.json path. Kept as-is so
// existing integration tests and the pre-Phase-8 init-cluster /
// init-local workflow remain functional.
func bootFromShardConfig(configPath, dataDir string) (*bootResult, error) {
	joinResult, err := shard.JoinShard(configPath, dataDir)
	if err != nil {
		return nil, err
	}
	cfg := joinResult.Config

	verifyMode, err := parseVerificationModeString(cfg.VerificationMode)
	if err != nil {
		joinResult.DB.Close()
		return nil, err
	}
	govConfig, err := cfg.GovernanceConfig()
	if err != nil {
		joinResult.DB.Close()
		return nil, err
	}
	sp1VK, _ := decodeHexOptional(cfg.SP1VerifyingKey)

	return &bootResult{
		DB:          joinResult.DB,
		ChainDB:     joinResult.ChainDB,
		StateDB:     joinResult.StateDB,
		ChainConfig: joinResult.ChainConfig,
		ChainID:     cfg.ChainID,
		// GenesisCovenantTxID is a BSV txid (big-endian display form in
		// the shard.json file) — use BSVHashFromHex so in-memory bytes
		// end up in chainhash little-endian order.
		GenesisCovenantTxID: types.BSVHashFromHex(cfg.GenesisCovenantTxID),
		GenesisCovenantVout: cfg.GenesisCovenantVout,
		CovenantSats:        cfg.CovenantSats,
		// GenesisStateRoot is an L2 / EVM hash — keep big-endian bytes
		// matching big-endian hex convention.
		GenesisStateRoot:  types.HexToHash(cfg.GenesisStateRoot),
		Verification:      verifyMode,
		Governance:        govConfig,
		SP1VerifyingKey:   sp1VK,
		Synced:            joinResult.Synced,
		LegacyShardConfig: cfg,
	}, nil
}

// parseVerificationModeString mirrors the switch in main.go's legacy
// cmdRun. Extracted so both boot paths converge on the same typed
// value.
func parseVerificationModeString(s string) (covenant.VerificationMode, error) {
	switch s {
	case "fri":
		return covenant.VerifyFRI, nil
	case "groth16":
		return covenant.VerifyGroth16, nil
	case "groth16-wa":
		return covenant.VerifyGroth16WA, nil
	case "devkey":
		return covenant.VerifyDevKey, nil
	default:
		return 0, fmt.Errorf("unknown verification mode %q", s)
	}
}

// decodeHexOptional returns the decoded bytes for a hex string, or
// nil on decode errors / empty input. Used for SP1 VK where an
// invalid hex is tolerated on the non-enforcing modes.
func decodeHexOptional(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// resolveRawGenesisTx tries every configured source in priority
// order and returns the first one whose bytes hash to expectedTxID.
// Returns the raw tx hex and a short label identifying the source
// ("file", "cache", "rpc", or "peer"). Every candidate is subject
// to the same shard.VerifyRawTxMatchesTxID check — sources are
// plug-ins, not trust boundaries.
//
// Priority:
//  1. opts.TxFilePath — operator supplied the bytes explicitly.
//  2. <datadir>/genesis.cache — previous run persisted it.
//  3. opts.Provider — fetch via BSV RPC (traditional Phase 8 path).
//  4. opts.PeerSync — request from peers over libp2p.
//
// Every source that is not configured is skipped silently. If all
// configured sources fail, the last error is returned so the
// operator can tell which layer was responsible.
func resolveRawGenesisTx(
	ctx context.Context,
	expectedTxID, dataDir string,
	opts bootGenesisOpts,
) (rawTxHex, source string, err error) {
	type candidate struct {
		label string
		raw   string
		err   error
	}
	var tried []candidate

	// 1. --genesis-tx-file.
	if opts.TxFilePath != "" {
		raw, ferr := readTxFile(opts.TxFilePath)
		tried = append(tried, candidate{"file", raw, ferr})
		if ferr == nil {
			if verr := shard.VerifyRawTxMatchesTxID(raw, expectedTxID); verr == nil {
				return raw, "file", nil
			} else {
				tried[len(tried)-1].err = verr
				slog.Warn("genesis-tx-file hash mismatch — ignoring file and trying other sources",
					"path", opts.TxFilePath, "error", verr)
			}
		}
	}

	// 2. local cache.
	if cached, cerr := readTxFile(filepath.Join(dataDir, genesisCacheFile)); cerr == nil {
		tried = append(tried, candidate{"cache", cached, nil})
		if verr := shard.VerifyRawTxMatchesTxID(cached, expectedTxID); verr == nil {
			return cached, "cache", nil
		} else {
			slog.Warn("genesis cache hash mismatch — ignoring and trying other sources",
				"path", filepath.Join(dataDir, genesisCacheFile), "error", verr)
			tried[len(tried)-1].err = verr
		}
	}

	// 3. BSV RPC.
	if opts.Provider != nil {
		txData, rerr := opts.Provider.GetTransaction(expectedTxID)
		if rerr != nil {
			tried = append(tried, candidate{"rpc", "", rerr})
		} else if txData == nil || txData.Raw == "" {
			tried = append(tried, candidate{"rpc", "", fmt.Errorf("provider returned empty raw tx")})
		} else {
			tried = append(tried, candidate{"rpc", txData.Raw, nil})
			if verr := shard.VerifyRawTxMatchesTxID(txData.Raw, expectedTxID); verr == nil {
				return txData.Raw, "rpc", nil
			} else {
				slog.Warn("BSV RPC returned a tx whose hash doesn't match — refusing to trust it",
					"error", verr)
				tried[len(tried)-1].err = verr
			}
		}
	}

	// 4. P2P peer sync.
	if opts.PeerSync != nil {
		raw, perr := opts.PeerSync(ctx)
		if perr != nil {
			tried = append(tried, candidate{"peer", "", perr})
		} else {
			tried = append(tried, candidate{"peer", raw, nil})
			if verr := shard.VerifyRawTxMatchesTxID(raw, expectedTxID); verr == nil {
				return raw, "peer", nil
			} else {
				slog.Warn("peer returned a tx whose hash doesn't match — refusing to trust it",
					"error", verr)
				tried[len(tried)-1].err = verr
			}
		}
	}

	if len(tried) == 0 {
		return "", "", fmt.Errorf("no genesis tx source configured (need --genesis-tx-file, --bsv-rpc, or a P2P peer)")
	}
	// Summarise what was tried so the operator can see exactly which
	// path(s) were exhausted.
	var parts []string
	for _, c := range tried {
		if c.err != nil {
			parts = append(parts, fmt.Sprintf("%s: %v", c.label, c.err))
		} else {
			parts = append(parts, fmt.Sprintf("%s: hash mismatch", c.label))
		}
	}
	return "", "", fmt.Errorf("exhausted all genesis sources (%s)", strings.Join(parts, "; "))
}

// readTxFile reads a file containing raw tx hex and returns the
// trimmed content. Used uniformly for --genesis-tx-file and the
// on-disk cache so both paths tolerate trailing newlines / leading
// whitespace identically.
func readTxFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("read tx file: empty path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read tx file %s: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// writeGenesisCache persists the raw-tx hex to <datadir>/genesis.cache
// so the next restart can skip the RPC / P2P round-trip. Writes the
// hex with a trailing newline (matching readTxFile's TrimSpace) and
// 0644 permissions (the file contains public data).
func writeGenesisCache(dataDir, rawTxHex string) error {
	if dataDir == "" {
		return fmt.Errorf("datadir must not be empty")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dataDir, err)
	}
	path := filepath.Join(dataDir, genesisCacheFile)
	if err := os.WriteFile(path, []byte(rawTxHex+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
