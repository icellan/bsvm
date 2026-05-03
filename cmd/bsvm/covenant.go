// `bsvm covenant tip` is a read-only operator helper that prints the
// live covenant UTXO state for the locally-cached shard. It is the
// runbook companion to `deploy/covenant/cmd/rotate-vk` (see
// docs/operator/vk-rotation.md §1, §6) — its output is the exact set of
// fields a `RotateVKConfig` JSON needs filled in before a VK rotation
// can be assembled and broadcast.
//
// The subcommand is intentionally narrow: it never writes to chaindata,
// never broadcasts anything to BSV, and never opens any of the
// daemon's heavier subsystems (no overlay, no gossip, no prover). It
// only:
//
//  1. Reads the locally-cached covenant tip from <datadir>/chaindata
//     via pkg/block.ChainDB.ReadCovenantTxID +
//     pkg/block.ChainDB.ReadCovenantState.
//  2. Asks the configured BSV node (`--bsv-rpc` / $BSVM_BSV_RPC) for
//     the live covenant UTXO's locking-script hex + satoshi value via
//     getrawtransaction verbose=1.
//  3. Emits a single JSON object on stdout with the union of the local
//     and on-chain fields the rotation runbook requires.
//
// The runbook's `pkg/covenant.LoadState` and `pkg/covenant.ReadRollupState`
// helpers do not actually exist; the helpers we use instead live on
// pkg/block.ChainDB and pkg/covenant.DecodeCovenantState. This is
// documented in the runbook update accompanying the subcommand's
// introduction.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/urfave/cli/v2"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// covenantCommand returns the urfave/cli command spec for
// `bsvm covenant ...`. Today it carries a single subcommand (`tip`);
// future operator-ergonomics work (covenant tail, etc.) can hang off
// the same parent.
func covenantCommand() *cli.Command {
	return &cli.Command{
		Name:  "covenant",
		Usage: "Read-only operator helpers for the rollup covenant UTXO chain",
		Subcommands: []*cli.Command{
			{
				Name:  "tip",
				Usage: "Print the live covenant UTXO tip as JSON (covenantTxId, covenantVout, covenantSatsLive, currentStateRootHex, currentBlockNumber, lockingScriptHex, lockingScriptSha256)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "datadir",
						Value: "./data",
						Usage: "path to data directory (must contain chaindata/)",
					},
					&cli.StringFlag{
						Name:    "bsv-rpc",
						Usage:   "BSV JSON-RPC endpoint (user:pass@host:port). Defaults to $BSVM_BSV_RPC",
						EnvVars: []string{"BSVM_BSV_RPC"},
					},
					&cli.StringFlag{
						Name:    "bsv-network",
						Value:   "regtest",
						Usage:   "BSV network: regtest|testnet|mainnet (defaults to $BSVM_BSV_NETWORK or regtest)",
						EnvVars: []string{"BSVM_BSV_NETWORK"},
					},
					&cli.StringFlag{
						Name:  "shard-id",
						Usage: "optional shard identifier for the output (defaults to <datadir>/genesis.txid or <datadir>/shard.json)",
					},
				},
				Action: cmdCovenantTip,
			},
		},
	}
}

// CovenantTip is the on-stdout JSON shape `bsvm covenant tip` emits.
// Field names mirror the rotation-only fields of
// `deploy/covenant/rotate-vk.go::RotateVKConfig` so an operator can
// drop them straight into a rotation config.
//
// CurrentStateRootHex carries the canonical 0x-prefixed hex form
// pkg/types.Hash uses; CovenantTxId carries the BSV-canonical big-
// endian display form (no 0x prefix), matching the rotate-vk config's
// expectation. LockingScriptSha256 is the bare sha256 of the locking
// script bytes (no double-sha, no reversal) — matches the bridge re-
// deploy flow's `StateCovenantScriptHash` shape.
type CovenantTip struct {
	ShardID             string `json:"shardId,omitempty"`
	CovenantTxID        string `json:"covenantTxId"`
	CovenantVout        uint32 `json:"covenantVout"`
	CovenantSatsLive    uint64 `json:"covenantSatsLive"`
	CurrentStateRootHex string `json:"currentStateRootHex"`
	CurrentBlockNumber  uint64 `json:"currentBlockNumber"`
	LockingScriptHex    string `json:"lockingScriptHex"`
	LockingScriptSha256 string `json:"lockingScriptSha256"`
}

// covenantTipChainReader is the minimum surface BuildCovenantTip needs
// from the local chaindata. ChainDB satisfies it; tests use a hand-
// rolled in-memory implementation.
type covenantTipChainReader interface {
	ReadCovenantTxID() types.Hash
	ReadCovenantState() []byte
}

// covenantUTXOFetcher resolves a covenant UTXO's live BSV state given
// its txid and (always-zero) vout. It returns the locking-script hex,
// the satoshi value carried by that output, and any fetch error.
//
// In production this is a thin wrapper around BSVProviderClient.
// GetRawTransactionVerbose; tests substitute a fixture closure.
type covenantUTXOFetcher func(txidBSVDisplay string, vout uint32) (lockingScriptHex string, sats uint64, err error)

// cmdCovenantTip is the urfave/cli action handler. It opens the local
// chaindata read-only-in-spirit (LevelDB doesn't ship a true read-only
// mode but the helper writes nothing), constructs a BSV-node fetcher
// from the standard --bsv-rpc / $BSVM_BSV_RPC plumbing, and hands both
// to BuildCovenantTip.
func cmdCovenantTip(ctx *cli.Context) error {
	dataDir := strings.TrimSpace(ctx.String("datadir"))
	if dataDir == "" {
		return fmt.Errorf("--datadir is required")
	}

	// 1. Resolve the BSV provider via the standard config surface so
	// operators can pass --bsv-rpc, set $BSVM_BSV_RPC, or rely on a
	// node TOML pointed at by $BSVM_CONFIG. Without an RPC endpoint
	// we cannot fetch the live covenant UTXO's locking script or
	// satoshi value, which are the whole point of the subcommand.
	nodeCfg := DefaultNodeConfig()
	if err := ApplyEnvOverrides(nodeCfg); err != nil {
		return fmt.Errorf("applying env overrides: %w", err)
	}
	if v := strings.TrimSpace(ctx.String("bsv-rpc")); v != "" {
		nodeCfg.BSV.NodeURL = v
	}
	if v := strings.TrimSpace(ctx.String("bsv-network")); v != "" {
		nodeCfg.BSV.Network = v
	}
	if len(nodeCfg.BSV.EffectiveNodeURLs()) == 0 {
		return fmt.Errorf("no BSV RPC endpoint configured: set --bsv-rpc or BSVM_BSV_RPC")
	}
	provider, err := BuildBSVProvider(nodeCfg.BSV)
	if err != nil {
		return fmt.Errorf("building BSV provider: %w", err)
	}
	if provider == nil {
		// BuildBSVProvider returns (nil, nil) only when EffectiveNodeURLs
		// is empty; we already gated on that above. Defensive belt.
		return fmt.Errorf("BSV provider construction returned nil despite configured endpoints")
	}

	// 2. Open chaindata. We never write so the daemon-vs-tip race is
	// confined to LevelDB's own MVCC; the goleveldb backend tolerates a
	// concurrent read-only opener so long as there is at most one
	// writer (the daemon) and our reads see a consistent snapshot.
	//
	// In practice operators run `bsvm covenant tip` against a stopped
	// node before kicking off a rotation; the docstring will say so.
	dbPath := filepath.Join(dataDir, "chaindata")
	if _, statErr := os.Stat(dbPath); statErr != nil {
		return fmt.Errorf("chaindata not found at %s: %w", dbPath, statErr)
	}
	database, err := db.NewLevelDB(dbPath, 256, 256)
	if err != nil {
		return fmt.Errorf("opening database at %s: %w", dbPath, err)
	}
	defer database.Close()
	chainDB := block.NewChainDB(database)

	// 3. Build the BSV-side fetcher closure. Using the verbose
	// getrawtransaction lets us pull both the locking-script hex and
	// the satoshi value from a single call.
	fetcher := newProviderUTXOFetcher(provider)

	// 4. Resolve the optional shard identifier — purely informational,
	// printed as-is when set.
	shardID := strings.TrimSpace(ctx.String("shard-id"))
	if shardID == "" {
		shardID = inferShardID(dataDir)
	}

	// 5. Build the tip and emit it.
	tip, err := BuildCovenantTip(chainDB, fetcher, shardID, dataDir)
	if err != nil {
		return err
	}
	enc, err := json.MarshalIndent(tip, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tip: %w", err)
	}
	if _, err := os.Stdout.Write(append(enc, '\n')); err != nil {
		return fmt.Errorf("write tip: %w", err)
	}
	return nil
}

// BuildCovenantTip is the pure / testable core of `bsvm covenant tip`.
// It reads the locally-cached covenant tip from chainDB, asks fetcher
// for the live UTXO's locking script + satoshi value, and assembles
// a CovenantTip ready for JSON emission.
//
// dataDir is consulted ONLY as a fallback when chainDB hasn't seen
// any covenant advance yet (ReadCovenantTxID returns the zero hash):
// in that case we fall back to <datadir>/genesis.txid so the tip still
// reports the genesis covenant before the daemon has applied its
// first ApplyAdvance.
func BuildCovenantTip(
	chainDB covenantTipChainReader,
	fetcher covenantUTXOFetcher,
	shardID string,
	dataDir string,
) (*CovenantTip, error) {
	// 1. Read the locally-cached tip txid + state. ReadCovenantTxID
	// returns the chainhash little-endian byte order; BSVString()
	// reverses to the BSV-canonical display form rotate-vk's
	// covenantTxId expects.
	txid := chainDB.ReadCovenantTxID()
	stateBytes := chainDB.ReadCovenantState()

	var (
		stateRootHex   string
		blockNumber    uint64
		txidBSVDisplay string
	)
	if stateBytes != nil {
		state, err := covenant.DecodeCovenantState(stateBytes)
		if err != nil {
			return nil, fmt.Errorf("decoding cached covenant state: %w", err)
		}
		stateRootHex = state.StateRoot.Hex()
		blockNumber = state.BlockNumber
	}

	if txid == (types.Hash{}) {
		// No advance applied yet — fall back to genesis.txid as the
		// best-known tip. State root + block number stay zero (which
		// is correct: the L2 hasn't moved and the operator probably
		// hasn't actually deployed yet).
		genesisTxID, err := readGenesisTxIDFile(dataDir)
		if err != nil {
			return nil, fmt.Errorf(
				"local chaindata has no covenant tip and no genesis.txid fallback: %w; "+
					"run `bsvm deploy-shard` first or boot the daemon at least once",
				err,
			)
		}
		txidBSVDisplay = genesisTxID
	} else {
		txidBSVDisplay = txid.BSVString()
	}

	// 2. Ask BSV for the live UTXO's locking script + sats. The
	// covenant output is always at vout 0 — this is invariant across
	// genesis + every advance (ApplyAdvance hard-codes
	// `cm.currentVout = 0` per pkg/covenant/manager.go).
	const covenantVout uint32 = 0
	lockingScriptHex, sats, err := fetcher(txidBSVDisplay, covenantVout)
	if err != nil {
		return nil, fmt.Errorf("fetch live covenant UTXO %s vout %d: %w",
			txidBSVDisplay, covenantVout, err)
	}
	if lockingScriptHex == "" {
		return nil, fmt.Errorf(
			"BSV node returned empty locking-script hex for %s vout %d — "+
				"the UTXO may have been spent (covenant has advanced)",
			txidBSVDisplay, covenantVout,
		)
	}
	scriptBytes, err := hex.DecodeString(lockingScriptHex)
	if err != nil {
		return nil, fmt.Errorf("decoding locking-script hex from BSV node: %w", err)
	}
	scriptHashSum := sha256.Sum256(scriptBytes)

	tip := &CovenantTip{
		ShardID:             shardID,
		CovenantTxID:        txidBSVDisplay,
		CovenantVout:        covenantVout,
		CovenantSatsLive:    sats,
		CurrentStateRootHex: stateRootHex,
		CurrentBlockNumber:  blockNumber,
		LockingScriptHex:    lockingScriptHex,
		LockingScriptSha256: hex.EncodeToString(scriptHashSum[:]),
	}
	if tip.CurrentStateRootHex == "" {
		// Surface a 0x-prefixed all-zeros hash rather than empty string
		// so consumers that simply paste this into a RotateVKConfig
		// JSON do not produce an invalid `currentStateRootHex` field.
		tip.CurrentStateRootHex = (types.Hash{}).Hex()
	}
	return tip, nil
}

// newProviderUTXOFetcher wraps a BSVProviderClient as a
// covenantUTXOFetcher. The closure issues a single
// getrawtransaction(txid, true) and pulls the requested vout's
// scriptPubKey.hex + sats out of the response.
//
// The BSV node reports satoshi values as a decimal BSV float; we
// round to the nearest satoshi via int64(round(value*1e8)) to avoid
// float drift (matches the convention pkg/bsvclient uses).
func newProviderUTXOFetcher(provider BSVProviderClient) covenantUTXOFetcher {
	return func(txidBSVDisplay string, vout uint32) (string, uint64, error) {
		raw, err := provider.GetRawTransactionVerbose(txidBSVDisplay)
		if err != nil {
			return "", 0, err
		}
		voutsRaw, ok := raw["vout"].([]interface{})
		if !ok {
			return "", 0, fmt.Errorf("BSV node response missing vout array")
		}
		if int(vout) >= len(voutsRaw) {
			return "", 0, fmt.Errorf("BSV node response only has %d vouts; need vout %d",
				len(voutsRaw), vout)
		}
		o, ok := voutsRaw[vout].(map[string]interface{})
		if !ok {
			return "", 0, fmt.Errorf("BSV node response vout %d is not an object", vout)
		}
		// Satoshi value: BSV node reports a decimal BSV float.
		valBTC, _ := o["value"].(float64)
		// Round half-away-from-zero to the nearest satoshi. Avoids
		// math.Round import — for non-negative values (covenant
		// values are always positive) this is equivalent.
		sats := uint64(valBTC*1e8 + 0.5)
		// Locking-script hex.
		spk, ok := o["scriptPubKey"].(map[string]interface{})
		if !ok {
			return "", 0, fmt.Errorf("BSV node response vout %d missing scriptPubKey", vout)
		}
		scriptHex, _ := spk["hex"].(string)
		return scriptHex, sats, nil
	}
}

// inferShardID reads <datadir>/genesis.txid (the deploy-shard convention)
// and falls back to <datadir>/shard.json::shardId. Returns "" when
// neither source is readable — the subcommand still works without a
// ShardID, the field is just omitted from the JSON.
func inferShardID(dataDir string) string {
	if id, err := readGenesisTxIDFile(dataDir); err == nil {
		return id
	}
	shardPath := filepath.Join(dataDir, "shard.json")
	raw, err := os.ReadFile(shardPath)
	if err != nil {
		return ""
	}
	var probe struct {
		ShardID string `json:"shardId"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return strings.TrimSpace(probe.ShardID)
}

// readGenesisTxIDFile reads <datadir>/genesis.txid and returns the
// trimmed contents (stripping a leading 0x if the operator stamped
// one in by hand — deploy-shard writes the bare 64-char form).
func readGenesisTxIDFile(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "genesis.txid")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	if s == "" {
		return "", fmt.Errorf("genesis.txid at %s is empty", path)
	}
	return s, nil
}
