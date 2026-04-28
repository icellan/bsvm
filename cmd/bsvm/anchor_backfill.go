// `bsvm anchor-backfill` walks the local ChainDB looking for AnchorRecord
// rows where Confirmed=false and tries to flip them to Confirmed=true (with
// the corresponding BSV block height) by re-querying the operator's BSV node
// via getrawtransaction verbose=1.
//
// This subcommand is the operator-facing recovery path for anchors that were
// written BEFORE the ConfirmationWatcher landed: the watcher backfills only
// while it is running, so any anchor that was confirmed outside its
// observation window stays Confirmed=false until somebody scans. Run this
// once after upgrading a long-lived node to bring its anchor history up to
// date.
//
// The subcommand is idempotent — re-running on an already-backfilled DB
// is a no-op (every anchor is skipped) and never broadcasts anything to BSV.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	cli "github.com/urfave/cli/v2"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// anchorBackfillCommand returns the urfave/cli command spec for
// `bsvm anchor-backfill`. Wired into main.go alongside the existing
// subcommands.
func anchorBackfillCommand() *cli.Command {
	return &cli.Command{
		Name:  "anchor-backfill",
		Usage: "Walk the local ChainDB and re-query BSV for unconfirmed AnchorRecord rows",
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
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "report what would change without writing to ChainDB",
			},
			&cli.IntFlag{
				Name:  "limit",
				Value: 0,
				Usage: "maximum number of unconfirmed anchors to process (0 = unlimited)",
			},
			&cli.StringFlag{
				Name:    "config",
				Usage:   "optional node TOML config (used for [bsv] settings if --bsv-rpc not given)",
				EnvVars: []string{"BSVM_CONFIG"},
			},
		},
		Action: cmdAnchorBackfill,
	}
}

// cmdAnchorBackfill is the urfave/cli action handler. It opens the
// per-node ChainDB, builds a BSV provider client from the same config
// surface the daemon uses, and hands both to runAnchorBackfill.
func cmdAnchorBackfill(ctx *cli.Context) error {
	dataDir := ctx.String("datadir")
	dryRun := ctx.Bool("dry-run")
	limit := ctx.Int("limit")
	if limit < 0 {
		return fmt.Errorf("--limit must be >= 0 (got %d)", limit)
	}

	// 1. Resolve [bsv] section. Operators can supply --config (full TOML)
	// or just --bsv-rpc / --bsv-network (the common case). When neither
	// the flag nor the env-var sources yield a URL, we abort early —
	// without RPC there's nothing to look up.
	var nodeCfg *NodeConfig
	if cfgPath := strings.TrimSpace(ctx.String("config")); cfgPath != "" {
		var err error
		nodeCfg, err = LoadNodeConfig(cfgPath)
		if err != nil {
			return fmt.Errorf("loading config %s: %w", cfgPath, err)
		}
	} else {
		nodeCfg = DefaultNodeConfig()
	}
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
		// is empty; we already gated on that above. Belt-and-braces.
		return fmt.Errorf("BSV provider construction returned nil despite configured endpoints")
	}

	// The RunarBroadcastClient already implements TransactionStatusSource
	// over a ConfirmationSource — but we don't need a full broadcast
	// client here (no contract, no signer). The provider directly
	// satisfies covenant.ConfirmationSource via GetRawTransactionVerbose,
	// so wrap it in a small adapter that surfaces the same TxStatus shape
	// the watcher consumes.
	statusSrc := newProviderStatusSource(provider)

	// 2. Open the local ChainDB read/write.
	dbPath := filepath.Join(dataDir, "chaindata")
	database, err := db.NewLevelDB(dbPath, 256, 256)
	if err != nil {
		return fmt.Errorf("opening database at %s: %w", dbPath, err)
	}
	defer database.Close()

	chainDB := block.NewChainDB(database)

	// 3. Run the backfill.
	report, err := runAnchorBackfill(ctx.Context, chainDB, statusSrc, anchorBackfillOpts{
		DryRun: dryRun,
		Limit:  limit,
	})
	if err != nil {
		return fmt.Errorf("anchor backfill: %w", err)
	}

	mode := "live"
	if dryRun {
		mode = "dry-run"
	}
	fmt.Printf("anchor-backfill (%s): processed=%d updated=%d skipped=%d errored=%d\n",
		mode, report.Processed, report.Updated, report.Skipped, report.Errored)
	return nil
}

// anchorBackfillOpts gathers the (small) knob set runAnchorBackfill takes.
type anchorBackfillOpts struct {
	// DryRun, when true, reports what would change without invoking
	// WriteAnchorRecord on ChainDB.
	DryRun bool
	// Limit caps the number of UNCONFIRMED anchors processed in one
	// run. Zero (the default) means unlimited. Already-confirmed
	// anchors don't count against the limit — they are skipped before
	// any RPC work.
	Limit int
}

// AnchorBackfillReport summarises the work runAnchorBackfill did.
type AnchorBackfillReport struct {
	// Processed counts every anchor visited (confirmed + unconfirmed).
	Processed int
	// Updated counts the anchors that were (or would be, in dry-run)
	// flipped to Confirmed=true with a non-zero block height.
	Updated int
	// Skipped counts already-confirmed anchors and unconfirmed anchors
	// that the BSV node still reports as unmined.
	Skipped int
	// Errored counts anchors whose status lookup or write failed.
	Errored int
}

// runAnchorBackfill is the testable core of `bsvm anchor-backfill`.
// It walks every persisted AnchorRecord, re-queries the supplied
// TransactionStatusSource for each Confirmed=false row, and writes
// back the updated record when the BSV node reports a confirmed,
// non-zero block height.
//
// The function is deterministic on its inputs and never touches BSV
// directly — all RPC happens through src — so tests can drive it with a
// fake TransactionStatusSource.
func runAnchorBackfill(
	ctx context.Context,
	chainDB *block.ChainDB,
	src covenant.TransactionStatusSource,
	opts anchorBackfillOpts,
) (AnchorBackfillReport, error) {
	if chainDB == nil {
		return AnchorBackfillReport{}, fmt.Errorf("nil ChainDB")
	}
	if src == nil {
		return AnchorBackfillReport{}, fmt.Errorf("nil status source")
	}

	var report AnchorBackfillReport
	// Snapshot every AnchorRecord first so the iterator's read-locks
	// are released before we issue any RPCs. The iterator is held the
	// whole time we walk it, and per-anchor RPCs can take seconds —
	// holding the iterator that long is a bad idea on a busy node.
	var pending []*block.AnchorRecord
	if err := chainDB.IterateAnchorRecords(ctx, func(r *block.AnchorRecord) bool {
		// Re-allocate to avoid the iterator clobbering the slice slot
		// on the next Next() call.
		copy := *r
		pending = append(pending, &copy)
		return true
	}); err != nil {
		return report, fmt.Errorf("iterating anchor records: %w", err)
	}

	processedUnconfirmed := 0
	for _, rec := range pending {
		report.Processed++

		if rec.Confirmed && rec.BSVBlockHeight > 0 {
			// Already complete — nothing to do. Skipping these is what
			// makes the subcommand idempotent on repeat runs.
			report.Skipped++
			continue
		}

		// Bound the run when --limit is set. Already-confirmed anchors
		// don't burn limit budget; the cap is on real RPC work.
		if opts.Limit > 0 && processedUnconfirmed >= opts.Limit {
			break
		}
		processedUnconfirmed++

		// Per-RPC timeout so a hanging BSV node can't lock up the
		// entire backfill. The 30s ceiling matches what the daemon's
		// ConfirmationWatcher uses for its own poll loop, give or take.
		rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		st, err := src.GetTransactionStatus(rpcCtx, rec.BSVTxID)
		cancel()
		if err != nil {
			report.Errored++
			slog.Warn("anchor-backfill: status lookup failed",
				"block", rec.L2BlockNum,
				"txid", rec.BSVTxID.BSVString(),
				"error", err,
			)
			continue
		}

		// Skip when the BSV node still says the tx is unmined or when
		// it's mined but the height couldn't be determined (the
		// covenant.RunarBroadcastClient + getblockheader fallback
		// guarantees a non-zero height for confirmed txs on modern AND
		// legacy BSV nodes; if both still report zero, we have nothing
		// useful to write — the next run will retry).
		if st.Confirmations == 0 || st.BlockHeight == 0 {
			report.Skipped++
			slog.Debug("anchor-backfill: unconfirmed or unknown height, skipping",
				"block", rec.L2BlockNum,
				"txid", rec.BSVTxID.BSVString(),
				"confirmations", st.Confirmations,
				"blockHeight", st.BlockHeight,
			)
			continue
		}

		if opts.DryRun {
			report.Updated++
			slog.Info("anchor-backfill: would update",
				"block", rec.L2BlockNum,
				"txid", rec.BSVTxID.BSVString(),
				"bsvHeight", st.BlockHeight,
				"confirmations", st.Confirmations,
			)
			continue
		}

		updated := &block.AnchorRecord{
			L2BlockNum:     rec.L2BlockNum,
			BSVTxID:        rec.BSVTxID,
			BSVBlockHeight: st.BlockHeight,
			Confirmed:      true,
		}
		if werr := chainDB.WriteAnchorRecord(updated); werr != nil {
			report.Errored++
			slog.Warn("anchor-backfill: write failed",
				"block", rec.L2BlockNum,
				"txid", rec.BSVTxID.BSVString(),
				"error", werr,
			)
			continue
		}
		report.Updated++
		slog.Info("anchor-backfill: updated",
			"block", rec.L2BlockNum,
			"txid", rec.BSVTxID.BSVString(),
			"bsvHeight", st.BlockHeight,
			"confirmations", st.Confirmations,
		)
	}

	return report, nil
}

// providerStatusSource adapts a BSVProviderClient into the
// covenant.TransactionStatusSource interface. It delegates to the
// covenant package's stand-alone TxStatusReader so the parsing logic
// (including the getblockheader fallback for legacy BSV nodes that
// don't populate getrawtransaction.blockheight) lives in exactly one
// place — the same logic the live RunarBroadcastClient uses on the hot
// daemon path.
type providerStatusSource struct {
	reader *covenant.TxStatusReader
}

// newProviderStatusSource wraps a BSVProviderClient. The provider's
// GetRawTransactionVerbose handles the primary lookup; its Call method
// powers the getblockheader fallback when the primary response omits
// blockheight.
func newProviderStatusSource(p BSVProviderClient) *providerStatusSource {
	return &providerStatusSource{reader: covenant.NewTxStatusReader(p, p)}
}

// GetTransactionStatus implements covenant.TransactionStatusSource.
func (a *providerStatusSource) GetTransactionStatus(ctx context.Context, txid types.Hash) (covenant.TxStatus, error) {
	return a.reader.GetTransactionStatus(ctx, txid)
}
