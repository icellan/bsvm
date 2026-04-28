// Cold-boot recovery of the bridge UTXO state.
//
// The pre-recovery wiring (cmd/bsvm/bridge_wiring.go::seedBridgeUTXO)
// trusted the operator's [bridge].bridge_utxo_* keys as the only
// source of truth for the live bridge UTXO. Any operator typo or stale
// snapshot would persist into the running daemon: the Withdrawer would
// build claims against a non-existent UTXO and the BridgeMonitor would
// credit deposits to the wrong outpoint.
//
// recoverBridgeUTXOFromChain walks the BSV chain backwards from the
// chaintracks tip and locates the most recent transaction that has an
// output paying to the bridge covenant script. That output is the
// current bridge UTXO. The chain-discovered value is preferred over the
// operator hint; mismatches are logged at WARN so the operator can
// reconcile their config. If nothing is found within the configured
// walk bound the recovery falls back to the hint (or returns nil if no
// hint is configured) so a fresh shard / paused bridge stays bootable.
//
// The recovery only consumes the public BridgeMonitor API
// (SetBridgeUTXO + CurrentBridgeUTXO); it does not touch the Run loop
// or any internal monitor state.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
)

// defaultBridgeRecoveryWalkBound is the maximum number of BSV blocks
// the cold-boot recovery walks backwards from the chaintracks tip
// before giving up. 144 ~= 24 hours at the 10-minute BSV target. A
// healthy bridge sees a covenant advance well within that window
// (deposits, withdrawals, or operator-driven rollups all spend the
// bridge UTXO and produce a fresh outpoint). Anything older than 144
// blocks without a touch is either a fresh / paused shard or a
// genuinely cold deployment — in both cases falling back to the
// operator hint is safe and operator-visible.
//
// Exposed as a package var (not const) so tests can dial it down to a
// few blocks for deterministic harness construction.
var defaultBridgeRecoveryWalkBound uint64 = 144

// bridgeRecoveryBlockClient is the subset of the bridge BSV-client
// adapter the recovery actually uses. Defined as an interface so unit
// tests can drive the recovery against an in-memory fake without
// standing up the full chaintracks + WoC + RPC stack.
type bridgeRecoveryBlockClient interface {
	GetBlockTransactions(height uint64) ([]*bridge.BSVTransaction, error)
}

// bridgeRecoveryHeaderOracle is the subset of chaintracks the recovery
// uses to resolve the current tip height. Tip() is the only method
// touched; HeaderByHeight is implicitly consulted via the block client.
type bridgeRecoveryHeaderOracle interface {
	Tip(ctx context.Context) (*chaintracks.BlockHeader, error)
}

// recoverBridgeUTXOFromChain seeds the BridgeMonitor's live UTXO
// snapshot from the most recent on-chain bridge-covenant output it can
// find within walkBound blocks of the chaintracks tip.
//
// Behaviour matrix (chain ⊕ hint):
//
//   - chain match, no hint           → seed from chain (INFO)
//   - chain match agrees with hint   → seed from chain (INFO; hint redundant)
//   - chain match disagrees with hint → seed from chain (WARN; chain wins)
//   - no chain match, hint provided  → seed from hint (INFO; "fresh shard or paused")
//   - no chain match, no hint        → seed nothing; CurrentBridgeUTXO stays nil
//
// Arguments:
//   - chaintracksClient: optional. nil means "no SPV anchor"; in that
//     case we cannot establish a chain tip and fall through to the
//     hint. The daemon's main.go path passes a real client, so this
//     null-safety mostly matters in tests.
//   - blockClient: optional. nil means "block scanning unavailable";
//     same fall-through behaviour as a missing chaintracks client.
//   - monitor: required. The recovery is a no-op when monitor is nil.
//   - hint: optional. The operator's bridge_utxo_* config snapshot,
//     used as the fallback when the chain walk yields nothing.
//   - bridgeScriptHash: required. The bridge covenant locking script
//     (bytes.Equal-matched against output scripts during the walk).
//   - walkBound: maximum blocks to scan. 0 means "use the package
//     default" (defaultBridgeRecoveryWalkBound).
//   - logger: required.
//
// Honours ctx cancellation between blocks; a cancelled walk returns
// ctx.Err() and leaves the monitor untouched (callers can still seed
// from the hint manually if they prefer).
func recoverBridgeUTXOFromChain(
	ctx context.Context,
	chaintracksClient bridgeRecoveryHeaderOracle,
	blockClient bridgeRecoveryBlockClient,
	monitor *bridge.BridgeMonitor,
	hint *bridge.BridgeUTXO,
	bridgeScriptHash []byte,
	walkBound uint64,
	logger *slog.Logger,
) error {
	if monitor == nil {
		// Recovery is purely a wiring concern — when no monitor is
		// configured for this shard there is nothing to seed.
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	if walkBound == 0 {
		walkBound = defaultBridgeRecoveryWalkBound
	}
	if len(bridgeScriptHash) == 0 {
		// No script to match against — fall back to hint.
		return seedFromHint(monitor, hint, logger, "no bridge script configured")
	}

	if chaintracksClient == nil || blockClient == nil {
		// No way to reach the chain. The operator's hint is the only
		// source of truth available.
		return seedFromHint(monitor, hint, logger,
			"chaintracks or block client unavailable; using operator hint")
	}

	tip, err := chaintracksClient.Tip(ctx)
	if err != nil {
		// Chaintracks not yet hot — surface the error but fall back to
		// the hint so the daemon can still boot. Without a hint the
		// snapshot stays nil and the Withdrawer logs idle.
		logger.Warn("bridge recovery: chaintracks tip unavailable, falling back to operator hint",
			"err", err,
		)
		return seedFromHint(monitor, hint, logger, "chaintracks tip unavailable")
	}

	found, err := walkForBridgeUTXO(ctx, blockClient, bridgeScriptHash, tip.Height, walkBound, logger)
	if err != nil {
		// Walk-level error (ctx cancel, fetcher fail). Surface verbatim
		// — the daemon will treat it as a hard boot error.
		return err
	}

	switch {
	case found != nil && hint == nil:
		logger.Info("bridge recovery: discovered live UTXO on chain (no operator hint)",
			"txid", found.TxID.BSVString(),
			"vout", found.Vout,
			"balance_sat", found.Balance,
		)
		monitor.SetBridgeUTXO(found)
		return nil

	case found != nil && bridgeUTXOOutpointMatches(found, hint):
		logger.Info("bridge recovery: chain-discovered UTXO agrees with operator hint",
			"txid", found.TxID.BSVString(),
			"vout", found.Vout,
			"balance_sat", found.Balance,
		)
		// Preserve the hint's LastClaimedNonce — the chain walk has no
		// view of it, but the operator does.
		if hint != nil {
			found.LastClaimedNonce = hint.LastClaimedNonce
		}
		monitor.SetBridgeUTXO(found)
		return nil

	case found != nil:
		// Chain disagrees with hint — chain wins, but make the
		// discrepancy operator-visible so a config typo gets noticed.
		logger.Warn("bridge recovery: chain-discovered UTXO disagrees with operator hint, preferring chain",
			"chain_txid", found.TxID.BSVString(),
			"chain_vout", found.Vout,
			"chain_balance_sat", found.Balance,
			"hint_txid", hint.TxID.BSVString(),
			"hint_vout", hint.Vout,
			"hint_balance_sat", hint.Balance,
		)
		// The hint's LastClaimedNonce may still be authoritative even
		// when the outpoint differs — preserve it; otherwise the
		// Withdrawer would re-attempt already-claimed nonces.
		found.LastClaimedNonce = hint.LastClaimedNonce
		monitor.SetBridgeUTXO(found)
		return nil

	default:
		// Nothing found within the walk bound. Fall back to the hint.
		return seedFromHint(monitor, hint, logger,
			fmt.Sprintf("no bridge UTXO found within %d blocks of tip %d", walkBound, tip.Height))
	}
}

// seedFromHint applies the operator hint to the monitor (or leaves the
// snapshot nil when no hint was supplied) and logs the outcome at INFO.
// Returning a nil error is intentional: a missing hint is operator-
// visible via the absence of CurrentBridgeUTXO and the Withdrawer's
// idle-loop log; failing the daemon boot would be more disruptive than
// helpful for fresh shards.
func seedFromHint(monitor *bridge.BridgeMonitor, hint *bridge.BridgeUTXO, logger *slog.Logger, reason string) error {
	if hint == nil {
		logger.Info("bridge recovery: no chain-discovered UTXO and no operator hint; snapshot stays nil",
			"reason", reason,
		)
		return nil
	}
	logger.Info("bridge recovery: seeding monitor from operator hint",
		"reason", reason,
		"txid", hint.TxID.BSVString(),
		"vout", hint.Vout,
		"balance_sat", hint.Balance,
	)
	monitor.SetBridgeUTXO(hint)
	return nil
}

// walkForBridgeUTXO scans up to walkBound blocks backwards from
// tipHeight, returning the most recent bridge-covenant output it finds.
// Returns (nil, nil) when no output matches within the window.
//
// The walk goes one block per iteration so a long-running recovery can
// honour ctx cancellation. It does NOT cache scanned blocks; the
// chaintracks anchor + the block client absorb any RPC-level caching.
func walkForBridgeUTXO(
	ctx context.Context,
	blockClient bridgeRecoveryBlockClient,
	bridgeScriptHash []byte,
	tipHeight uint64,
	walkBound uint64,
	logger *slog.Logger,
) (*bridge.BridgeUTXO, error) {
	scanned := uint64(0)
	height := tipHeight
	for scanned < walkBound {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		txs, err := blockClient.GetBlockTransactions(height)
		if err != nil {
			if errors.Is(err, ErrBlockFetchUnsupported) {
				logger.Info("bridge recovery: block fetch unsupported, aborting walk (BEEF path remains live)",
					"height", height,
				)
				return nil, nil
			}
			// Don't fail the boot on a single missing block — log + try
			// the next height down. The walk is best-effort.
			logger.Warn("bridge recovery: GetBlockTransactions failed, skipping",
				"height", height,
				"err", err,
			)
			scanned++
			if height == 0 {
				break
			}
			height--
			continue
		}

		// Scan within the block. ProcessBlock-style ordering doesn't
		// matter here — there is at most one bridge-output-bearing tx
		// per block on a healthy chain (the bridge covenant chain
		// branches at most once per advance), so we take the first
		// match we see and stop.
		if utxo := findBridgeOutputInBlock(txs, bridgeScriptHash, height); utxo != nil {
			logger.Info("bridge recovery: matched bridge-covenant output",
				"height", height,
				"txid", utxo.TxID.BSVString(),
				"vout", utxo.Vout,
				"balance_sat", utxo.Balance,
				"blocks_scanned", scanned+1,
			)
			return utxo, nil
		}

		scanned++
		if height == 0 {
			// Reached genesis without a match.
			break
		}
		height--
	}
	logger.Info("bridge recovery: no bridge-covenant output found within walk bound",
		"tip", tipHeight,
		"walk_bound", walkBound,
		"blocks_scanned", scanned,
	)
	return nil, nil
}

// findBridgeOutputInBlock returns the FIRST bridge-covenant output it
// finds in any of the block's transactions, projected into a
// BridgeUTXO snapshot. Returns nil when no tx in the block has a
// matching output.
//
// The bridge UTXO is identified by an output whose locking script is
// byte-identical to bridgeScriptHash (the operator-supplied bridge
// covenant locking script). The chain may also carry a spec-12
// "BSVM\x02" OP_RETURN in unrelated rollup-advance txs; those don't
// pay the bridge script so they're skipped here.
func findBridgeOutputInBlock(txs []*bridge.BSVTransaction, bridgeScriptHash []byte, height uint64) *bridge.BridgeUTXO {
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		for vout, out := range tx.Outputs {
			if !bytes.Equal(out.Script, bridgeScriptHash) {
				continue
			}
			_ = height // logged by the caller
			return &bridge.BridgeUTXO{
				TxID:             tx.TxID,
				Vout:             uint32(vout),
				Balance:          out.Value,
				LastClaimedNonce: bridge.LastClaimedNonceUnset,
				Script:           append([]byte(nil), bridgeScriptHash...),
			}
		}
	}
	return nil
}

// bridgeUTXOOutpointMatches reports whether two BridgeUTXO snapshots
// share the same outpoint (TxID + Vout) AND balance. LastClaimedNonce
// is intentionally excluded — the chain walk has no view of nonce
// state, and the hint's nonce is the authoritative value either way.
func bridgeUTXOOutpointMatches(a, b *bridge.BridgeUTXO) bool {
	if a == nil || b == nil {
		return false
	}
	return a.TxID == b.TxID && a.Vout == b.Vout && a.Balance == b.Balance
}

