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
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/covenant"
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

// ScriptHashVersion captures one entry in the bridge covenant
// locking-script history. Versions are ordered by activation time
// (oldest first); Index is informational and matches the entry's
// position in the original history slice. Hash is the complete
// locking script bytes the walker compares output scripts against
// (byte-for-byte equality, mirroring matchesBridgeCovenant).
type ScriptHashVersion struct {
	Index int
	Hash  []byte
}

// buildBridgeScriptHashHistory parses the operator-supplied hex
// strings (oldest first) into ScriptHashVersion entries and appends
// the current bridge script hash as the last entry. Returns an error
// when any history entry is malformed hex or zero-length.
//
// Empty / whitespace-only entries are skipped silently to make
// config rolling-back ("comment out an upgrade by blanking the
// entry") safe.
func buildBridgeScriptHashHistory(historyHex []string, currentHash []byte) ([]ScriptHashVersion, error) {
	out := make([]ScriptHashVersion, 0, len(historyHex)+1)
	for i, h := range historyHex {
		h = strings.TrimPrefix(strings.TrimSpace(h), "0x")
		if h == "" {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("bridge_script_hex_history[%d]: %w", i, err)
		}
		if len(raw) == 0 {
			continue
		}
		out = append(out, ScriptHashVersion{Index: len(out), Hash: raw})
	}
	if len(currentHash) > 0 {
		out = append(out, ScriptHashVersion{Index: len(out), Hash: append([]byte(nil), currentHash...)})
	}
	return out, nil
}

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
	return recoverBridgeUTXOFromChainHistory(
		ctx, chaintracksClient, blockClient, monitor, hint,
		[]ScriptHashVersion{{Index: 0, Hash: bridgeScriptHash}},
		walkBound, logger,
	)
}

// recoverBridgeUTXOFromChainHistory is the multi-version variant of
// recoverBridgeUTXOFromChain. The walker matches output scripts
// against ANY hash in scriptHashHistory (ordered oldest-first);
// matches against newer versions are preferred when both appear in
// the searchable window. An upgrade boundary is logged at WARN when a
// match flips from one version to another.
//
// scriptHashHistory must be non-empty; the last entry is the
// "current" script. Empty entries are tolerated and skipped to make
// callers' config-passing simpler.
func recoverBridgeUTXOFromChainHistory(
	ctx context.Context,
	chaintracksClient bridgeRecoveryHeaderOracle,
	blockClient bridgeRecoveryBlockClient,
	monitor *bridge.BridgeMonitor,
	hint *bridge.BridgeUTXO,
	scriptHashHistory []ScriptHashVersion,
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

	// Filter out empty entries — operators sometimes leave gaps in
	// the history slice when an upgrade was rolled back / never
	// activated.
	cleanHistory := make([]ScriptHashVersion, 0, len(scriptHashHistory))
	for _, v := range scriptHashHistory {
		if len(v.Hash) > 0 {
			cleanHistory = append(cleanHistory, v)
		}
	}
	if len(cleanHistory) == 0 {
		// No script to match against — fall back to hint.
		return seedFromHint(monitor, hint, logger, "no bridge script history configured")
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

	found, err := walkForBridgeUTXOHistory(ctx, blockClient, cleanHistory, tip.Height, walkBound, logger)
	if err != nil {
		// Walk-level error (ctx cancel, fetcher fail). Surface verbatim
		// — the daemon will treat it as a hard boot error.
		return err
	}

	switch {
	case found != nil && hint == nil:
		applyHintNonceFallback(found, nil, logger)
		logger.Info("bridge recovery: discovered live UTXO on chain (no operator hint)",
			"txid", found.TxID.BSVString(),
			"vout", found.Vout,
			"balance_sat", found.Balance,
			"last_claimed_nonce", found.LastClaimedNonce,
		)
		monitor.SetBridgeUTXO(found)
		return nil

	case found != nil && bridgeUTXOOutpointMatches(found, hint):
		// Outpoint agrees. Chain wins on nonce too: the on-chain
		// BridgeState is the source of truth. If the hint disagrees
		// with the chain-decoded nonce we WARN; if the chain script
		// failed to parse we fall back to the hint's nonce.
		applyHintNonceFallback(found, hint, logger)
		logChainNonceDecision(found, hint, logger, "agrees with operator hint")
		monitor.SetBridgeUTXO(found)
		return nil

	case found != nil:
		// Chain disagrees with hint on the outpoint — chain wins.
		// Make the discrepancy operator-visible so a config typo
		// gets noticed.
		logger.Warn("bridge recovery: chain-discovered UTXO disagrees with operator hint, preferring chain",
			"chain_txid", found.TxID.BSVString(),
			"chain_vout", found.Vout,
			"chain_balance_sat", found.Balance,
			"hint_txid", hint.TxID.BSVString(),
			"hint_vout", hint.Vout,
			"hint_balance_sat", hint.Balance,
		)
		applyHintNonceFallback(found, hint, logger)
		logChainNonceDecision(found, hint, logger, "outpoint disagreed; chain wins")
		monitor.SetBridgeUTXO(found)
		return nil

	default:
		// Nothing found within the walk bound. Fall back to the hint.
		return seedFromHint(monitor, hint, logger,
			fmt.Sprintf("no bridge UTXO found within %d blocks of tip %d", walkBound, tip.Height))
	}
}

// applyHintNonceFallback fills in found.LastClaimedNonce from the
// hint when the chain script parse left it at the unset sentinel
// (i.e. ParseBridgeStateFromScriptBytes failed or returned nonce 0).
// When the chain decoded a real nonce, it stays — chain wins on
// nonce per the round-7 follow-up policy.
//
// Two intentional asymmetries:
//
//   - chain WithdrawalNonce==0 maps to LastClaimedNonceUnset, which is
//     also the unset-sentinel value. We can't disambiguate "nonce
//     genuinely 0" from "parse failed" purely from the value; in both
//     cases the hint's LastClaimedNonce (if any) is a better signal
//     because an operator only sets the hint after a real claim.
//
//   - chain has a positive nonce: keep it, regardless of what the hint
//     says. The hint may be stale; the chain is canonical.
func applyHintNonceFallback(found, hint *bridge.BridgeUTXO, _ *slog.Logger) {
	if found == nil {
		return
	}
	if found.LastClaimedNonce == bridge.LastClaimedNonceUnset && hint != nil {
		found.LastClaimedNonce = hint.LastClaimedNonce
	}
}

// logChainNonceDecision emits an INFO log capturing the
// chain-vs-hint nonce reconciliation outcome. WARN is used only when
// the hint contradicted a successfully-parsed chain nonce.
func logChainNonceDecision(found, hint *bridge.BridgeUTXO, logger *slog.Logger, outpointSummary string) {
	if found == nil {
		return
	}
	if hint != nil && hint.LastClaimedNonce != bridge.LastClaimedNonceUnset &&
		found.LastClaimedNonce != bridge.LastClaimedNonceUnset &&
		hint.LastClaimedNonce != found.LastClaimedNonce {
		logger.Warn("bridge recovery: chain-decoded last_claimed_nonce disagrees with operator hint, preferring chain",
			"chain_last_claimed_nonce", found.LastClaimedNonce,
			"hint_last_claimed_nonce", hint.LastClaimedNonce,
			"outpoint_summary", outpointSummary,
		)
		return
	}
	logger.Info("bridge recovery: chain-discovered UTXO accepted",
		"txid", found.TxID.BSVString(),
		"vout", found.Vout,
		"balance_sat", found.Balance,
		"last_claimed_nonce", found.LastClaimedNonce,
		"outpoint_summary", outpointSummary,
	)
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
//
// Single-hash variant kept for backwards compatibility; the
// production path uses walkForBridgeUTXOHistory which accepts a
// version slice.
func walkForBridgeUTXO(
	ctx context.Context,
	blockClient bridgeRecoveryBlockClient,
	bridgeScriptHash []byte,
	tipHeight uint64,
	walkBound uint64,
	logger *slog.Logger,
) (*bridge.BridgeUTXO, error) {
	return walkForBridgeUTXOHistory(ctx, blockClient,
		[]ScriptHashVersion{{Index: 0, Hash: bridgeScriptHash}},
		tipHeight, walkBound, logger)
}

// walkForBridgeUTXOHistory is the multi-version walker: it matches
// each block's outputs against EVERY entry in scriptHashHistory and
// returns the first (i.e. most recent) match. The match's version
// index is logged so a covenant-upgrade boundary stands out:
// transitioning from one version's match to a newer version's match
// implies the operator upgraded the covenant locking script between
// the two block heights.
//
// "Upgrade boundary" detection happens regardless of where in the
// walk it occurs. The walker tracks the LAST matched version index
// while it scans newer→older blocks; if a deeper block matches a
// DIFFERENT (older) version, we WARN with both heights so operators
// can correlate the upgrade event. Within a single recovery the most
// recent match always wins (the function returns at the first match
// seen during the newer-to-older walk, so the very first match — if
// any — is the answer).
func walkForBridgeUTXOHistory(
	ctx context.Context,
	blockClient bridgeRecoveryBlockClient,
	scriptHashHistory []ScriptHashVersion,
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

		// Scan within the block against EVERY history entry. Match
		// order: newest version first, so a chain where the upgrade
		// happened K blocks ago and the new covenant has already had
		// activity prefers the new-version match. When a match
		// against an OLDER version happens AFTER (i.e. at a higher
		// block height than) we'd expect the new version to be
		// active, log the upgrade boundary loudly. Within a single
		// block we consider every output paying ANY history hash and
		// take the newest version's match.
		matchedVersion, utxo := findBridgeOutputInBlockMulti(txs, scriptHashHistory)
		if utxo != nil {
			logger.Info("bridge recovery: matched bridge-covenant output",
				"height", height,
				"txid", utxo.TxID.BSVString(),
				"vout", utxo.Vout,
				"balance_sat", utxo.Balance,
				"version_index", matchedVersion.Index,
				"blocks_scanned", scanned+1,
			)
			// If the matched version isn't the LATEST (last in the
			// history slice) we are seeing the chain BEFORE the
			// activation height of newer upgrades — log the boundary
			// so operators can spot stale-covenant chains.
			if matchedVersion.Index < scriptHashHistory[len(scriptHashHistory)-1].Index {
				logger.Warn("bridge covenant upgrade boundary: chain walk found older-version UTXO",
					"matched_version_index", matchedVersion.Index,
					"current_version_index", scriptHashHistory[len(scriptHashHistory)-1].Index,
					"matched_height", height,
					"hint", "operator may have stale [bridge].bridge_script_hex_history; chain has not yet seen the new covenant active",
				)
			}
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
		"versions_checked", len(scriptHashHistory),
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
//
// The found UTXO's LastClaimedNonce is decoded from the on-chain
// BridgeState pushdata embedded in the locking script. The encoded
// state's WithdrawalNonce is the next-claim nonce; LastClaimedNonce =
// WithdrawalNonce - 1 (or LastClaimedNonceUnset for nonce 0). When
// the state cannot be parsed (malformed script, no matching pushdata)
// LastClaimedNonce stays at the unset sentinel and the caller falls
// back to the operator hint with a WARN.
func findBridgeOutputInBlock(txs []*bridge.BSVTransaction, bridgeScriptHash []byte, height uint64) *bridge.BridgeUTXO {
	_, utxo := findBridgeOutputInBlockMulti(txs,
		[]ScriptHashVersion{{Index: 0, Hash: bridgeScriptHash}})
	_ = height // retained in signature for backwards compatibility with callers
	return utxo
}

// findBridgeOutputInBlockMulti returns the FIRST bridge-covenant
// output it finds in any of the block's transactions, matched
// against ANY entry in scriptHashHistory. When multiple history
// entries match (rare; only possible if two distinct covenant
// versions emit byte-identical locking scripts — they don't, by
// construction), the NEWEST version (highest Index) wins.
//
// Returns the matching version + the UTXO, or (zero-value, nil) when
// no match is found.
func findBridgeOutputInBlockMulti(txs []*bridge.BSVTransaction, scriptHashHistory []ScriptHashVersion) (ScriptHashVersion, *bridge.BridgeUTXO) {
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		for vout, out := range tx.Outputs {
			// Iterate history newest-first so a same-block tie goes
			// to the newer version. Walking newest→oldest also lets
			// us short-circuit the first match.
			for i := len(scriptHashHistory) - 1; i >= 0; i-- {
				v := scriptHashHistory[i]
				if !bytes.Equal(out.Script, v.Hash) {
					continue
				}
				utxo := &bridge.BridgeUTXO{
					TxID:             tx.TxID,
					Vout:             uint32(vout),
					Balance:          out.Value,
					LastClaimedNonce: bridge.LastClaimedNonceUnset,
					Script:           append([]byte(nil), v.Hash...),
				}
				// Decode on-chain BridgeState from the embedded
				// pushdata to recover the canonical LastClaimedNonce.
				// Parse failures surface back to the caller via the
				// unset sentinel; the caller logs + falls back to the
				// operator hint.
				if state, err := covenant.ParseBridgeStateFromScriptBytes(out.Script); err == nil {
					utxo.LastClaimedNonce = chainNonceToLastClaimed(state.WithdrawalNonce)
				}
				return v, utxo
			}
		}
	}
	return ScriptHashVersion{}, nil
}

// chainNonceToLastClaimed converts the on-chain BridgeState
// WithdrawalNonce (the NEXT nonce to claim) into the BridgeUTXO
// LastClaimedNonce convention (nonce of the LAST claim, or
// LastClaimedNonceUnset when no claim has happened). See
// pkg/bridge.LastClaimedNonceUnset for the rationale.
func chainNonceToLastClaimed(withdrawalNonce uint64) uint64 {
	if withdrawalNonce == 0 {
		return bridge.LastClaimedNonceUnset
	}
	return withdrawalNonce - 1
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
