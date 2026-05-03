// governance_broadcast.go — wiring helpers for the at-threshold
// governance broadcaster (spec 15 §"Multisig governance actions").
//
// The pkg/governance.Broadcaster expects:
//
//   - A CovenantStateReader to read the live covenant tip + locking
//     script. covenant.CovenantManager satisfies the interface
//     directly via CurrentTxID / CurrentVout / Covenant /
//     GovernanceConfig — but the optional CovenantUTXOReader
//     (CurrentSats) requires an adapter because the manager keeps
//     the current sats value unexported. The adapter below adds it.
//
//   - A SpendTxBuilder closure. Production wires up
//     deploy/covenant.BuildUpgradeSpendTx, which already builds the
//     1-input/1-output BSV transaction shape freeze/unfreeze/upgrade
//     all share. The covenant continuation output reuses the live
//     covenant locking script (freeze/unfreeze flip only the
//     `frozen` byte; the script bytes themselves don't change), so
//     the builder is reused verbatim with the live LockingScript as
//     the "new" continuation script.
package main

import (
	"fmt"

	covenantdeploy "github.com/icellan/bsvm/deploy/covenant"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/governance"
	"github.com/icellan/bsvm/pkg/types"
)

// covenantStateAdapter wraps covenant.CovenantManager to expose the
// fields pkg/governance.Broadcaster needs.
//
// CovenantManager already implements pkg/governance.CovenantStateReader
// (CurrentTxID / CurrentVout / Covenant / GovernanceConfig) via its
// existing exported methods. This adapter additionally implements the
// optional CovenantUTXOReader (CurrentSats) by mirroring the manager's
// constructor-supplied sats — the manager itself keeps that field
// unexported, so we re-fetch it via the persister or fall back to the
// broadcaster's DefaultSats (covenant.DefaultCovenantSats) if neither
// path produces a value.
//
// The adapter is intentionally trivial — every method delegates to the
// underlying manager. It exists only because Go's structural-typing
// requires a concrete type to add the optional CurrentSats method
// without modifying CovenantManager's public surface.
type covenantStateAdapter struct {
	mgr *covenant.CovenantManager
}

// CurrentTxID delegates to the wrapped manager.
func (a *covenantStateAdapter) CurrentTxID() types.Hash { return a.mgr.CurrentTxID() }

// CurrentVout delegates to the wrapped manager.
func (a *covenantStateAdapter) CurrentVout() uint32 { return a.mgr.CurrentVout() }

// Covenant returns the compiled covenant artefact (or nil when the
// node started without the covenant.anf.json file). Delegates to the
// wrapped manager.
func (a *covenantStateAdapter) Covenant() *covenant.CompiledCovenant { return a.mgr.Covenant() }

// GovernanceConfig delegates to the wrapped manager.
func (a *covenantStateAdapter) GovernanceConfig() covenant.GovernanceConfig {
	return a.mgr.GovernanceConfig()
}

// CurrentSats returns 0 today — the wrapped manager does not expose
// its currentSats field. The broadcaster falls back to its
// configured DefaultSats (covenant.DefaultCovenantSats) when this
// returns 0, which is the right value for every shard whose covenant
// UTXO carries the default sats. Operators running with a non-default
// sats budget should plumb a custom value through the broadcaster
// config; that work is out of scope for the initial wiring and is
// tracked alongside WW-governance-payload-extension.
func (a *covenantStateAdapter) CurrentSats() uint64 { return 0 }

// Compile-time interface assertions.
var (
	_ governance.CovenantStateReader = (*covenantStateAdapter)(nil)
	_ governance.CovenantUTXOReader  = (*covenantStateAdapter)(nil)
)

// governanceSpendBuilder is the production SpendTxBuilder for the
// governance broadcaster. It delegates to
// deploy/covenant.BuildUpgradeSpendTx, which builds the
// 1-input/1-output BSV transaction shape freeze/unfreeze/upgrade all
// share (single covenant input under unlockBytes, single covenant
// output under continuationLockingScript).
//
// For freeze + unfreeze, continuationLockingScript is the live
// covenant's existing LockingScript — the `frozen` flag is encoded in
// the covenant's STATE bytes, not in the script bytes themselves, so
// the script is byte-identical pre/post-toggle.
//
// For upgrade, continuationLockingScript would be the recompiled
// covenant under the new VK — but that path is currently deferred
// (see pkg/governance/broadcaster.go's dispatchUpgrade godoc).
func governanceSpendBuilder(
	covenantTxID string,
	covenantVout uint32,
	covenantSatsLive uint64,
	continuationLockingScript []byte,
	unlockBytes []byte,
) (txHex string, txID string, err error) {
	tx, err := covenantdeploy.BuildUpgradeSpendTx(
		covenantTxID,
		covenantVout,
		covenantSatsLive,
		continuationLockingScript,
		unlockBytes,
	)
	if err != nil {
		return "", "", fmt.Errorf("BuildUpgradeSpendTx: %w", err)
	}
	return tx.Hex(), tx.TxID().String(), nil
}

