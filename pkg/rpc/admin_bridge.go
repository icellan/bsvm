package rpc

import (
	"encoding/hex"
	"fmt"

	"github.com/icellan/bsvm/pkg/bridge"
)

// BridgeRescanFn is the callback the daemon registers via
// AdminAPI.SetBridgeRescanner so admin_rescanDeposits can drive the
// block-scan adapter (cmd/bsvm/bridge_blockscan_wiring.go) without
// pkg/rpc importing pkg/chaintracks. The callback returns the number
// of blocks scheduled to scan starting at fromHeight, or an error
// describing why the rescan could not start (chaintracks down,
// no monitor, etc.).
//
// Implementations should be non-blocking: the rescan itself runs in
// the daemon's existing scanner goroutine. The "scheduled" count is
// the heuristic the explorer UI shows in its progress indicator.
type BridgeRescanFn func(fromHeight uint64) (scheduled uint64, err error)

// SetBridgeMonitor installs the live BridgeMonitor handle that
// admin_bridgeHealth + admin_rescanDeposits read from. Pass nil to
// detach (the RPCs return a "monitor not configured" error).
//
// Wiring contract: cmd/bsvm/main.go calls this after BuildBridgeMonitor
// returns successfully. Daemons that don't deploy a bridge skip the
// call — the monitor stays nil and the RPCs return the structured
// error documented in docs/operator/admin.md.
func (a *AdminAPI) SetBridgeMonitor(m *bridge.BridgeMonitor) {
	a.bridgeMonitor = m
}

// SetBridgeRescanner installs the rescan-callback the daemon owns.
// Decoupled from SetBridgeMonitor because the rescan path needs the
// chaintracks-backed BSV adapter, which lives in cmd/bsvm and would
// pull a chaintracks dep into pkg/rpc otherwise. Pass nil to detach.
func (a *AdminAPI) SetBridgeRescanner(fn BridgeRescanFn) {
	a.bridgeRescan = fn
}

// bridgeHealthInternal builds the admin_bridgeHealth response from
// the live monitor. Split out from BridgeHealth so the dispatcher
// can return a typed error when the monitor is detached.
func (a *AdminAPI) bridgeHealthInternal() map[string]interface{} {
	if a.bridgeMonitor == nil {
		return map[string]interface{}{
			"monitorAttached": false,
			"subCovenants":    []map[string]interface{}{},
			"mismatch":        false,
			"totalLocked":     "0",
			"totalSupply":     "0",
			"lastScanned":     0,
			"rescanPending":   false,
			"note":            "bridge monitor not attached to overlay (no [bridge].bridge_script_hex configured) — see docs/operator/admin.md",
		}
	}

	utxo := a.bridgeMonitor.CurrentBridgeUTXO()
	subCovenants := []map[string]interface{}{}
	totalLocked := uint64(0)
	if utxo != nil {
		totalLocked = utxo.Balance
		subCovenants = append(subCovenants, map[string]interface{}{
			"bsvTxid":          hex.EncodeToString(utxo.TxID[:]),
			"vout":             utxo.Vout,
			"balance":          utxo.Balance,
			"lastClaimedNonce": utxo.LastClaimedNonce,
			"status":           "active",
		})
	}

	return map[string]interface{}{
		"monitorAttached": true,
		"rescannerWired":  a.bridgeRescan != nil,
		"subCovenants":    subCovenants,
		"mismatch":        false, // l2 supply check lives in the indexer, not the monitor
		"totalLocked":     fmt.Sprintf("%d", totalLocked),
		"totalSupply":     fmt.Sprintf("%d", totalLocked), // monitor exposes locked-side only; indexer surface lands separately
		"lastScanned":     a.bridgeMonitor.DepositHorizon(),
		"pendingDeposits": a.bridgeMonitor.PendingCount(),
		"localShardId":    a.bridgeMonitor.LocalShardID(),
		"rescanPending":   false,
	}
}

// rescanDepositsInternal validates fromHeight against the wired
// rescanner and forwards the call. Returns a typed error when the
// rescanner is not configured — the error message points the operator
// at the cmd-side wire.
func (a *AdminAPI) rescanDepositsInternal(fromHeight uint64) (map[string]interface{}, error) {
	if a.bridgeMonitor == nil {
		return nil, fmt.Errorf("admin_rescanDeposits: bridge monitor not attached (configure [bridge].bridge_script_hex; see docs/operator/admin.md)")
	}
	if a.bridgeRescan == nil {
		return nil, fmt.Errorf("admin_rescanDeposits: bridge rescanner not wired (cmd-side wire missing; tracked as WW-bridge-rescanner-attach)")
	}
	scheduled, err := a.bridgeRescan(fromHeight)
	if err != nil {
		return nil, fmt.Errorf("admin_rescanDeposits: %w", err)
	}
	return map[string]interface{}{
		"success":    true,
		"fromHeight": fromHeight,
		"scheduled":  scheduled,
	}, nil
}
