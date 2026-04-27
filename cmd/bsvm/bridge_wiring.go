// Daemon-side bridge-monitor wiring. The helper here builds the
// pkg/bridge.BridgeMonitor the BEEF deposit consumer hands verified
// envelopes to via PersistDeposit (cmd/bsvm/beef_wiring.go::
// makeBridgeConsumer). Until this retrofit, WireBEEFEndpoints was
// always called with BridgeMonitor=nil and the consumer fell through
// to the pre-Item-3 fail-closed path: envelopes were stored but no L2
// credit was ever applied.
//
// The monitor instance constructed here is BEEF-driven: the bsvClient
// (legacy block-scanning) parameter is left nil because the BEEF flow
// supplies fully-verified deposits via the consumer callback rather
// than scanning blocks. PersistDeposit only needs the DepositStore (the
// daemon's shared LevelDB) and the script-hash + shard-id setters.
//
// The L1 bridge covenant locking script must be provisioned out of
// band — the operator pastes its hex into [bridge].bridge_script_hex
// once the L1 bridge transaction has been mined. When that field is
// empty BuildBridgeMonitor returns (nil, nil) so the BEEF consumer
// stays fail-closed; this keeps the daemon bootable on shards that
// haven't deployed an L1 bridge yet.
package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/overlay"
)

// BuildBridgeMonitor constructs a bridge.BridgeMonitor wired for the
// BEEF deposit-consumer flow.
//
//   - cfg.MinDepositSatoshis / MinWithdrawalSatoshis / BSVConfirmations
//     drive bridge.Config.
//   - bridgeScriptHex (operator-supplied) is the L1 covenant locking
//     script outputs are matched against; empty means the bridge isn't
//     deployed yet for this shard and the helper returns (nil, nil).
//   - chainID becomes the monitor's LocalShardID; the BEEF consumer
//     rejects deposits whose OP_RETURN encodes a different shard so a
//     cross-shard envelope cannot accidentally credit on the wrong
//     L2.
//   - store is the shared LevelDB (boot.DB); it must implement both
//     db.Database and db.Iteratee. Both LevelDB and MemoryDB do.
//   - overlay is the overlay node so the monitor can flush pending
//     deposits via SubmitDepositTx when the next L2 block builds. Pass
//     nil only for tests that drive PersistDeposit directly.
//
// Returns the configured monitor and the byte-decoded script hash so
// callers can pass both into WireBEEFEndpoints without re-parsing.
func BuildBridgeMonitor(
	cfg BridgeSection,
	bridgeScriptHex string,
	chainID int64,
	store db.Database,
	overlayNode *overlay.OverlayNode,
) (*bridge.BridgeMonitor, []byte, error) {
	hexStr := strings.TrimPrefix(strings.TrimSpace(bridgeScriptHex), "0x")
	if hexStr == "" {
		return nil, nil, nil
	}
	scriptHash, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, nil, fmt.Errorf("bridge.bridge_script_hex: %w", err)
	}
	if len(scriptHash) == 0 {
		return nil, nil, nil
	}

	depositStore, ok := store.(bridge.DepositStore)
	if !ok {
		return nil, nil, fmt.Errorf("bridge: shared DB does not implement db.Iteratee (got %T)", store)
	}

	bcfg := bridge.DefaultConfig()
	if cfg.MinDepositSatoshis > 0 {
		bcfg.MinDepositSatoshis = cfg.MinDepositSatoshis
	}
	if cfg.MinWithdrawalSatoshis > 0 {
		bcfg.MinWithdrawalSatoshis = cfg.MinWithdrawalSatoshis
	}
	if cfg.BSVConfirmations > 0 {
		bcfg.BSVConfirmations = cfg.BSVConfirmations
	}

	// bsvClient is intentionally nil — the BEEF flow supplies pre-
	// verified deposits through the consumer callback (PersistDeposit).
	// Block-scanning paths (which DO need a BSV client) are not used
	// here; if they're activated later, supply a real client at that
	// site so SubscribeNewBlocks etc. don't NPE.
	monitor := bridge.NewBridgeMonitor(bcfg, nil, overlayNode, depositStore)
	monitor.SetBridgeScriptHash(scriptHash)
	if chainID > 0 {
		monitor.SetLocalShardID(uint32(chainID))
	}

	// L2-side rollback hook (decision S-withdrawal-and-rollback): when
	// chaintracks reports a reorg the block-scan adapter calls
	// monitor.RetractDepositsAbove, which now invokes this callback.
	// The overlay node pauses the batcher and rolls back to the last
	// finalized tip so wBSV mints from retracted deposits cannot be
	// spent on speculative state. Operator must clear the halt via the
	// admin API once the new BSV chain is settled.
	if overlayNode != nil {
		monitor.SetReorgRollbackCallback(func(bsvCommonAncestorHeight uint64) {
			if err := overlayNode.HaltAndRollbackForReorg(bsvCommonAncestorHeight); err != nil {
				// Halt was applied (BatcherPause runs first); the
				// rollback may have failed. Log + carry on — operator
				// will see the paused batcher.
				slog.Error("HaltAndRollbackForReorg failed",
					"bsvCommonAncestor", bsvCommonAncestorHeight,
					"error", err,
				)
			}
		})
	}

	// Replay any deposits the previous run already persisted so the
	// in-memory dedup map is hot and re-delivered envelopes are
	// idempotent.
	if err := monitor.LoadProcessedDeposits(); err != nil {
		return nil, nil, fmt.Errorf("bridge: load processed deposits: %w", err)
	}

	// TODO(S-followup): wire the bridge.Withdrawer here once the
	// production WithdrawalScanner lands (see pkg/bridge/withdrawer.go).
	// The signer should be the same FeeWallet PrivateKey used for
	// covenant advances. The Withdrawer's ProcessFinalizedWithdrawalsLoop
	// should be started in a goroutine alongside the deposit consumer
	// so finalised withdrawals are claimed automatically against the
	// bridge covenant.

	return monitor, scriptHash, nil
}
