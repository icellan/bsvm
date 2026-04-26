// Daemon-side wiring that activates the bridge.BridgeMonitor's block-
// scanning loop using the bridgeBSVClient adapter (see
// cmd/bsvm/bridge_bsv_client.go). The BEEF deposit path remains the
// primary deposit channel; this scanner backs it up for deposits that
// land directly on-chain (BSV tx with bridge-script output, no BEEF
// envelope).
//
// startBridgeBlockScanner returns a Close function the caller defers
// so the scanner goroutine + the chaintracks WS subscription unwind
// cleanly on daemon shutdown. Returns (nil, nil) when the scanner is
// not applicable for the current daemon configuration (no monitor, no
// chaintracks anchor); the daemon stays bootable in that case and the
// BEEF path keeps running in isolation.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/whatsonchain"
)

// blockScannerCloseFunc is returned from startBridgeBlockScanner so
// callers can defer-close the scanner without importing context here.
type blockScannerCloseFunc func() error

// bridgeBSVProviderForScan narrows the cmd-side BSVProviderClient
// down to the bridgeRPCClient surface the adapter needs (Call only).
// Returns nil when the input is nil so the scanner can proceed in
// chaintracks-only mode without faking an RPC client.
func bridgeBSVProviderForScan(p BSVProviderClient) bridgeRPCClient {
	if p == nil {
		return nil
	}
	return p
}

// startBridgeBlockScanner wires the bridge.BridgeMonitor's Run loop
// against a bridgeBSVClient composed from chaintracks + WoC + the
// optional BSV-node RPC provider. The scanner runs in its own
// goroutine and exits when ctx is cancelled OR the chaintracks stream
// closes.
//
// Behaviour:
//
//   - Returns (nil, nil) when monitor is nil (no [bridge].
//     bridge_script_hex configured) — the daemon does not need a
//     scanner there.
//   - Returns (nil, nil) when chaintracks is nil (no SPV anchor) — we
//     refuse to scan without one because deposit confirmations are
//     unverifiable.
//   - Returns the close function on success. The function blocks
//     until the scanner goroutine has returned.
//
// Errors come from the BSV client construction; they're operator-
// fixable so we surface them rather than warn-and-continue.
func startBridgeBlockScanner(
	ctx context.Context,
	monitor *bridge.BridgeMonitor,
	chaintracksClient chaintracks.ChaintracksClient,
	wocClient whatsonchain.WhatsOnChainClient,
	rpcClient bridgeRPCClient,
	logger *slog.Logger,
) (blockScannerCloseFunc, error) {
	if monitor == nil {
		// No bridge configured for this shard — nothing to scan.
		return nil, nil
	}
	if chaintracksClient == nil {
		logger.Warn("bridge block scanner: chaintracks not configured, scanner disabled (BEEF path remains active)")
		return nil, nil
	}

	adapter, err := newBridgeBSVClient(chaintracksClient, wocClient, rpcClient, monitor, logger)
	if err != nil {
		return nil, fmt.Errorf("bridge block scanner: %w", err)
	}

	// The monitor.Run loop subscribes to SubscribeNewBlocks itself.
	// Pre-construction: swap the monitor's bsvClient field. We can't
	// do that cleanly because the monitor struct doesn't expose a
	// setter — and adding one is a bigger surface change than the
	// current task warrants. Instead we drive ProcessBlock directly
	// from this goroutine (mirroring monitor.Run's logic) so the
	// monitor stays unchanged and the BEEF path keeps owning the
	// shared mu via PersistDeposit.
	scanCtx, cancel := context.WithCancel(ctx)
	blockCh, err := adapter.SubscribeNewBlocks(scanCtx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("bridge block scanner: subscribe: %w", err)
	}

	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		logger.Info("bridge block scanner started",
			"rpc_configured", rpcClient != nil,
			"woc_configured", wocClient != nil,
		)
		for {
			select {
			case <-scanCtx.Done():
				return
			case height, ok := <-blockCh:
				if !ok {
					logger.Warn("bridge block scanner: chaintracks stream closed; scanner exiting (no auto-resubscribe in this wave)")
					return
				}
				txs, err := adapter.GetBlockTransactions(height)
				if err != nil {
					if errors.Is(err, ErrBlockFetchUnsupported) {
						// Surface once per startup, then squelch: the
						// scanner is effectively a no-op without RPC,
						// but the chaintracks subscription is cheap
						// enough to keep open for reorg notifications.
						logger.Debug("bridge block scanner: getblock unsupported, skipping height", "height", height)
						continue
					}
					logger.Warn("bridge block scanner: GetBlockTransactions failed", "height", height, "err", err)
					continue
				}
				monitor.ProcessBlock(height, txs)
			}
		}
	}()

	closeFn := func() error {
		cancel()
		done.Wait()
		return nil
	}
	return closeFn, nil
}
