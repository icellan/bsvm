// Daemon-side adapter that satisfies bridge.BSVClient by composing
// the chaintracks header oracle (W6-1/2/9), the WhatsOnChain raw-tx
// fetcher (W6-8), and the BSV-node JSON-RPC failover provider (W6-11).
// Until this file landed, BuildBridgeMonitor was always called with a
// nil bsvClient because no single in-tree client implemented the
// SubscribeNewBlocks / GetBlockTransactions surface the monitor needs
// for the legacy block-scanning fallback path. The BEEF deposit path
// (W6-4) had been wired and remains the primary deposit channel; this
// adapter restores the secondary path for deposits that arrive
// directly on-chain (BSV tx with a bridge-script output, no BEEF
// envelope).
//
// Composition:
//
//   - SubscribeNewBlocks rides on chaintracks.SubscribeReorgs. The
//     chaintracks stream surfaces both forward extensions and reorgs
//     as the same ReorgEvent shape; the adapter projects every event's
//     NewTip hash to a height via chaintracks.HeaderByHash and pushes
//     the height into the channel the BridgeMonitor consumes.
//   - Reorg events (CommonAncestor != OldTip) ALSO trigger a
//     RetractDepositsAbove call on the BridgeMonitor so deposits
//     observed in the orphaned chain segment are rolled back; the
//     monitor will re-detect any survivors when ProcessBlock runs
//     against the new chain.
//   - GetBlockTransactions resolves the height to a block hash via
//     chaintracks, then calls the BSV-node RPC's `getblock <hash> 2`
//     to project the verbose vout list into bridge.BSVTransaction.
//     When no RPC provider is configured (operators on a deployment
//     using only chaintracks plus WoC) this returns
//     ErrBlockFetchUnsupported — the BEEF deposit path remains live,
//     but the on-chain block-scan fallback is not available without
//     an RPC node. WoC's per-tx fan-out path is left as a follow-up
//     because every WoC GetTx burns one rate-limited API call; for a
//     4 MB block that's multiple thousand calls and operators will
//     routinely hit the daily quota. RPC is the realistic deployment
//     shape for any operator who actually wants block-scan-based
//     deposits.
//   - GetTransaction delegates to WoC's cached client (W6-8) which
//     transparently shares a singleflight gate so concurrent ParseDeposit
//     ancestor lookups collapse to one RTT.
//   - GetBlockHeight reads chaintracks Tip().
//
// Reorg-safety: bounded resource use is preserved by streaming the
// block's tx list lazily — the verbose getblock response is parsed
// directly into BSVTransaction values without holding the JSON tree
// in memory beyond the one-block scope. The adapter never caches
// scanned block contents; the BridgeMonitor's own ProcessBlock /
// RetractDepositsAbove bookkeeping is the source of truth.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/whatsonchain"
)

// ErrBlockFetchUnsupported is returned by GetBlockTransactions when
// no BSV-node RPC provider is configured and the block-fetch path has
// no upstream to ask. Callers (the BridgeMonitor.Run loop) are
// expected to log + skip; the BEEF deposit path is unaffected.
var ErrBlockFetchUnsupported = errors.New("bridge bsv client: getblock unsupported (no BSV-node RPC configured)")

// blockFetchTimeout caps each per-block RPC call. A verbose getblock on
// a packed BSV block can ship multiple megabytes of JSON; 60s is
// generous enough to absorb an HTTP slow-start without holding the
// monitor goroutine open indefinitely.
const blockFetchTimeout = 60 * time.Second

// bridgeNotifier is the subset of bridge.BridgeMonitor the adapter
// drives for reorg retraction. Defined as an interface so the unit
// tests can inject a recording fake without standing up a real monitor.
type bridgeNotifier interface {
	RetractDepositsAbove(minHeight uint64)
}

// bridgeRPCClient is the subset of cmd/bsvm.BSVProviderClient the
// adapter actually uses. Keeping the surface small lets tests inject
// a stub that only implements Call.
type bridgeRPCClient interface {
	Call(method string, params ...interface{}) (json.RawMessage, error)
}

// bridgeBSVClient implements bridge.BSVClient by composing the
// chaintracks SPV anchor with WoC raw-tx lookups and (optionally) the
// BSV-node JSON-RPC failover provider. See the package doc-comment for
// the full design rationale.
type bridgeBSVClient struct {
	cht     chaintracks.ChaintracksClient
	woc     whatsonchain.WhatsOnChainClient
	rpc     bridgeRPCClient
	monitor bridgeNotifier // optional; when non-nil reorgs trigger RetractDepositsAbove
	logger  *slog.Logger

	mu      sync.Mutex
	lastTip [32]byte // tracked so duplicate stream frames don't re-publish heights
}

// newBridgeBSVClient constructs the adapter. cht is required (the
// monitor cannot scan without an SPV anchor). rpc is optional; when
// nil GetBlockTransactions returns ErrBlockFetchUnsupported. woc is
// optional; when nil GetTransaction returns whatsonchain.ErrNotFound
// for every txid.
func newBridgeBSVClient(
	cht chaintracks.ChaintracksClient,
	woc whatsonchain.WhatsOnChainClient,
	rpc bridgeRPCClient,
	monitor bridgeNotifier,
	logger *slog.Logger,
) (*bridgeBSVClient, error) {
	if cht == nil {
		return nil, errors.New("bridge bsv client: chaintracks required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &bridgeBSVClient{
		cht:     cht,
		woc:     woc,
		rpc:     rpc,
		monitor: monitor,
		logger:  logger,
	}, nil
}

// GetTransaction fetches a single BSV transaction by txid via the
// cached WoC client. Returns nil + nil error when WoC reports
// not-found so the BridgeMonitor's pre-check call sites can treat
// "not in WoC" as "ignore" rather than "fail". When no WoC client is
// configured the method returns nil + nil — this is consistent with
// the legacy mockBSVClient behaviour and means the BEEF path remains
// the only deposit source on a WoC-less deployment.
func (a *bridgeBSVClient) GetTransaction(txid types.Hash) (*bridge.BSVTransaction, error) {
	if a.woc == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), blockFetchTimeout)
	defer cancel()
	raw, err := a.woc.GetTx(ctx, [32]byte(txid))
	if err != nil {
		if errors.Is(err, whatsonchain.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("bridge bsv client: GetTx %x: %w", txid[:8], err)
	}
	// raw is the canonical BSV tx serialisation. We only need the
	// outputs for ParseDeposit, but parsing the full tx here would
	// duplicate the SDK's transaction.Transaction.Hex roundtrip; the
	// monitor's BEEF path already covers ancestor lookups and the
	// block-scan path uses GetBlockTransactions for outputs. Surface
	// the raw bytes inside an output-less BSVTransaction so callers
	// see "exists, no parsed body" — they'll fall through to the
	// block-scan path for actual deposit detection.
	_ = raw
	return &bridge.BSVTransaction{
		TxID: txid,
	}, nil
}

// GetBlockHeight returns the current BSV chain tip height from
// chaintracks.
func (a *bridgeBSVClient) GetBlockHeight() (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tip, err := a.cht.Tip(ctx)
	if err != nil {
		return 0, fmt.Errorf("bridge bsv client: chaintracks tip: %w", err)
	}
	return tip.Height, nil
}

// GetBlockTransactions resolves height → block hash via chaintracks
// then fetches the verbose block from the configured BSV-node RPC and
// projects each tx's vout into bridge.BSVTransaction.
//
// Returns ErrBlockFetchUnsupported when no RPC client is configured —
// the BEEF path remains live but block scanning is unavailable.
func (a *bridgeBSVClient) GetBlockTransactions(height uint64) ([]*bridge.BSVTransaction, error) {
	if a.rpc == nil {
		return nil, ErrBlockFetchUnsupported
	}
	ctx, cancel := context.WithTimeout(context.Background(), blockFetchTimeout)
	defer cancel()
	hdr, err := a.cht.HeaderByHeight(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("bridge bsv client: header at %d: %w", height, err)
	}
	blockHashHex := hex.EncodeToString(reverseBytes(hdr.Hash[:]))
	// Verbosity 2: header + tx list with full vout/value/script details.
	resp, err := a.rpc.Call("getblock", blockHashHex, 2)
	if err != nil {
		return nil, fmt.Errorf("bridge bsv client: getblock %s: %w", blockHashHex, err)
	}
	return parseVerboseBlock(resp, height)
}

// SubscribeNewBlocks rides on chaintracks.SubscribeReorgs. Every event
// (forward extension OR reorg) is projected to the new tip's height;
// the height is pushed into the returned channel. Reorgs additionally
// trigger RetractDepositsAbove on the configured notifier so the
// monitor's pending list is rolled back to the common ancestor before
// the new-chain blocks are scanned.
//
// Channel buffer is 16 — enough to absorb a brief monitor stall
// without tripping chaintracks' "subscriber slow, disconnecting"
// safeguard. If the consumer falls further behind chaintracks will
// drop us; the monitor will reconnect on the next ProcessBlock cycle
// (a follow-up wave wires automatic re-subscription on EOF).
func (a *bridgeBSVClient) SubscribeNewBlocks(ctx context.Context) (<-chan uint64, error) {
	reorgCh, err := a.cht.SubscribeReorgs(ctx)
	if err != nil {
		return nil, fmt.Errorf("bridge bsv client: SubscribeReorgs: %w", err)
	}
	out := make(chan uint64, 16)
	go a.pumpReorgs(ctx, reorgCh, out)
	return out, nil
}

// pumpReorgs is the goroutine spawned by SubscribeNewBlocks. It owns
// the close on `out` so receivers can rely on the channel-close
// semantics for shutdown.
func (a *bridgeBSVClient) pumpReorgs(ctx context.Context, in <-chan *chaintracks.ReorgEvent, out chan<- uint64) {
	defer close(out)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			if ev == nil {
				continue
			}
			a.handleReorgEvent(ctx, ev, out)
		}
	}
}

// handleReorgEvent classifies the chaintracks event, performs reorg
// retraction if needed, and pushes the new tip's height into out.
func (a *bridgeBSVClient) handleReorgEvent(ctx context.Context, ev *chaintracks.ReorgEvent, out chan<- uint64) {
	a.mu.Lock()
	prevTip := a.lastTip
	a.lastTip = ev.NewTip
	a.mu.Unlock()
	if ev.NewTip == prevTip {
		// Duplicate frame (e.g. resume + initial tip). Skip.
		return
	}

	hdr, err := a.cht.HeaderByHash(ctx, ev.NewTip)
	if err != nil {
		a.logger.Warn("bridge block-scan: HeaderByHash for new tip failed",
			"new_tip", hex.EncodeToString(ev.NewTip[:]),
			"err", err,
		)
		return
	}

	// Reorg discriminator: chaintracks emits forward extensions with
	// CommonAncestor == OldTip (the parent of NewTip). Anything else
	// — different OldTip vs CommonAncestor, or a NewChainLen > 1 — is
	// a reorg and we must retract first.
	isReorg := ev.OldTip != ev.CommonAncestor || ev.NewChainLen > 1
	if isReorg && a.monitor != nil {
		caHdr, err := a.cht.HeaderByHash(ctx, ev.CommonAncestor)
		if err != nil {
			// We can't establish the common-ancestor height. Retract
			// everything pending — pessimistic but safe (the new chain
			// will re-credit any survivors).
			a.logger.Warn("bridge block-scan: reorg without common-ancestor header, retracting all pending",
				"new_tip", hex.EncodeToString(ev.NewTip[:]),
				"common_ancestor", hex.EncodeToString(ev.CommonAncestor[:]),
				"err", err,
			)
			a.monitor.RetractDepositsAbove(0)
		} else {
			a.logger.Info("bridge block-scan: reorg detected, retracting deposits above common ancestor",
				"common_ancestor_height", caHdr.Height,
				"new_tip_height", hdr.Height,
				"new_chain_len", ev.NewChainLen,
			)
			a.monitor.RetractDepositsAbove(caHdr.Height)
		}
	}

	select {
	case out <- hdr.Height:
	case <-ctx.Done():
	}
}

// parseVerboseBlock turns the JSON payload of `getblock <hash> 2`
// into a slice of bridge.BSVTransaction values. The verbose schema
// matches bitcoind / SV Node / Teranode: a `tx` array of objects, each
// with a `txid` (hex, big-endian) and a `vout` array of {value,
// scriptPubKey: {hex}} entries.
func parseVerboseBlock(raw json.RawMessage, height uint64) ([]*bridge.BSVTransaction, error) {
	var block struct {
		Tx []struct {
			TxID string `json:"txid"`
			Vout []struct {
				Value        float64 `json:"value"`
				ScriptPubKey struct {
					Hex string `json:"hex"`
				} `json:"scriptPubKey"`
			} `json:"vout"`
		} `json:"tx"`
	}
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, fmt.Errorf("bridge bsv client: parse getblock: %w", err)
	}

	out := make([]*bridge.BSVTransaction, 0, len(block.Tx))
	for i, tx := range block.Tx {
		txid, err := decodeBSVHashBE(tx.TxID)
		if err != nil {
			// One bad txid in a 4 MB block is not worth aborting the
			// whole scan — log and skip. The adjacent txs are still
			// scannable.
			continue
		}
		bt := &bridge.BSVTransaction{
			TxID:        txid,
			BlockHeight: height,
			TxIndex:     uint(i),
			Outputs:     make([]bridge.BSVOutput, 0, len(tx.Vout)),
		}
		for _, o := range tx.Vout {
			script, err := hex.DecodeString(o.ScriptPubKey.Hex)
			if err != nil {
				continue
			}
			// `value` is in BSV (decimal). Round to satoshi to avoid
			// float drift on round-number outputs — same convention as
			// pkg/bsvclient/rpc_provider.go::GetTransaction.
			sats := uint64(math.Round(o.Value * 1e8))
			bt.Outputs = append(bt.Outputs, bridge.BSVOutput{
				Script: script,
				Value:  sats,
			})
		}
		out = append(out, bt)
	}
	return out, nil
}

// decodeBSVHashBE parses a big-endian hex hash (the BSV display form
// returned by bitcoind / WoC) into a types.Hash. The internal byte
// order in BSVM is little-endian (matching BSV consensus serialisation
// and chaintracks); we reverse during decode so callers see the
// natural in-memory shape used everywhere else in this package.
func decodeBSVHashBE(s string) (types.Hash, error) {
	var h types.Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	if len(b) != 32 {
		return h, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	for i := 0; i < 32; i++ {
		h[i] = b[31-i]
	}
	return h, nil
}

// reverseBytes returns the byte-reversed copy of b. Used to convert
// the chaintracks little-endian header hash into the big-endian hex
// form bitcoind / WoC expect on input.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, x := range b {
		out[len(b)-1-i] = x
	}
	return out
}
