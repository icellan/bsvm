package bridge

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// withdrawalInitiatedTopic mirrors the topic-0 hash emitted by
// pkg/block.ApplyWithdrawTx for the canonical
// `WithdrawalInitiated(uint256,bytes20,uint256,bytes32)` event. It is
// recomputed here (rather than imported from pkg/block) so the bridge
// package keeps its one-way dependency on the EVM execution layer:
// pkg/block already imports pkg/bridge, so the reverse is forbidden.
var withdrawalInitiatedTopic = types.BytesToHash(crypto.Keccak256(
	[]byte("WithdrawalInitiated(uint256,bytes20,uint256,bytes32)"),
))

// ChainHeader is the minimal subset of an L2 header the scanner needs.
// Defined locally to avoid importing pkg/block.
type ChainHeader struct {
	Number uint64
	Hash   types.Hash
}

// ChainReader is the minimal subset of pkg/block.ChainDB the
// production WithdrawalScanner uses to walk finalized batches and
// pull receipts. The cmd-side wiring passes a small adapter that
// forwards to the daemon's *block.ChainDB so pkg/bridge does not
// need to import pkg/block.
type ChainReader interface {
	// HeaderByNumber returns a minimal header (number + canonical hash)
	// for the given block, or nil when the block is not in the canonical
	// chain.
	HeaderByNumber(number uint64) *ChainHeader
	// ReceiptsByBlock returns the receipts stored at (hash, number), or
	// nil on miss. The order MUST match the order receipts were emitted
	// during execution — withdrawals are scanned in receipt order so the
	// nonce-recovery logic relies on stable ordering.
	ReceiptsByBlock(hash types.Hash, number uint64) []*types.Receipt
}

// FinalizedTipProvider returns the highest L2 block number with at
// least 6 BSV confirmations. The OverlayNode satisfies this seam via
// FinalizedTip(); tests pass a static value.
type FinalizedTipProvider interface {
	FinalizedTip() uint64
}

// FinalizedTipFunc adapts a plain function into a FinalizedTipProvider.
type FinalizedTipFunc func() uint64

// FinalizedTip implements FinalizedTipProvider.
func (f FinalizedTipFunc) FinalizedTip() uint64 { return f() }

// ChainDBWithdrawalScanner is the production implementation of
// WithdrawalScanner. It walks the canonical chain from block 1 up to
// the latest finalized tip, scans receipts for WithdrawalInitiated
// logs, reconstructs the per-batch withdrawal-hash list, and returns
// only those withdrawals whose nonce >= the bridge's last-claimed
// nonce + 1.
//
// The scanner is stateless across calls: every invocation walks the
// chain fresh. Callers wire the bridge UTXO's LastClaimedNonce in via
// the fromNonce argument (Withdrawer does this in
// ProcessFinalizedWithdrawals), giving idempotent semantics — running
// twice produces the same result, and an already-claimed withdrawal is
// filtered before it ever reaches the broadcaster.
//
// Cancellation: ScanPendingWithdrawalsCtx accepts a context and returns
// early if it is cancelled mid-walk. The plain WithdrawalScanner
// interface uses ScanPendingWithdrawals (no context); use the Ctx
// variant from the daemon loop to cooperate with shutdown.
type ChainDBWithdrawalScanner struct {
	chain     ChainReader
	finalized FinalizedTipProvider
}

// NewChainDBWithdrawalScanner constructs the scanner. Both arguments
// must be non-nil.
func NewChainDBWithdrawalScanner(
	chain ChainReader,
	finalized FinalizedTipProvider,
) *ChainDBWithdrawalScanner {
	return &ChainDBWithdrawalScanner{chain: chain, finalized: finalized}
}

// ScanPendingWithdrawals implements WithdrawalScanner. See
// ScanPendingWithdrawalsCtx for the cancellable variant; this method
// passes context.Background() through.
func (s *ChainDBWithdrawalScanner) ScanPendingWithdrawals(fromNonce uint64) ([]*PendingWithdrawal, error) {
	return s.ScanPendingWithdrawalsCtx(context.Background(), fromNonce)
}

// ScanPendingWithdrawalsCtx walks the canonical chain up to the
// current finalized tip and returns every WithdrawalInitiated event
// whose recovered nonce >= fromNonce, in nonce order. Honours ctx
// cancellation between blocks.
//
// Algorithm:
//
//  1. Read finalizedTip from the FinalizedTipProvider. Anything above
//     the tip is speculative and MUST NOT be claimed yet (the BSV
//     bridge covenant rejects withdrawals against an unfinalized
//     advance).
//  2. Walk blocks 1..finalizedTip. For each, read receipts and scan
//     for WithdrawalInitiated logs in emission order.
//  3. Per batch: collect the full ordered list of leaf hashes (so the
//     Merkle proof for any leaf can be constructed); assign each
//     withdrawal its position-in-batch as LeafIndex; thread the full
//     leaf list through PendingWithdrawal.BatchHashes so the Withdrawer
//     can re-verify the locally-computed root against what the SP1
//     guest committed.
//  4. Filter against fromNonce: drop entries whose nonce < fromNonce.
//
// Implementation note on nonce recovery: ApplyWithdrawTx increments
// the bridge's withdrawalNonce slot once per withdrawal in emission
// order. We mirror that by maintaining a running counter as we walk
// the chain — the counter is the "next nonce to assign" and matches
// what the on-chain bridge stored at the time of each event.
func (s *ChainDBWithdrawalScanner) ScanPendingWithdrawalsCtx(ctx context.Context, fromNonce uint64) ([]*PendingWithdrawal, error) {
	if s.chain == nil {
		return nil, fmt.Errorf("chain reader is nil")
	}
	if s.finalized == nil {
		return nil, fmt.Errorf("finalized tip provider is nil")
	}

	tip := s.finalized.FinalizedTip()
	if tip == 0 {
		return nil, nil
	}

	// nextNonce tracks the on-chain bridge's withdrawalNonce slot value
	// at the START of each log we visit. It begins at 0 (genesis bridge
	// state) and increments per WithdrawalInitiated event.
	var nextNonce uint64
	var pending []*PendingWithdrawal

	for blockNum := uint64(1); blockNum <= tip; blockNum++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header := s.chain.HeaderByNumber(blockNum)
		if header == nil {
			// A gap in the canonical chain is a hard error during a
			// finalized walk: the chain head reports finality up to
			// `tip` but a block in [1, tip] is missing. Skip + log
			// rather than fail the whole scan; the caller's next pass
			// can pick up where this one left off.
			slog.Warn("withdrawal scanner: missing canonical header, skipping",
				"block", blockNum, "tip", tip)
			continue
		}
		receipts := s.chain.ReceiptsByBlock(header.Hash, header.Number)
		if len(receipts) == 0 {
			continue
		}

		// First pass: collect per-batch leaf hashes in emission order
		// and remember which (recipient, satoshis, leafIdx) each leaf
		// originated from. We need the full list before producing
		// PendingWithdrawal records so each gets the same BatchHashes.
		type emitted struct {
			recipient []byte
			satoshis  uint64
			leafIdx   int
			nonce     uint64
		}
		var batchLeaves []types.Hash
		var emits []emitted

		for _, r := range receipts {
			if r == nil {
				continue
			}
			for _, log := range r.Logs {
				if log == nil || log.Address != types.BridgeContractAddress {
					continue
				}
				if len(log.Topics) == 0 || log.Topics[0] != withdrawalInitiatedTopic {
					continue
				}
				// Need 96 bytes: addrPadded(32) | weiAmount(32) | withdrawalHash(32).
				if len(log.Data) < 96 {
					slog.Warn("withdrawal scanner: log data too short",
						"len", len(log.Data), "block", blockNum)
					continue
				}
				bsvAddr := make([]byte, 20)
				copy(bsvAddr, log.Data[0:20])
				satoshis := weiBytesToSatoshisBE(log.Data[32:64])
				var leaf types.Hash
				copy(leaf[:], log.Data[64:96])

				idx := len(batchLeaves)
				batchLeaves = append(batchLeaves, leaf)
				emits = append(emits, emitted{
					recipient: bsvAddr,
					satoshis:  satoshis,
					leafIdx:   idx,
					nonce:     nextNonce,
				})
				nextNonce++
			}
		}

		if len(emits) == 0 {
			continue
		}

		// Second pass: produce PendingWithdrawal records, threading the
		// full per-batch leaf list (BatchHashes) through so the
		// Withdrawer can reconstruct the Merkle proof and cross-check
		// against the SP1-committed withdrawalRoot.
		for _, e := range emits {
			if e.nonce < fromNonce {
				continue
			}
			pending = append(pending, &PendingWithdrawal{
				Nonce:          e.nonce,
				BSVAddress:     e.recipient,
				AmountSatoshis: e.satoshis,
				L2BlockNum:     blockNum,
				WithdrawalHash: WithdrawalHash(e.recipient, e.satoshis, e.nonce),
				LeafIndex:      e.leafIdx,
				BatchHashes:    batchLeaves,
			})
		}
	}

	return pending, nil
}

// weiBytesToSatoshisBE interprets a 32-byte big-endian wei amount and
// converts to satoshis (floor div by 10^10). Mirrors the helper in
// pkg/overlay (which is private to that package); the bridge package
// reproduces it locally to avoid a circular import (pkg/overlay
// already imports pkg/bridge).
func weiBytesToSatoshisBE(b []byte) uint64 {
	if len(b) != 32 {
		return 0
	}
	for i := 0; i < 24; i++ {
		if b[i] != 0 {
			weiHi := binary.BigEndian.Uint64(b[16:24])
			weiLo := binary.BigEndian.Uint64(b[24:32])
			if weiHi == 0 {
				return weiLo / 10_000_000_000
			}
			return ^uint64(0)
		}
	}
	wei := binary.BigEndian.Uint64(b[24:32])
	return wei / 10_000_000_000
}
