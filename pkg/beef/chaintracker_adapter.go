package beef

import (
	"context"
	"errors"
	"fmt"

	sdkhash "github.com/bsv-blockchain/go-sdk/chainhash"
	sdkct "github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/icellan/bsvm/pkg/chaintracks"
)

// chaintracksAdapter satisfies the go-sdk's chaintracker.ChainTracker
// interface on top of our pkg/chaintracks.ChaintracksClient. The SDK's
// MerklePath.Verify and spv.Verify call IsValidRootForHeight to bind a
// computed merkle root to a confirmed BSV header at the BUMP's declared
// block height — we forward to MerkleRootAtHeight and compare.
//
// CurrentHeight returns the chaintracks tip's height; the SDK uses it
// only when the caller did not pre-stamp the merkle path with a height
// (which our flow always does), so an error here is non-fatal for the
// hot path but we still implement it to keep the contract honest.
type chaintracksAdapter struct {
	ct chaintracks.ChaintracksClient
}

// NewChaintracksAdapter wraps a ChaintracksClient into a value the
// go-sdk's verification helpers accept. The returned adapter is safe
// for concurrent use as long as the underlying client is.
func NewChaintracksAdapter(ct chaintracks.ChaintracksClient) sdkct.ChainTracker {
	return &chaintracksAdapter{ct: ct}
}

// IsValidRootForHeight implements chaintracker.ChainTracker. Returns
// true iff the chaintracks-known header at height has a merkle root
// equal to root. ErrUnknownHeader from chaintracks surfaces as
// (false, nil) so the SDK's BUMP verifier reports the more useful
// "merkle path does not validate" error rather than a transport-style
// failure; explicit transport / quorum errors are propagated.
func (a *chaintracksAdapter) IsValidRootForHeight(ctx context.Context, root *sdkhash.Hash, height uint32) (bool, error) {
	if a == nil || a.ct == nil {
		return false, errors.New("beef: chaintracks adapter has no client")
	}
	if root == nil {
		return false, errors.New("beef: nil merkle root")
	}
	expected, err := a.ct.MerkleRootAtHeight(ctx, uint64(height))
	if err != nil {
		if errors.Is(err, chaintracks.ErrUnknownHeader) {
			// Header not yet seen — treat as "no, this root does not bind
			// to a known header" rather than as a transport error so the
			// caller's reject reason is the user-facing one.
			return false, nil
		}
		return false, fmt.Errorf("beef: header lookup at %d: %w", height, err)
	}
	// MerkleRootAtHeight returns the canonical 32-byte little-endian
	// internal-byte-order root, which is also how the SDK's
	// chainhash.Hash stores values. Compare bytewise.
	for i := 0; i < 32; i++ {
		if expected[i] != root[i] {
			return false, nil
		}
	}
	return true, nil
}

// CurrentHeight implements chaintracker.ChainTracker. Returns the
// chaintracks tip height as a uint32; the SDK callers never need a
// value above the BSV chain height so the truncation is safe in
// practice.
func (a *chaintracksAdapter) CurrentHeight(ctx context.Context) (uint32, error) {
	if a == nil || a.ct == nil {
		return 0, errors.New("beef: chaintracks adapter has no client")
	}
	tip, err := a.ct.Tip(ctx)
	if err != nil {
		return 0, fmt.Errorf("beef: tip lookup: %w", err)
	}
	if tip == nil {
		return 0, errors.New("beef: chaintracks has no tip")
	}
	return uint32(tip.Height), nil
}
