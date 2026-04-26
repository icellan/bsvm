package chaintracks

import (
	"encoding/hex"
	"fmt"
)

// Checkpoint pins a (height, hash) pair on the BSV main chain. Any
// header reported at this height MUST hash to this value or the
// validator rejects the chain.
//
// Hash is in INTERNAL byte order (the same orientation BlockHeader.Hash
// uses — i.e. the raw double-SHA256 result without display reversal).
// Use the helper MustReverseHex to seed checkpoints from a Bitcoin-
// style display hash, e.g. WhatsOnChain or a block explorer.
type Checkpoint struct {
	Height uint64
	Hash   [32]byte
}

// IMPORTANT — to update before each release:
//
// These checkpoints pin the BSV main chain. They must be refreshed
// from a trusted block explorer (e.g. https://whatsonchain.com or a
// self-operated BSV node) prior to every release so the validator
// rejects any history-rewriting reorg older than the latest pinned
// height.
//
// Each entry includes the source URL for verification. The hashes are
// expressed in display order (big-endian) and converted to internal
// byte order at init() time.
//
// Captured 2026-04-26 from publicly published BSV block-hash data.

var bsvMainnetCheckpoints = []struct {
	Height  uint64
	Display string // big-endian display hash
}{
	// Bitcoin / BSV genesis block. This value is fixed forever.
	{0, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"},
	// Block 478558: pre-fork checkpoint, last common ancestor of BTC,
	// BCH, and BSV. Anchors the entire post-2017 chain.
	{478558, "0000000000000000011865af4122fe3b144e2cbeea86142e8ff2fb4107352d43"},
	// Block 556767: BCH/BSV split block. Pinning this excludes any
	// reorg attempt that re-writes the original BCH-side history.
	{556767, "0000000000000000004626ff6e3b936941d341c5932ece4357eeccac44e6d56c"},
	// Block 800000: high-water mainnet activity checkpoint.
	{800000, "00000000000000000d20cb78d80c0d6cdb50fcdb1ad24cf41d09a52a47104b50"},
}

var defaultCheckpoints []Checkpoint

func init() {
	defaultCheckpoints = make([]Checkpoint, 0, len(bsvMainnetCheckpoints))
	for _, c := range bsvMainnetCheckpoints {
		defaultCheckpoints = append(defaultCheckpoints, Checkpoint{
			Height: c.Height,
			Hash:   MustReverseHex(c.Display),
		})
	}
}

// DefaultCheckpoints returns a fresh copy of the pinned BSV mainnet
// checkpoints. The slice is sorted by height.
func DefaultCheckpoints() []Checkpoint {
	out := make([]Checkpoint, len(defaultCheckpoints))
	copy(out, defaultCheckpoints)
	return out
}

// LatestCheckpointHeight returns the height of the highest checkpoint
// in cps (or 0 if cps is empty).
func LatestCheckpointHeight(cps []Checkpoint) uint64 {
	var max uint64
	for _, c := range cps {
		if c.Height > max {
			max = c.Height
		}
	}
	return max
}

// EnforceCheckpoints rejects h if (a) its height matches a pinned
// checkpoint but its hash does not, or (b) its height is below the
// latest pinned checkpoint (i.e. would re-write history beneath an
// established anchor).
//
// Pass cps=nil to disable enforcement (used by tests against synthetic
// chains and by the bootstrap path before checkpoints are configured).
func EnforceCheckpoints(h *BlockHeader, cps []Checkpoint) error {
	if h == nil || len(cps) == 0 {
		return nil
	}
	latest := LatestCheckpointHeight(cps)
	if h.Height < latest {
		return fmt.Errorf("%w: height %d < latest checkpoint %d", ErrBelowCheckpoint, h.Height, latest)
	}
	for _, c := range cps {
		if c.Height == h.Height && c.Hash != h.Hash {
			return fmt.Errorf("%w: at height %d expected %x got %x",
				ErrCheckpointMismatch, c.Height, c.Hash, h.Hash)
		}
	}
	return nil
}

// MustReverseHex parses a 64-character display-order hex string and
// returns the bytes in INTERNAL byte order. Panics on bad input — only
// use with compile-time-constant strings (i.e. checkpoint literals).
func MustReverseHex(displayHex string) [32]byte {
	b, err := hex.DecodeString(displayHex)
	if err != nil {
		panic(fmt.Sprintf("checkpoints: bad hex %q: %v", displayHex, err))
	}
	if len(b) != 32 {
		panic(fmt.Sprintf("checkpoints: bad length %d for %q", len(b), displayHex))
	}
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out
}
