package chaintracks

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Validation errors. Callers can errors.Is against these to distinguish
// the failure mode without parsing strings.
var (
	// ErrBadPoW is returned when a header's double-SHA256 does not meet
	// the target encoded in its bits field.
	ErrBadPoW = errors.New("chaintracks: header fails proof-of-work")
	// ErrBadBits is returned when the compact-bits target is malformed
	// (e.g. negative target, exponent overflow).
	ErrBadBits = errors.New("chaintracks: malformed bits target")
	// ErrBrokenChain is returned when a header's PrevHash does not match
	// the previous header's Hash.
	ErrBrokenChain = errors.New("chaintracks: prev-hash does not link")
	// ErrHashMismatch is returned when a header's Hash field disagrees
	// with the double-SHA256 of its serialised body.
	ErrHashMismatch = errors.New("chaintracks: declared hash does not match header bytes")
	// ErrCheckpointMismatch is returned when a header at a hard-coded
	// checkpoint height has a different hash than the pinned value.
	ErrCheckpointMismatch = errors.New("chaintracks: header diverges from pinned checkpoint")
	// ErrBelowCheckpoint is returned when a header's height is below
	// the latest pinned checkpoint and would re-write history.
	ErrBelowCheckpoint = errors.New("chaintracks: header below latest checkpoint")
	// ErrInsufficientWork is returned when a candidate chain's
	// cumulative work does not strictly exceed the current chain's.
	ErrInsufficientWork = errors.New("chaintracks: candidate chain has insufficient cumulative work")
)

// SerializeHeader builds the canonical 80-byte BSV/Bitcoin block header
// from a BlockHeader. Version defaults to 1 when not set, matching how
// upstream BRC-64 wire formats often omit it; production deployments
// SHOULD populate Version via the wire decoder. The output is the
// little-endian-fields, internal-byte-order layout that hashes via
// double-SHA256 to the canonical block hash.
func SerializeHeader(h *BlockHeader) []byte {
	var buf [80]byte
	v := h.Version
	if v == 0 {
		v = 1
	}
	binary.LittleEndian.PutUint32(buf[0:4], uint32(v))
	copy(buf[4:36], h.PrevHash[:])
	copy(buf[36:68], h.MerkleRoot[:])
	binary.LittleEndian.PutUint32(buf[68:72], h.Timestamp)
	binary.LittleEndian.PutUint32(buf[72:76], h.Bits)
	binary.LittleEndian.PutUint32(buf[76:80], h.Nonce)
	return buf[:]
}

// HeaderHash returns the double-SHA256 of the serialised header (i.e.
// the canonical block hash, in internal byte order — NOT reversed for
// display).
func HeaderHash(h *BlockHeader) [32]byte {
	first := sha256.Sum256(SerializeHeader(h))
	return sha256.Sum256(first[:])
}

// CompactToTarget decodes the Bitcoin "compact" (nBits) representation
// into the corresponding *big.Int target. It rejects targets with the
// sign bit set and exponents that would overflow 256 bits, matching
// Bitcoin Core semantics.
func CompactToTarget(bits uint32) (*big.Int, error) {
	if bits == 0 {
		return nil, fmt.Errorf("%w: zero bits", ErrBadBits)
	}
	exponent := bits >> 24
	mantissa := bits & 0x007fffff
	if bits&0x00800000 != 0 {
		return nil, fmt.Errorf("%w: negative target", ErrBadBits)
	}
	target := new(big.Int)
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		target.SetUint64(uint64(mantissa))
	} else {
		target.SetUint64(uint64(mantissa))
		target.Lsh(target, uint(8*(exponent-3)))
	}
	if target.BitLen() > 256 {
		return nil, fmt.Errorf("%w: target overflow", ErrBadBits)
	}
	return target, nil
}

// WorkForBits returns the chainwork contribution of a single header at
// the given compact-bits difficulty, computed as floor(2^256 / (target +
// 1)). This matches Bitcoin Core's `GetBlockProof`.
func WorkForBits(bits uint32) (*big.Int, error) {
	target, err := CompactToTarget(bits)
	if err != nil {
		return nil, err
	}
	if target.Sign() == 0 {
		return new(big.Int), nil
	}
	num := new(big.Int).Lsh(big.NewInt(1), 256)
	den := new(big.Int).Add(target, big.NewInt(1))
	return num.Quo(num, den), nil
}

// hashToBig interprets a 32-byte block hash (internal byte order, i.e.
// little-endian display) as a big-endian unsigned integer for
// target-comparison. Bitcoin Core stores hashes little-endian in
// memory, so the comparison reverses the bytes.
func hashToBig(h [32]byte) *big.Int {
	var rev [32]byte
	for i := 0; i < 32; i++ {
		rev[i] = h[31-i]
	}
	return new(big.Int).SetBytes(rev[:])
}

// CheckProofOfWork verifies that the header's hash, computed from its
// serialised body, is <= the target encoded by its bits. Returns nil
// on success, ErrBadPoW (or ErrBadBits / ErrHashMismatch) on failure.
//
// The header's declared Hash is also cross-checked against the
// recomputed hash — a chaintracks upstream that reports a hash
// inconsistent with the header bytes is rejected outright.
func CheckProofOfWork(h *BlockHeader) error {
	if h == nil {
		return errors.New("chaintracks: nil header")
	}
	target, err := CompactToTarget(h.Bits)
	if err != nil {
		return err
	}
	got := HeaderHash(h)
	// Empty declared hash means the upstream hasn't filled it in;
	// adopt the recomputed value rather than failing.
	var zero [32]byte
	if h.Hash != zero && h.Hash != got {
		return fmt.Errorf("%w: got %x want %x", ErrHashMismatch, got, h.Hash)
	}
	if hashToBig(got).Cmp(target) > 0 {
		return fmt.Errorf("%w: hash %x above target", ErrBadPoW, got)
	}
	return nil
}

// CheckLink verifies that next.PrevHash matches prev.Hash. prev may be
// nil to skip the link check (used at the bootstrap checkpoint where
// the parent is unknown).
func CheckLink(prev, next *BlockHeader) error {
	if prev == nil || next == nil {
		return nil
	}
	if next.PrevHash != prev.Hash {
		return fmt.Errorf("%w: next.prev=%x prev.hash=%x", ErrBrokenChain, next.PrevHash, prev.Hash)
	}
	if next.Height != prev.Height+1 {
		return fmt.Errorf("%w: height jump %d -> %d", ErrBrokenChain, prev.Height, next.Height)
	}
	return nil
}

// ValidateHeader runs PoW + link checks + checkpoint enforcement for a
// single header against an optional parent. Pass cps=DefaultCheckpoints()
// (or a custom set) to enforce checkpoints; pass nil to skip them
// (useful in tests against synthetic low-difficulty chains).
func ValidateHeader(prev, h *BlockHeader, cps []Checkpoint) error {
	if err := CheckProofOfWork(h); err != nil {
		return err
	}
	if err := CheckLink(prev, h); err != nil {
		return err
	}
	if err := EnforceCheckpoints(h, cps); err != nil {
		return err
	}
	return nil
}

// CompareCumulativeWork compares two cumulative-work values. Returns
// >0 if candidate has strictly more work than current, 0 on tie, <0
// otherwise. nil is treated as zero work.
func CompareCumulativeWork(current, candidate *big.Int) int {
	cur := current
	if cur == nil {
		cur = new(big.Int)
	}
	cand := candidate
	if cand == nil {
		cand = new(big.Int)
	}
	return cand.Cmp(cur)
}

// CheckReorgWork returns ErrInsufficientWork if candidate does not
// strictly exceed current. Used at the swap-chain decision point.
func CheckReorgWork(currentWork, candidateWork *big.Int) error {
	if CompareCumulativeWork(currentWork, candidateWork) > 0 {
		return nil
	}
	return ErrInsufficientWork
}
