package chaintracks

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
)

// mineHeader brute-forces a Nonce so the resulting double-SHA256 meets
// `bits`. Used by tests to build PoW-valid headers without needing a
// real BSV header. `bits` must encode an easy target (e.g. 0x207fffff
// for regtest, which is the largest legal target so almost any nonce
// hits on the first try).
func mineHeader(t *testing.T, prev *BlockHeader, bits uint32, height uint64) *BlockHeader {
	t.Helper()
	target, err := CompactToTarget(bits)
	if err != nil {
		t.Fatalf("CompactToTarget(%#x): %v", bits, err)
	}
	h := &BlockHeader{
		Height:     height,
		Version:    1,
		MerkleRoot: mkHash(byte(height)),
		Timestamp:  uint32(1700000000 + height),
		Bits:       bits,
	}
	if prev != nil {
		h.PrevHash = prev.Hash
	}
	for nonce := uint32(0); ; nonce++ {
		h.Nonce = nonce
		got := HeaderHash(h)
		if hashToBig(got).Cmp(target) <= 0 {
			h.Hash = got
			break
		}
		if nonce > 5_000_000 {
			t.Fatalf("could not mine header within 5M nonces")
		}
	}
	return h
}

func TestCompactToTargetKnownValues(t *testing.T) {
	cases := []struct {
		bits uint32
		want string // hex, big-endian
	}{
		// Bitcoin/BSV genesis difficulty.
		{0x1d00ffff, "00000000ffff0000000000000000000000000000000000000000000000000000"},
		// Easiest regtest difficulty.
		{0x207fffff, "7fffff0000000000000000000000000000000000000000000000000000000000"},
	}
	for _, tc := range cases {
		got, err := CompactToTarget(tc.bits)
		if err != nil {
			t.Fatalf("CompactToTarget(%#x): %v", tc.bits, err)
		}
		want, _ := new(big.Int).SetString(tc.want, 16)
		if got.Cmp(want) != 0 {
			t.Errorf("CompactToTarget(%#x) = %x want %x", tc.bits, got, want)
		}
	}
}

func TestCompactToTargetRejectsNegative(t *testing.T) {
	if _, err := CompactToTarget(0x1d80ffff); !errors.Is(err, ErrBadBits) {
		t.Fatalf("expected ErrBadBits, got %v", err)
	}
}

func TestSerializeHeaderRoundTrip(t *testing.T) {
	// Build a header, serialise, hash, and check the result equals
	// the canonical double-SHA256 of the serialised bytes.
	h := &BlockHeader{
		Version:    2,
		PrevHash:   mkHash(0xab),
		MerkleRoot: mkHash(0xcd),
		Timestamp:  1700000000,
		Bits:       0x207fffff,
		Nonce:      42,
	}
	raw := SerializeHeader(h)
	if len(raw) != 80 {
		t.Fatalf("len = %d want 80", len(raw))
	}
	first := sha256.Sum256(raw)
	want := sha256.Sum256(first[:])
	if got := HeaderHash(h); got != want {
		t.Errorf("HeaderHash mismatch")
	}
	// Spot-check field placement.
	if v := binary.LittleEndian.Uint32(raw[0:4]); v != 2 {
		t.Errorf("version field placement: got %d", v)
	}
	if ts := binary.LittleEndian.Uint32(raw[68:72]); ts != 1700000000 {
		t.Errorf("timestamp placement: got %d", ts)
	}
}

func TestCheckProofOfWorkAcceptsMined(t *testing.T) {
	h := mineHeader(t, nil, 0x207fffff, 0)
	if err := CheckProofOfWork(h); err != nil {
		t.Fatalf("CheckProofOfWork: %v", err)
	}
}

func TestCheckProofOfWorkRejectsBadHash(t *testing.T) {
	h := mineHeader(t, nil, 0x207fffff, 0)
	// Tamper with the merkle root — recomputed hash won't match the
	// declared one, AND will (almost certainly) not meet the target.
	h.MerkleRoot = mkHash(0xff)
	err := CheckProofOfWork(h)
	if err == nil {
		t.Fatalf("expected error after tampering")
	}
	if !errors.Is(err, ErrHashMismatch) && !errors.Is(err, ErrBadPoW) {
		t.Fatalf("expected ErrHashMismatch or ErrBadPoW, got %v", err)
	}
}

func TestCheckProofOfWorkRejectsAboveTarget(t *testing.T) {
	// Build a header whose hash exceeds a tight target. Use bits
	// 0x1d00ffff (mainnet genesis-era) — a random nonce won't meet it.
	h := &BlockHeader{
		Version:    1,
		MerkleRoot: mkHash(0x01),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      1,
	}
	h.Hash = HeaderHash(h)
	if err := CheckProofOfWork(h); !errors.Is(err, ErrBadPoW) {
		t.Fatalf("expected ErrBadPoW, got %v", err)
	}
}

func TestCheckLink(t *testing.T) {
	a := mineHeader(t, nil, 0x207fffff, 100)
	b := mineHeader(t, a, 0x207fffff, 101)
	if err := CheckLink(a, b); err != nil {
		t.Fatalf("CheckLink: %v", err)
	}
	// Wrong prev hash.
	bad := mineHeader(t, nil, 0x207fffff, 101)
	if err := CheckLink(a, bad); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("expected ErrBrokenChain, got %v", err)
	}
	// Wrong height.
	skip := mineHeader(t, a, 0x207fffff, 110)
	if err := CheckLink(a, skip); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("expected ErrBrokenChain on height jump, got %v", err)
	}
}

func TestWorkForBitsMonotonic(t *testing.T) {
	easyWork, err := WorkForBits(0x207fffff)
	if err != nil {
		t.Fatalf("WorkForBits easy: %v", err)
	}
	hardWork, err := WorkForBits(0x1d00ffff)
	if err != nil {
		t.Fatalf("WorkForBits hard: %v", err)
	}
	if hardWork.Cmp(easyWork) <= 0 {
		t.Fatalf("hard work %v should exceed easy work %v", hardWork, easyWork)
	}
}

func TestCheckReorgWork(t *testing.T) {
	cur := big.NewInt(100)
	if err := CheckReorgWork(cur, big.NewInt(101)); err != nil {
		t.Fatalf("strict greater should pass: %v", err)
	}
	if err := CheckReorgWork(cur, big.NewInt(100)); !errors.Is(err, ErrInsufficientWork) {
		t.Fatalf("equal should fail with ErrInsufficientWork, got %v", err)
	}
	if err := CheckReorgWork(cur, big.NewInt(99)); !errors.Is(err, ErrInsufficientWork) {
		t.Fatalf("less should fail with ErrInsufficientWork, got %v", err)
	}
	// Nil current is treated as zero work.
	if err := CheckReorgWork(nil, big.NewInt(1)); err != nil {
		t.Fatalf("nil current vs positive: %v", err)
	}
}

func TestValidateHeaderAppliesCheckpoints(t *testing.T) {
	cps := []Checkpoint{{Height: 100, Hash: mkHash(0xaa)}}
	// Header at the checkpoint height with the wrong hash should fail.
	h := mineHeader(t, nil, 0x207fffff, 100)
	if err := ValidateHeader(nil, h, cps); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("expected ErrCheckpointMismatch, got %v", err)
	}
	// Header below the latest checkpoint should fail.
	low := mineHeader(t, nil, 0x207fffff, 50)
	if err := ValidateHeader(nil, low, cps); !errors.Is(err, ErrBelowCheckpoint) {
		t.Fatalf("expected ErrBelowCheckpoint, got %v", err)
	}
	// Header above checkpoint passes (no PrevHash/Link issue).
	above := mineHeader(t, nil, 0x207fffff, 200)
	if err := ValidateHeader(nil, above, cps); err != nil {
		t.Fatalf("above-checkpoint header rejected: %v", err)
	}
}
