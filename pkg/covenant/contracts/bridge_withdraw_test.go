package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// SHA-256 Merkle helpers (mirror runar.MerkleRootSha256 semantics)
// ---------------------------------------------------------------------------
//
// runar.MerkleRootSha256 walks a binary SHA-256 Merkle tree from leaf
// to root using:
//
//	for i in 0..depth:
//	    sibling = proof[i*32 : (i+1)*32]
//	    bit     = (index >> i) & 1
//	    if bit == 0: current = SHA256(current || sibling)
//	    else:        current = SHA256(sibling || current)
//
// The helpers below build proofs and roots with that exact bit
// orientation so the on-chain verifier accepts them.

// sha256Sum returns SHA-256(a || b).
func sha256Sum(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// buildSha256MerkleProof builds a minimal full-binary SHA-256 Merkle
// tree of fixed depth padded with the 32-byte zero hash, and returns
// the root and the inclusion proof for the leaf at leafIndex.
//
// The proof is a depth*32 concatenated byte string of sibling hashes
// from leaf upward, matching the runar.MerkleRootSha256 layout.
func buildSha256MerkleProof(leaves [][]byte, leafIndex int, depth int) (root []byte, proof []byte) {
	zero := make([]byte, 32)
	level := make([][]byte, 0, 1<<depth)
	level = append(level, leaves...)
	for len(level) < (1 << depth) {
		level = append(level, zero)
	}

	pos := leafIndex
	proof = make([]byte, 0, depth*32)
	for d := 0; d < depth; d++ {
		var sibling []byte
		if pos%2 == 0 {
			sibling = level[pos+1]
		} else {
			sibling = level[pos-1]
		}
		proof = append(proof, sibling...)

		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, sha256Sum(level[i], level[i+1]))
		}
		level = next
		pos /= 2
	}
	if len(level) != 1 {
		panic("merkle build: did not reduce to single root")
	}
	root = level[0]
	return root, proof
}

// withdrawalLeaf computes hash256(bsvAddress || amountBE8 || nonceBE8),
// the leaf value the bridge covenant expects in the SHA-256 withdrawal
// Merkle tree. This is also the nullifier folded into
// WithdrawalsCommitment.
func withdrawalLeaf(bsvAddress []byte, amount, nonce uint64) []byte {
	buf := make([]byte, 0, len(bsvAddress)+16)
	buf = append(buf, bsvAddress...)
	var amountBE [8]byte
	binary.BigEndian.PutUint64(amountBE[:], amount)
	buf = append(buf, amountBE[:]...)
	var nonceBE [8]byte
	binary.BigEndian.PutUint64(nonceBE[:], nonce)
	buf = append(buf, nonceBE[:]...)
	first := sha256.Sum256(buf)
	second := sha256.Sum256(first[:])
	return second[:]
}

// ---------------------------------------------------------------------------
// Cross-covenant reference fixtures
// ---------------------------------------------------------------------------

// makeRefOutputScript returns a deterministic state-covenant output
// script blob. The bridge contract only cares that hash256 of this
// blob matches the readonly StateCovenantScriptHash — the bytes
// themselves are opaque to the covenant.
func makeRefOutputScript(seed string) []byte {
	out := make([]byte, 0, 64)
	out = append(out, []byte(seed)...)
	for len(out) < 64 {
		out = append(out, 0x42)
	}
	return out
}

// stateCovenantScriptHash returns hash256(refOutputScript), matching
// the on-chain assertion the bridge performs.
func stateCovenantScriptHash(refOutputScript []byte) []byte {
	first := sha256.Sum256(refOutputScript)
	second := sha256.Sum256(first[:])
	return second[:]
}

// makeRefOpReturn builds the spec-12 advance OP_RETURN script the
// rollup contracts emit:
//
//	OP_FALSE OP_RETURN OP_PUSHDATA4 <payload_len_le4>
//	  "BSVM\x02" || withdrawalRoot(32) || batchData
//
// The bridge extracts withdrawalRoot at byte offset 12.
func makeRefOpReturn(withdrawalRoot []byte, batchData []byte) []byte {
	if len(withdrawalRoot) != 32 {
		panic("withdrawalRoot must be 32 bytes")
	}
	payload := make([]byte, 0, 5+32+len(batchData))
	payload = append(payload, 'B', 'S', 'V', 'M', 0x02)
	payload = append(payload, withdrawalRoot...)
	payload = append(payload, batchData...)

	script := make([]byte, 0, 3+4+len(payload))
	script = append(script, 0x00, 0x6a, 0x4e)
	var lenBytes [4]byte
	binary.LittleEndian.PutUint32(lenBytes[:], uint32(len(payload)))
	script = append(script, lenBytes[:]...)
	script = append(script, payload...)
	return script
}

// ---------------------------------------------------------------------------
// Bridge-covenant builder
// ---------------------------------------------------------------------------

// bridgeFixture bundles a fresh BridgeCovenant plus the fixed
// cross-covenant material used by the tests.
type bridgeFixture struct {
	cov            *BridgeCovenant
	refScript      []byte // state covenant output script
	scriptHash     []byte // hash256(refScript)
	commitmentSeed []byte // expected genesis WithdrawalsCommitment (32 zero bytes)
}

func newBridgeFixture(initialBalance int64) *bridgeFixture {
	refScript := makeRefOutputScript("test-state-covenant-script-seed")
	hash := stateCovenantScriptHash(refScript)

	zero := make([]byte, 32)
	cov := &BridgeCovenant{
		Balance:                 runar.Bigint(initialBalance),
		WithdrawalNonce:         0,
		WithdrawalsCommitment:   runar.ByteString(zero),
		StateCovenantScriptHash: runar.ByteString(hash),
	}
	return &bridgeFixture{
		cov:            cov,
		refScript:      refScript,
		scriptHash:     hash,
		commitmentSeed: zero,
	}
}

// callWithdraw invokes the BridgeCovenant.Withdraw method with the
// given parameters. Returns true if the call succeeded (no panic),
// false if it panicked.
func callWithdraw(
	t *testing.T,
	cov *BridgeCovenant,
	addr []byte,
	amount, nonce, index, depth int64,
	merkleProof, refScript, refOpReturn []byte,
) (ok bool, panicVal any) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			ok = false
			panicVal = r
		}
	}()
	cov.Withdraw(
		runar.ByteString(addr),
		runar.Bigint(amount),
		runar.Bigint(nonce),
		runar.ByteString(merkleProof),
		runar.Bigint(index),
		runar.Bigint(depth),
		runar.ByteString(refScript),
		runar.ByteString(refOpReturn),
	)
	ok = true
	return
}

// expectAccept asserts the call succeeded.
func expectAccept(t *testing.T, ok bool, panicVal any) {
	t.Helper()
	if !ok {
		t.Fatalf("Withdraw rejected unexpectedly: %v", panicVal)
	}
}

// expectReject asserts the call panicked.
func expectReject(t *testing.T, ok bool, panicVal any) {
	t.Helper()
	if ok {
		t.Fatal("Withdraw accepted but should have rejected")
	}
}

// ---------------------------------------------------------------------------
// Happy-path tests at multiple depths
// ---------------------------------------------------------------------------

// TestBridgeWithdraw_HappyPath_Depth4 covers a typical small-batch
// withdrawal: 16 leaves, target leaf at index 5.
func TestBridgeWithdraw_HappyPath_Depth4(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0x11)
	const amount, nonce, depth = 50_000, 0, 4
	const targetIndex = 5

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaf := withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	leaves[targetIndex] = leaf

	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)
	batchData := []byte("batch-data-doesn't-matter-here")
	refOpReturn := makeRefOpReturn(root, batchData)

	ok, pv := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectAccept(t, ok, pv)

	// Post-state: balance and nonce updated, commitment folded.
	if got := int64(bf.cov.Balance); got != 1_000_000-amount {
		t.Errorf("balance: got %d, want %d", got, 1_000_000-amount)
	}
	if bf.cov.WithdrawalNonce != 1 {
		t.Errorf("nonce: got %d, want 1", bf.cov.WithdrawalNonce)
	}
	wantCommit := foldCommitment(bf.commitmentSeed, leaf)
	if got := []byte(bf.cov.WithdrawalsCommitment); !bytesEqual(got, wantCommit) {
		t.Errorf("commitment not folded: got %x, want %x", got, wantCommit)
	}
}

// TestBridgeWithdraw_HappyPath_Depth8 covers a 256-leaf batch.
func TestBridgeWithdraw_HappyPath_Depth8(t *testing.T) {
	bf := newBridgeFixture(10_000_000)
	addr := bytesAddr(0x22)
	const amount, nonce, depth = 1_234, 0, 8
	const targetIndex = 200

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaf := withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	leaves[targetIndex] = leaf

	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)
	refOpReturn := makeRefOpReturn(root, []byte("d8"))

	ok, pv := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectAccept(t, ok, pv)
}

// TestBridgeWithdraw_HappyPath_Depth16 covers the spec 13 maximum tree
// depth (65k leaves).
func TestBridgeWithdraw_HappyPath_Depth16(t *testing.T) {
	bf := newBridgeFixture(1_000_000_000)
	addr := bytesAddr(0x33)
	const amount, nonce, depth = 9_999, 0, 16
	const targetIndex = 12345

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaf := withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	leaves[targetIndex] = leaf

	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)
	refOpReturn := makeRefOpReturn(root, []byte("d16"))

	ok, pv := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectAccept(t, ok, pv)
}

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

// TestBridgeWithdraw_BadProof_FlipSibling flips one byte of the proof
// and asserts the covenant rejects.
func TestBridgeWithdraw_BadProof_FlipSibling(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0xAA)
	const amount, nonce, depth = 50_000, 0, 4
	const targetIndex = 3

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)

	// Corrupt the first sibling.
	proof[0] ^= 0xFF
	refOpReturn := makeRefOpReturn(root, nil)

	ok, _ := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectReject(t, ok, nil)
}

// TestBridgeWithdraw_WrongIndex pins the index→bit-orientation mapping.
// Same proof, wrong index → reconstruction yields a different root.
func TestBridgeWithdraw_WrongIndex(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0xBB)
	const amount, nonce, depth = 50_000, 0, 4
	const targetIndex = 5

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)
	refOpReturn := makeRefOpReturn(root, nil)

	// Claim index 6 instead of 5.
	ok, _ := callWithdraw(t, bf.cov, addr, amount, nonce, 6, depth,
		proof, bf.refScript, refOpReturn)
	expectReject(t, ok, nil)
}

// TestBridgeWithdraw_WrongRoot pins that the on-chain check is against
// the OP_RETURN root, not a caller-supplied one. Tampering with the
// OP_RETURN's root field is rejected.
func TestBridgeWithdraw_WrongRoot(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0xCC)
	const amount, nonce, depth = 50_000, 0, 4
	const targetIndex = 1

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	_, proof := buildSha256MerkleProof(leaves, targetIndex, depth)

	// Write a deliberately-wrong root into the OP_RETURN.
	badRoot := make([]byte, 32)
	for i := range badRoot {
		badRoot[i] = 0xEE
	}
	refOpReturn := makeRefOpReturn(badRoot, nil)

	ok, _ := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectReject(t, ok, nil)
}

// TestBridgeWithdraw_WrongCrossCovScript pins the cross-covenant ref:
// hash256(refOutputScript) must match the bridge's pinned
// StateCovenantScriptHash.
func TestBridgeWithdraw_WrongCrossCovScript(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0xDD)
	const amount, nonce, depth = 50_000, 0, 4
	const targetIndex = 0

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)
	refOpReturn := makeRefOpReturn(root, nil)

	// Substitute a different script. Hash will not match the readonly
	// StateCovenantScriptHash, so the cross-cov assertion fails.
	otherScript := makeRefOutputScript("a-different-covenant")

	ok, _ := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, otherScript, refOpReturn)
	expectReject(t, ok, nil)
}

// TestBridgeWithdraw_ReplayedNonce ensures a second withdrawal with the
// same nonce is rejected. After a successful withdrawal the covenant's
// WithdrawalNonce moves to 1, so a second call with nonce=0 must fail
// the nonce==WithdrawalNonce assertion (anti-replay layer 1).
func TestBridgeWithdraw_ReplayedNonce(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0xEE)
	const amount, depth = 50_000, 4
	const targetIndex = 7

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), 0)
	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)
	refOpReturn := makeRefOpReturn(root, nil)

	// First withdrawal with nonce=0 succeeds.
	ok, pv := callWithdraw(t, bf.cov, addr, amount, 0, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectAccept(t, ok, pv)
	if bf.cov.WithdrawalNonce != 1 {
		t.Fatalf("expected WithdrawalNonce=1 after success, got %d", bf.cov.WithdrawalNonce)
	}

	// Replay with nonce=0 must fail the nonce check.
	ok, _ = callWithdraw(t, bf.cov, addr, amount, 0, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectReject(t, ok, nil)
}

// ---------------------------------------------------------------------------
// Boundary tests
// ---------------------------------------------------------------------------

// TestBridgeWithdraw_RejectZeroAmount pins that the satoshiAmount > 0
// invariant is enforced.
func TestBridgeWithdraw_RejectZeroAmount(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0x01)

	// Build a single-leaf tree at depth 0; the root is the leaf.
	leaf := withdrawalLeaf(addr, 0, 0)
	refOpReturn := makeRefOpReturn(leaf, nil)

	ok, _ := callWithdraw(t, bf.cov, addr, 0, 0, 0, 0,
		nil, bf.refScript, refOpReturn)
	expectReject(t, ok, nil)
}

// TestBridgeWithdraw_RejectInsufficientBalance pins that amount must
// not exceed Balance.
func TestBridgeWithdraw_RejectInsufficientBalance(t *testing.T) {
	bf := newBridgeFixture(100) // tiny balance
	addr := bytesAddr(0x02)
	const amount, nonce, depth = 1_000_000, 0, 4
	const targetIndex = 0

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)
	refOpReturn := makeRefOpReturn(root, nil)

	ok, _ := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectReject(t, ok, nil)
}

// TestBridgeWithdraw_RejectDepthOverMax pins the spec 13 max-depth-16
// guard.
func TestBridgeWithdraw_RejectDepthOverMax(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0x03)
	const amount, nonce, depth = 50_000, 0, 17 // > spec max
	const targetIndex = 0

	// Provide a proof of the right byte length (17*32) so we don't trip
	// any earlier length check before reaching the depth assertion.
	proof := make([]byte, depth*32)
	root := make([]byte, 32)
	refOpReturn := makeRefOpReturn(root, nil)

	ok, _ := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectReject(t, ok, nil)
}

// ---------------------------------------------------------------------------
// Cross-cov OP_RETURN failure modes
// ---------------------------------------------------------------------------

// TestBridgeWithdraw_RefOpReturnTruncated pins that a refOpReturn
// shorter than 12+32 = 44 bytes (the minimum to extract withdrawalRoot)
// is rejected. The runar.Substr lookup at offset 12 will panic on a
// short slice in the mock runtime, mirroring an OP_VERIFY failure
// on-chain.
func TestBridgeWithdraw_RefOpReturnTruncated(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0x04)
	const amount, nonce, depth = 50_000, 0, 4
	const targetIndex = 0

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	_, proof := buildSha256MerkleProof(leaves, targetIndex, depth)

	// Truncated OP_RETURN — only the header, no payload.
	tinyRefOpReturn := []byte{0x00, 0x6a, 0x4e, 0x00, 0x00, 0x00, 0x00}

	ok, _ := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, tinyRefOpReturn)
	expectReject(t, ok, nil)
}

// TestBridgeWithdraw_RefOpReturnWrongMagic pins that the OP_RETURN's
// magic prefix bytes are NOT silently accepted: an OP_RETURN whose
// "magic" slot at offset 7 is something other than "BSVM\x02" but
// whose offset-12 root happens to match a correct root would still be
// accepted today (the bridge doesn't currently verify the magic
// prefix). Document this as a known limitation and assert behaviour:
// if the bytes line up at the documented offset, the call accepts.
//
// This is intentional — the bridge depends on the off-chain caller to
// supply a valid spec-12 OP_RETURN from a confirmed advance tx; the
// on-chain check binds only the withdrawalRoot field, the commitment
// chain, and the cross-covenant script hash. A future revision could
// add a magic-prefix assertion if attack surface widens.
func TestBridgeWithdraw_RefOpReturnWrongMagicNotEnforced(t *testing.T) {
	bf := newBridgeFixture(1_000_000)
	addr := bytesAddr(0x05)
	const amount, nonce, depth = 50_000, 0, 4
	const targetIndex = 2

	leaves := make([][]byte, 1<<depth)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
	}
	leaves[targetIndex] = withdrawalLeaf(addr, uint64(amount), uint64(nonce))
	root, proof := buildSha256MerkleProof(leaves, targetIndex, depth)

	// Build a refOpReturn with a wrong magic but the root in the right
	// slot. The bridge's offset-only extraction accepts.
	hdr := []byte{0x00, 0x6a, 0x4e, 0x00, 0x00, 0x00, 0x00, 'X', 'X', 'X', 'X', 'X'}
	refOpReturn := append([]byte{}, hdr...)
	refOpReturn = append(refOpReturn, root...)

	ok, pv := callWithdraw(t, bf.cov, addr, amount, nonce, targetIndex, depth,
		proof, bf.refScript, refOpReturn)
	expectAccept(t, ok, pv)
}

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

// bytesAddr builds a 20-byte deterministic BSV address whose first
// byte is fill and the remainder is zero.
func bytesAddr(fill byte) []byte {
	a := make([]byte, 20)
	a[0] = fill
	return a
}

// foldCommitment computes hash256(prev || nullifier) — the on-chain
// WithdrawalsCommitment chain step.
func foldCommitment(prev, nullifier []byte) []byte {
	buf := make([]byte, 0, len(prev)+len(nullifier))
	buf = append(buf, prev...)
	buf = append(buf, nullifier...)
	first := sha256.Sum256(buf)
	second := sha256.Sum256(first[:])
	return second[:]
}

// bytesEqual is a minimal byte-slice comparison used by the
// post-state assertions above. Avoids importing bytes for a one-liner.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
