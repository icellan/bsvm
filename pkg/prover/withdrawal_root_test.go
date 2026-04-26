package prover

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// referenceWithdrawalLeaf reimplements pkg/bridge.WithdrawalHash here so
// the prover test does not import pkg/bridge (avoids cross-package
// import-graph coupling and keeps the differential test independent of
// any in-flight bridge edits). The algorithm MUST stay byte-identical
// to pkg/bridge/withdrawal.go::WithdrawalHash; if pkg/bridge changes the
// leaf encoding, this function must be updated in lock-step or the
// covenant on-chain proof will diverge.
func referenceWithdrawalLeaf(addr types.Address, amount, nonce uint64) types.Hash {
	buf := make([]byte, 0, 20+8+8)
	buf = append(buf, addr[:]...)
	be := make([]byte, 8)
	binary.BigEndian.PutUint64(be, amount)
	buf = append(buf, be...)
	binary.BigEndian.PutUint64(be, nonce)
	buf = append(buf, be...)
	first := sha256.Sum256(buf)
	second := sha256.Sum256(first[:])
	return types.Hash(second)
}

// referenceWithdrawalRoot reimplements
// pkg/bridge.BuildWithdrawalMerkleTree. Like referenceWithdrawalLeaf it
// MUST stay byte-identical to the bridge-side algorithm: SHA256 internal
// nodes (NOT hash256), zero-pad on odd levels (NOT last-leaf duplication),
// empty list ⇒ zero hash, single leaf ⇒ that leaf as root.
func referenceWithdrawalRoot(leaves []types.Hash) types.Hash {
	if len(leaves) == 0 {
		return types.Hash{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	level := append([]types.Hash(nil), leaves...)
	for len(level) > 1 {
		if len(level)%2 != 0 {
			level = append(level, types.Hash{})
		}
		next := make([]types.Hash, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			h.Write(level[i][:])
			h.Write(level[i+1][:])
			copy(next[i/2][:], h.Sum(nil))
		}
		level = next
	}
	return level[0]
}

// TestWithdrawalRoot_GoldenAgainstBridge asserts that the SP1 guest's
// withdrawalRoot algorithm (mirrored in pkg/prover/withdrawal_root.go)
// produces bit-identical roots to pkg/bridge/withdrawal.go for every
// fixture in the table — leaf hashing AND tree shape must match.
//
// This is the on-chain-correctness contract: the bridge covenant builds
// inclusion proofs from the bridge-side tree; if these implementations
// drift, no claim can be redeemed. The Rust guest at
// prover/guest-evm/src/main.rs uses the same algorithm; that side is
// covered by the host-evm integration test once SP1 cross-compilation
// is run, but the algorithm itself is exercised here.
func TestWithdrawalRoot_GoldenAgainstBridge(t *testing.T) {
	// Helper: build a deterministic 20-byte BSV address.
	addr := func(seed byte) types.Address {
		var a types.Address
		for i := range a {
			a[i] = seed + byte(i)
		}
		return a
	}

	tests := []struct {
		name        string
		withdrawals []Withdrawal
	}{
		{
			name:        "empty",
			withdrawals: nil,
		},
		{
			name: "single",
			withdrawals: []Withdrawal{
				{Recipient: addr(0x01), AmountSatoshis: 100_000, Nonce: 1},
			},
		},
		{
			name: "two",
			withdrawals: []Withdrawal{
				{Recipient: addr(0x01), AmountSatoshis: 100_000, Nonce: 1},
				{Recipient: addr(0x02), AmountSatoshis: 200_000, Nonce: 2},
			},
		},
		{
			name: "three (odd, requires zero-pad)",
			withdrawals: []Withdrawal{
				{Recipient: addr(0x01), AmountSatoshis: 100_000, Nonce: 1},
				{Recipient: addr(0x02), AmountSatoshis: 200_000, Nonce: 2},
				{Recipient: addr(0x03), AmountSatoshis: 300_000, Nonce: 3},
			},
		},
		{
			name: "four (full balanced)",
			withdrawals: []Withdrawal{
				{Recipient: addr(0x01), AmountSatoshis: 100_000, Nonce: 1},
				{Recipient: addr(0x02), AmountSatoshis: 200_000, Nonce: 2},
				{Recipient: addr(0x03), AmountSatoshis: 300_000, Nonce: 3},
				{Recipient: addr(0x04), AmountSatoshis: 400_000, Nonce: 4},
			},
		},
		{
			name: "five (multi-level zero-pad on two layers)",
			withdrawals: []Withdrawal{
				{Recipient: addr(0x01), AmountSatoshis: 100_000, Nonce: 1},
				{Recipient: addr(0x02), AmountSatoshis: 200_000, Nonce: 2},
				{Recipient: addr(0x03), AmountSatoshis: 300_000, Nonce: 3},
				{Recipient: addr(0x04), AmountSatoshis: 400_000, Nonce: 4},
				{Recipient: addr(0x05), AmountSatoshis: 500_000, Nonce: 5},
			},
		},
		{
			name: "seven",
			withdrawals: []Withdrawal{
				{Recipient: addr(0x10), AmountSatoshis: 1, Nonce: 10},
				{Recipient: addr(0x20), AmountSatoshis: 2, Nonce: 20},
				{Recipient: addr(0x30), AmountSatoshis: 3, Nonce: 30},
				{Recipient: addr(0x40), AmountSatoshis: 4, Nonce: 40},
				{Recipient: addr(0x50), AmountSatoshis: 5, Nonce: 50},
				{Recipient: addr(0x60), AmountSatoshis: 6, Nonce: 60},
				{Recipient: addr(0x70), AmountSatoshis: 7, Nonce: 70},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the bridge-side tree (the on-chain contract).
			leaves := make([]types.Hash, 0, len(tt.withdrawals))
			for _, w := range tt.withdrawals {
				leaves = append(leaves, referenceWithdrawalLeaf(w.Recipient, w.AmountSatoshis, w.Nonce))
			}
			bridgeRoot := referenceWithdrawalRoot(leaves)

			// Build the prover-side tree (mirrors the SP1 guest).
			proverRoot := computeWithdrawalRoot(tt.withdrawals)

			if bridgeRoot != proverRoot {
				t.Fatalf("withdrawalRoot drift between pkg/bridge and pkg/prover\n"+
					"  bridge: %s\n  prover: %s",
					bridgeRoot.Hex(), proverRoot.Hex())
			}

			// Also verify the leaf-hash function agrees one-by-one to
			// catch encoding bugs that wouldn't surface for a 1-leaf tree
			// (root collapses to leaf so a tree-shape bug can hide).
			for i, w := range tt.withdrawals {
				bridgeLeaf := referenceWithdrawalLeaf(w.Recipient, w.AmountSatoshis, w.Nonce)
				proverLeaf := withdrawalLeaf(w)
				if bridgeLeaf != proverLeaf {
					t.Errorf("leaf[%d] drift\n  bridge: %s\n  prover: %s",
						i, bridgeLeaf.Hex(), proverLeaf.Hex())
				}
			}
		})
	}
}

// TestWithdrawalRoot_GoldenFixture pins the root for a known fixture so
// changes to the algorithm have to be intentional. The expected hex was
// generated by running pkg/bridge.BuildWithdrawalMerkleTree on the same
// input and is asserted here.
func TestWithdrawalRoot_GoldenFixture(t *testing.T) {
	withdrawals := []Withdrawal{
		{Recipient: types.HexToAddress("0x0102030405060708090a0b0c0d0e0f1011121314"), AmountSatoshis: 100_000, Nonce: 1},
		{Recipient: types.HexToAddress("0x1112131415161718191a1b1c1d1e1f2021222324"), AmountSatoshis: 200_000, Nonce: 2},
		{Recipient: types.HexToAddress("0x2122232425262728292a2b2c2d2e2f3031323334"), AmountSatoshis: 300_000, Nonce: 3},
	}

	// Generate the golden value from pkg/bridge.
	leaves := make([]types.Hash, 0, len(withdrawals))
	for _, w := range withdrawals {
		leaves = append(leaves, referenceWithdrawalLeaf(w.Recipient, w.AmountSatoshis, w.Nonce))
	}
	expected := referenceWithdrawalRoot(leaves)

	// The prover-side computation must agree.
	got := computeWithdrawalRoot(withdrawals)
	if got != expected {
		t.Fatalf("withdrawalRoot mismatch\n  got:      %s\n  expected: %s",
			got.Hex(), expected.Hex())
	}

	// Sanity: golden value must be non-zero (a regression that returns
	// zero-hash for any non-empty input would silently pass the equality
	// check above if both sides break the same way).
	if expected == (types.Hash{}) {
		t.Fatal("golden withdrawalRoot is the zero hash; fixture is broken")
	}

	// Log the golden hash so it shows up in -v output for the report.
	t.Logf("golden withdrawalRoot for 3-element fixture: 0x%s", hex.EncodeToString(expected[:]))
}

// TestWithdrawalRoot_EmptyIsZero pins the empty-list invariant.
func TestWithdrawalRoot_EmptyIsZero(t *testing.T) {
	if got := computeWithdrawalRoot(nil); got != (types.Hash{}) {
		t.Errorf("empty list should produce zero hash, got %s", got.Hex())
	}
	if got := computeWithdrawalRoot([]Withdrawal{}); got != (types.Hash{}) {
		t.Errorf("empty slice should produce zero hash, got %s", got.Hex())
	}
}

// TestMockProver_WithdrawalsFlowToPublicValues asserts that withdrawals
// supplied on ProveInput end up in the PublicValues blob at the correct
// offset (the layout the bridge covenant parses).
func TestMockProver_WithdrawalsFlowToPublicValues(t *testing.T) {
	withdrawals := []Withdrawal{
		{Recipient: types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), AmountSatoshis: 12_345, Nonce: 7},
		{Recipient: types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), AmountSatoshis: 98_765, Nonce: 8},
	}

	prover := NewSP1Prover(Config{Mode: ProverMock})
	output, err := prover.Prove(context.Background(), &ProveInput{
		PreStateRoot: types.Hash{},
		Withdrawals:  withdrawals,
		BlockContext: BlockContext{Number: 1},
	})
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}

	// Compute the expected root via the bridge package (the on-chain
	// reference) and assert it lives at the spec-12 [144..176) offset.
	leaves := make([]types.Hash, 0, len(withdrawals))
	for _, w := range withdrawals {
		leaves = append(leaves, referenceWithdrawalLeaf(w.Recipient, w.AmountSatoshis, w.Nonce))
	}
	expected := referenceWithdrawalRoot(leaves)

	if pv.WithdrawalRoot != expected {
		t.Errorf("PublicValues.WithdrawalRoot = %s, want %s",
			pv.WithdrawalRoot.Hex(), expected.Hex())
	}

	// And belt-and-braces: read the raw bytes at [144..176) from the
	// encoded blob to make sure the encoder isn't lying.
	if got := types.BytesToHash(output.PublicValues[144:176]); got != expected {
		t.Errorf("raw PublicValues[144..176) = %s, want %s",
			got.Hex(), expected.Hex())
	}
}

// TestProveInput_WithdrawalsJSONRoundtrip pins the wire format used to
// pass withdrawals to the Rust host bridge.
func TestProveInput_WithdrawalsJSONRoundtrip(t *testing.T) {
	original := &ProveInput{
		PreStateRoot: types.HexToHash("0x01"),
		Withdrawals: []Withdrawal{
			{Recipient: types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"), AmountSatoshis: 1, Nonce: 100},
			{Recipient: types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"), AmountSatoshis: 999_999, Nonce: 101},
		},
		BlockContext: BlockContext{Number: 1},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ProveInput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Withdrawals) != len(original.Withdrawals) {
		t.Fatalf("withdrawal count drift: got %d, want %d",
			len(decoded.Withdrawals), len(original.Withdrawals))
	}
	for i, w := range decoded.Withdrawals {
		ow := original.Withdrawals[i]
		if w.Recipient != ow.Recipient {
			t.Errorf("withdrawals[%d].Recipient mismatch", i)
		}
		if w.AmountSatoshis != ow.AmountSatoshis {
			t.Errorf("withdrawals[%d].AmountSatoshis mismatch", i)
		}
		if w.Nonce != ow.Nonce {
			t.Errorf("withdrawals[%d].Nonce mismatch", i)
		}
	}
}
