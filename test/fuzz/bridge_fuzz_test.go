package fuzz

import (
	"testing"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/types"
)

// FuzzWithdrawalMerkleTree builds a withdrawal Merkle tree from random
// withdrawal hashes, generates proofs for each leaf, and verifies all
// proofs. This catches any tree construction or proof verification bugs.
func FuzzWithdrawalMerkleTree(f *testing.F) {
	// Seeds: each 32-byte chunk is a withdrawal hash.
	f.Add([]byte{0x01}, uint64(100), uint64(0))
	f.Add([]byte{0x01, 0x02}, uint64(200), uint64(1))
	f.Add(make([]byte, 20), uint64(0), uint64(0))
	f.Add(make([]byte, 20), uint64(1_000_000), uint64(42))
	f.Add([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6,
		0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec},
		uint64(999999999), uint64(100))

	f.Fuzz(func(t *testing.T, bsvAddr []byte, satoshis uint64, nonce uint64) {
		// Limit address length to reasonable size.
		if len(bsvAddr) > 40 {
			bsvAddr = bsvAddr[:40]
		}

		// Generate multiple withdrawal hashes from the fuzzed inputs
		// by varying the nonce.
		count := int(nonce%8) + 1 // 1 to 8 leaves
		hashes := make([]types.Hash, count)
		for i := 0; i < count; i++ {
			hashes[i] = bridge.WithdrawalHash(bsvAddr, satoshis, nonce+uint64(i))
		}

		// Build the tree and get proofs.
		root, proofs := bridge.BuildWithdrawalMerkleTree(hashes)

		// Verify that we got the right number of proofs.
		if len(proofs) != len(hashes) {
			t.Fatalf("expected %d proofs, got %d", len(hashes), len(proofs))
		}

		// Verify each proof.
		for i, hash := range hashes {
			if !bridge.VerifyWithdrawalProof(hash, proofs[i], i, root) {
				t.Fatalf("proof verification failed for leaf %d", i)
			}
		}

		// Cross-check: verify using the single-leaf proof function.
		for i, hash := range hashes {
			singleRoot, singleProof := bridge.WithdrawalProof(hashes, i)
			if singleRoot != root {
				t.Fatalf("root mismatch for leaf %d: tree root %s, single root %s",
					i, root.Hex(), singleRoot.Hex())
			}
			if !bridge.VerifyWithdrawalProof(hash, singleProof, i, root) {
				t.Fatalf("single proof verification failed for leaf %d", i)
			}
		}

		// Negative test: a modified hash should not verify.
		if len(hashes) > 0 {
			modified := hashes[0]
			modified[0] ^= 0xff // flip bits
			if bridge.VerifyWithdrawalProof(modified, proofs[0], 0, root) {
				// This is a valid failure only if the original hash was
				// all-zero and the flip created the same hash by chance,
				// which is astronomically unlikely. Still, we guard
				// against it.
				if modified != hashes[0] {
					t.Fatalf("modified hash should not verify")
				}
			}
		}
	})
}

// FuzzWithdrawalHashDeterminism verifies that WithdrawalHash is
// deterministic: the same inputs always produce the same output.
func FuzzWithdrawalHashDeterminism(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03}, uint64(100), uint64(0))
	f.Add(make([]byte, 20), uint64(0), uint64(0))
	f.Add([]byte{0xff}, uint64(1<<63), uint64(1<<63-1))

	f.Fuzz(func(t *testing.T, addr []byte, amount uint64, nonce uint64) {
		if len(addr) > 40 {
			addr = addr[:40]
		}

		h1 := bridge.WithdrawalHash(addr, amount, nonce)
		h2 := bridge.WithdrawalHash(addr, amount, nonce)

		if h1 != h2 {
			t.Fatalf("withdrawal hash not deterministic: %s != %s", h1.Hex(), h2.Hex())
		}
	})
}
