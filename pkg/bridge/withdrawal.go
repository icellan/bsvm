package bridge

import (
	"crypto/sha256"

	"github.com/icellan/bsvm/pkg/types"
)

// WithdrawalHash computes hash256(bsvAddress || amount_uint64_be || nonce_uint64_be).
// hash256 is double-SHA256, matching BSV's OP_HASH256.
// This is the leaf value in the withdrawal Merkle tree.
//
// The bsvAddress is a 20-byte BSV address (RIPEMD160(SHA256(pubkey))).
// The satoshiAmount and nonce are encoded as 8-byte big-endian uint64.
func WithdrawalHash(bsvAddress []byte, satoshiAmount uint64, nonce uint64) types.Hash {
	data := make([]byte, 0, len(bsvAddress)+16)
	data = append(data, bsvAddress...)
	data = append(data, types.Uint64ToBE(satoshiAmount)...)
	data = append(data, types.Uint64ToBE(nonce)...)
	return hash256(data)
}

// hash256 computes SHA256(SHA256(data)), matching BSV's OP_HASH256.
func hash256(data []byte) types.Hash {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return types.Hash(second)
}

// BuildWithdrawalMerkleTree builds a binary SHA256 Merkle tree from
// withdrawal hashes and returns the root and all proofs.
//
// If hashes is empty, returns the zero hash and nil proofs.
// If hashes has one element, the root is that element's hash.
// The tree is built bottom-up, padding with the zero hash when the
// level has an odd number of nodes.
func BuildWithdrawalMerkleTree(hashes []types.Hash) (root types.Hash, proofs [][]types.Hash) {
	if len(hashes) == 0 {
		return types.Hash{}, nil
	}

	proofs = make([][]types.Hash, len(hashes))
	for i := range proofs {
		proofs[i] = []types.Hash{}
	}

	if len(hashes) == 1 {
		return hashes[0], proofs
	}

	// Track which original leaf index maps to which position at each level.
	// indices[i] gives the position in the current level for original leaf i.
	n := len(hashes)
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	level := make([]types.Hash, n)
	copy(level, hashes)

	for len(level) > 1 {
		// Pad odd levels with zero hash.
		if len(level)%2 != 0 {
			level = append(level, types.Hash{})
		}

		nextLevel := make([]types.Hash, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			nextLevel[i/2] = sha256Pair(level[i], level[i+1])
		}

		// For each original leaf, record the sibling at this level.
		for leafIdx := 0; leafIdx < n; leafIdx++ {
			pos := indices[leafIdx]
			if pos%2 == 0 {
				// Sibling is to the right.
				proofs[leafIdx] = append(proofs[leafIdx], level[pos+1])
			} else {
				// Sibling is to the left.
				proofs[leafIdx] = append(proofs[leafIdx], level[pos-1])
			}
			indices[leafIdx] = pos / 2
		}

		level = nextLevel
	}

	return level[0], proofs
}

// WithdrawalProof generates a Merkle inclusion proof for the withdrawal at
// the given index. Returns the root and the proof (list of sibling hashes
// from leaf to root).
func WithdrawalProof(hashes []types.Hash, index int) (root types.Hash, proof []types.Hash) {
	if len(hashes) == 0 || index < 0 || index >= len(hashes) {
		return types.Hash{}, nil
	}

	if len(hashes) == 1 {
		return hashes[0], []types.Hash{}
	}

	proof = []types.Hash{}
	pos := index
	level := make([]types.Hash, len(hashes))
	copy(level, hashes)

	for len(level) > 1 {
		if len(level)%2 != 0 {
			level = append(level, types.Hash{})
		}

		nextLevel := make([]types.Hash, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			nextLevel[i/2] = sha256Pair(level[i], level[i+1])
		}

		if pos%2 == 0 {
			proof = append(proof, level[pos+1])
		} else {
			proof = append(proof, level[pos-1])
		}
		pos /= 2

		level = nextLevel
	}

	return level[0], proof
}

// VerifyWithdrawalProof verifies a SHA256 Merkle inclusion proof for a
// withdrawal hash against the given root.
func VerifyWithdrawalProof(leaf types.Hash, proof []types.Hash, index int, root types.Hash) bool {
	current := leaf
	pos := index

	for _, sibling := range proof {
		if pos%2 == 0 {
			current = sha256Pair(current, sibling)
		} else {
			current = sha256Pair(sibling, current)
		}
		pos /= 2
	}

	return current == root
}

// sha256Pair computes SHA256(left || right).
func sha256Pair(left, right types.Hash) types.Hash {
	h := sha256.New()
	h.Write(left[:])
	h.Write(right[:])
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}
