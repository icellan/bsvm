package prover

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/icellan/bsvm/pkg/types"
)

// computeWithdrawalRoot folds a list of L2 → BSV withdrawals into the
// binary SHA256 Merkle root the SP1 guest commits in public values at
// offset 144. The algorithm is deliberately bit-identical to
// pkg/bridge/withdrawal.go::BuildWithdrawalMerkleTree so the bridge
// covenant's inclusion proofs (built off pkg/bridge) verify against the
// STARK-attested root produced here:
//
//	leaf      = hash256(recipient || amount_u64_be || nonce_u64_be)
//	internal  = SHA256(left || right)            // single-block, NOT hash256
//	odd level = pad with bytes32(0)              // NOT last-element duplication
//	empty     = bytes32(0)
//
// The Rust guest at prover/guest-evm/src/main.rs uses the same algorithm.
// The pkg/prover/withdrawal_root_test.go differential test asserts the
// three implementations agree on a fixture set.
func computeWithdrawalRoot(withdrawals []Withdrawal) types.Hash {
	if len(withdrawals) == 0 {
		return types.Hash{}
	}

	level := make([]types.Hash, len(withdrawals))
	for i, w := range withdrawals {
		level[i] = withdrawalLeaf(w)
	}

	if len(level) == 1 {
		return level[0]
	}

	for len(level) > 1 {
		if len(level)%2 != 0 {
			level = append(level, types.Hash{})
		}
		next := make([]types.Hash, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = sha256Pair(level[i], level[i+1])
		}
		level = next
	}
	return level[0]
}

// withdrawalLeaf computes hash256(recipient || amount_be || nonce_be).
func withdrawalLeaf(w Withdrawal) types.Hash {
	buf := make([]byte, 0, 20+8+8)
	buf = append(buf, w.Recipient[:]...)
	be := make([]byte, 8)
	binary.BigEndian.PutUint64(be, w.AmountSatoshis)
	buf = append(buf, be...)
	binary.BigEndian.PutUint64(be, w.Nonce)
	buf = append(buf, be...)
	first := sha256.Sum256(buf)
	second := sha256.Sum256(first[:])
	return types.Hash(second)
}

// sha256Pair computes SHA256(left || right) — single-block internal node.
func sha256Pair(left, right types.Hash) types.Hash {
	h := sha256.New()
	h.Write(left[:])
	h.Write(right[:])
	var out types.Hash
	copy(out[:], h.Sum(nil))
	return out
}
