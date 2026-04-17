package covenant

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// BridgeState represents the state of the bridge covenant UTXO.
// These fields are persisted across UTXO spends via OP_PUSH_TX:
//   - Balance:               total locked BSV in satoshis
//   - WithdrawalNonce:       monotonic withdrawal counter
//   - WithdrawalsCommitment: running hash-chain commitment over every
//     processed withdrawal nullifier. Updated on every Withdraw call as
//     hash256(prevCommitment || nullifier) where
//     nullifier = hash256(bsvAddress || amountBE8 || nonceBE8). The
//     chain is initialised to the 32-byte zero hash at genesis. It is
//     tamper-evident — once a withdrawal has been folded in, the
//     commitment cannot be reverted without replaying the full history,
//     so a BSV reorg that rolls WithdrawalNonce back cannot re-use an
//     already-observed (recipient, amount, nonce) tuple silently.
type BridgeState struct {
	Balance               uint64     // Total locked BSV in satoshis
	WithdrawalNonce       uint64     // Monotonic withdrawal counter
	WithdrawalsCommitment types.Hash // Running hash chain over spent nullifiers
}

// bridgeStateEncodedSize is the fixed size of a serialized BridgeState.
// 8 bytes (Balance) + 8 bytes (WithdrawalNonce) + 32 bytes
// (WithdrawalsCommitment) = 48 bytes.
const bridgeStateEncodedSize = 48

// Encode serializes the bridge state for embedding in the locking script.
// The encoding is a fixed-size 48-byte blob:
//
//	[0..8]    Balance (8 bytes, little-endian)
//	[8..16]   WithdrawalNonce (8 bytes, little-endian)
//	[16..48]  WithdrawalsCommitment (32 bytes, raw)
func (s *BridgeState) Encode() []byte {
	buf := make([]byte, bridgeStateEncodedSize)
	binary.LittleEndian.PutUint64(buf[0:8], s.Balance)
	binary.LittleEndian.PutUint64(buf[8:16], s.WithdrawalNonce)
	copy(buf[16:48], s.WithdrawalsCommitment[:])
	return buf
}

// DecodeBridgeState deserializes bridge state from the locking script data.
// It expects exactly 48 bytes in the format produced by Encode.
func DecodeBridgeState(data []byte) (*BridgeState, error) {
	if len(data) != bridgeStateEncodedSize {
		return nil, fmt.Errorf("bridge state data must be %d bytes, got %d", bridgeStateEncodedSize, len(data))
	}
	s := &BridgeState{}
	s.Balance = binary.LittleEndian.Uint64(data[0:8])
	s.WithdrawalNonce = binary.LittleEndian.Uint64(data[8:16])
	copy(s.WithdrawalsCommitment[:], data[16:48])
	return s, nil
}

// EmptyBridgeState returns a BridgeState with zero balance, zero nonce,
// and a zero-hash withdrawal commitment (the genesis value).
func EmptyBridgeState() BridgeState {
	return BridgeState{
		Balance:               0,
		WithdrawalNonce:       0,
		WithdrawalsCommitment: types.Hash{},
	}
}

// WithdrawalNullifier computes the Go-side nullifier key for a
// withdrawal. It is hash256(bsvAddress_20 || amount_u64_be || nonce_u64_be),
// matching the withdrawal hash the bridge emits on L2 and the same
// encoding spec 07 mandates for Bitcoin-side verification. Keeping the
// same pre-image means the nullifier is equivalent to the
// on-chain-visible withdrawal hash.
//
// This is the SAME value the Rúnar bridge covenant folds into
// WithdrawalsCommitment on each Withdraw call — keep the encoding in
// lockstep with pkg/covenant/contracts/bridge.runar.go.
func WithdrawalNullifier(bsvAddress []byte, satoshiAmount uint64, nonce uint64) types.Hash {
	buf := make([]byte, 0, len(bsvAddress)+16)
	buf = append(buf, bsvAddress...)

	var amountBE [8]byte
	binary.BigEndian.PutUint64(amountBE[:], satoshiAmount)
	buf = append(buf, amountBE[:]...)

	var nonceBE [8]byte
	binary.BigEndian.PutUint64(nonceBE[:], nonce)
	buf = append(buf, nonceBE[:]...)

	first := sha256.Sum256(buf)
	second := sha256.Sum256(first[:])
	return types.Hash(second)
}

// foldWithdrawalsCommitment computes the next entry in the
// WithdrawalsCommitment hash chain:
//
//	newCommitment = hash256(prev || nullifier)
//
// It mirrors the Rúnar bridge covenant's on-chain step exactly so the
// Go-side BridgeState tracks the on-chain commitment byte-for-byte.
func foldWithdrawalsCommitment(prev types.Hash, nullifier types.Hash) types.Hash {
	buf := make([]byte, 0, 64)
	buf = append(buf, prev[:]...)
	buf = append(buf, nullifier[:]...)
	first := sha256.Sum256(buf)
	second := sha256.Sum256(first[:])
	return types.Hash(second)
}
