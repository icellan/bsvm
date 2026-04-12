package covenant

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// InboxState represents the state of the inbox covenant UTXO.
type InboxState struct {
	TxQueueHash types.Hash // Hash chain root of pending transactions
	TxCount     uint64     // Number of pending transactions
}

// inboxStateEncodedSize is the fixed size of a serialized InboxState.
// 32 bytes (TxQueueHash) + 8 bytes (TxCount) = 40 bytes.
const inboxStateEncodedSize = 40

// Encode serializes the inbox state for embedding in the locking script.
// The encoding is a fixed-size 40-byte blob:
//
//	[0..32]   TxQueueHash (32 bytes)
//	[32..40]  TxCount (8 bytes, little-endian)
func (s *InboxState) Encode() []byte {
	buf := make([]byte, inboxStateEncodedSize)
	copy(buf[0:32], s.TxQueueHash[:])
	binary.LittleEndian.PutUint64(buf[32:40], s.TxCount)
	return buf
}

// DecodeInboxState deserializes inbox state from the locking script data.
// It expects exactly 40 bytes in the format produced by Encode.
func DecodeInboxState(data []byte) (*InboxState, error) {
	if len(data) != inboxStateEncodedSize {
		return nil, fmt.Errorf("inbox state data must be %d bytes, got %d", inboxStateEncodedSize, len(data))
	}
	s := &InboxState{}
	copy(s.TxQueueHash[:], data[0:32])
	s.TxCount = binary.LittleEndian.Uint64(data[32:40])
	return s, nil
}

// EmptyInboxState returns the genesis inbox state with an empty queue.
// The initial TxQueueHash is hash256(zeroes(32)) to match the on-chain
// covenant's initial state.
func EmptyInboxState() InboxState {
	// hash256 = double SHA-256, matching BSV's OP_HASH256.
	zeroes := make([]byte, 32)
	first := sha256.Sum256(zeroes)
	second := sha256.Sum256(first[:])
	return InboxState{
		TxQueueHash: types.BytesToHash(second[:]),
		TxCount:     0,
	}
}
