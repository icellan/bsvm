package covenant

import (
	"encoding/binary"
	"fmt"
)

// BridgeState represents the state of the bridge covenant UTXO.
// These fields are persisted across UTXO spends via OP_PUSH_TX:
//   - Balance:         total locked BSV in satoshis
//   - WithdrawalNonce: monotonic withdrawal counter
type BridgeState struct {
	Balance         uint64 // Total locked BSV in satoshis
	WithdrawalNonce uint64 // Monotonic withdrawal counter
}

// bridgeStateEncodedSize is the fixed size of a serialized BridgeState.
// 8 bytes (Balance) + 8 bytes (WithdrawalNonce) = 16 bytes.
const bridgeStateEncodedSize = 16

// Encode serializes the bridge state for embedding in the locking script.
// The encoding is a fixed-size 16-byte blob:
//
//	[0..8]   Balance (8 bytes, little-endian)
//	[8..16]  WithdrawalNonce (8 bytes, little-endian)
func (s *BridgeState) Encode() []byte {
	buf := make([]byte, bridgeStateEncodedSize)
	binary.LittleEndian.PutUint64(buf[0:8], s.Balance)
	binary.LittleEndian.PutUint64(buf[8:16], s.WithdrawalNonce)
	return buf
}

// DecodeBridgeState deserializes bridge state from the locking script data.
// It expects exactly 16 bytes in the format produced by Encode.
func DecodeBridgeState(data []byte) (*BridgeState, error) {
	if len(data) != bridgeStateEncodedSize {
		return nil, fmt.Errorf("bridge state data must be %d bytes, got %d", bridgeStateEncodedSize, len(data))
	}
	s := &BridgeState{}
	s.Balance = binary.LittleEndian.Uint64(data[0:8])
	s.WithdrawalNonce = binary.LittleEndian.Uint64(data[8:16])
	return s, nil
}

// EmptyBridgeState returns a BridgeState with zero balance and zero nonce.
func EmptyBridgeState() BridgeState {
	return BridgeState{
		Balance:         0,
		WithdrawalNonce: 0,
	}
}
