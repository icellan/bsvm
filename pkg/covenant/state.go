package covenant

import (
	"encoding/binary"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// CovenantState represents the state stored in the covenant UTXO.
// These fields are persisted across UTXO spends via OP_PUSH_TX:
//   - StateRoot:          32-byte hash of current L2 state
//   - BlockNumber:        monotonically increasing block counter
//   - Frozen:             0 = active, 1 = frozen by governance
//   - AdvancesSinceInbox: number of advances since last inbox drain
type CovenantState struct {
	StateRoot          types.Hash
	BlockNumber        uint64
	Frozen             uint8  // 0 = active, 1 = frozen
	AdvancesSinceInbox uint64 // number of advances since last inbox drain
}

// covenantStateEncodedSize is the fixed size of a serialized CovenantState.
// 32 bytes (StateRoot) + 8 bytes (BlockNumber) + 1 byte (Frozen) +
// 8 bytes (AdvancesSinceInbox) = 49 bytes.
const covenantStateEncodedSize = 49

// Encode serializes the covenant state for embedding in the locking script.
// The encoding is a fixed-size 49-byte blob:
//
//	[0..32]   StateRoot (32 bytes)
//	[32..40]  BlockNumber (8 bytes, little-endian)
//	[40]      Frozen (1 byte)
//	[41..49]  AdvancesSinceInbox (8 bytes, little-endian)
func (s *CovenantState) Encode() []byte {
	buf := make([]byte, covenantStateEncodedSize)
	copy(buf[0:32], s.StateRoot[:])
	binary.LittleEndian.PutUint64(buf[32:40], s.BlockNumber)
	buf[40] = s.Frozen
	binary.LittleEndian.PutUint64(buf[41:49], s.AdvancesSinceInbox)
	return buf
}

// DecodeCovenantState deserializes covenant state from the locking script data.
// It expects exactly 49 bytes in the format produced by Encode.
func DecodeCovenantState(data []byte) (*CovenantState, error) {
	if len(data) != covenantStateEncodedSize {
		return nil, fmt.Errorf("covenant state data must be %d bytes, got %d", covenantStateEncodedSize, len(data))
	}
	s := &CovenantState{}
	copy(s.StateRoot[:], data[0:32])
	s.BlockNumber = binary.LittleEndian.Uint64(data[32:40])
	s.Frozen = data[40]
	if s.Frozen > 1 {
		return nil, fmt.Errorf("invalid frozen value %d, expected 0 or 1", s.Frozen)
	}
	s.AdvancesSinceInbox = binary.LittleEndian.Uint64(data[41:49])
	return s, nil
}
