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
//   - AdvancesSinceInbox: forced-inclusion counter; reset to 0 on every
//     advance that drains the inbox (inboxRootBefore != inboxRootAfter
//     in the SP1 public values), incremented otherwise. Must never reach
//     MaxAdvancesWithoutInboxDrain (10) while the inbox has pending txs
//     (see spec 10 "Forced Inclusion Inbox").
type CovenantState struct {
	StateRoot          types.Hash
	BlockNumber        uint64
	Frozen             uint8 // 0 = active, 1 = frozen
	AdvancesSinceInbox uint8 // forced-inclusion counter; reset on inbox drain
}

// covenantStateEncodedSize is the fixed size of a serialized CovenantState.
// 32 bytes (StateRoot) + 8 bytes (BlockNumber) + 1 byte (Frozen) +
// 1 byte (AdvancesSinceInbox) = 42 bytes. Format version 2 (v1 was 41
// bytes without the inbox counter).
const covenantStateEncodedSize = 42

// Encode serializes the covenant state for embedding in the locking script.
// The encoding is a fixed-size 42-byte blob (format v2):
//
//	[0..32]   StateRoot (32 bytes)
//	[32..40]  BlockNumber (8 bytes, little-endian)
//	[40]      Frozen (1 byte)
//	[41]      AdvancesSinceInbox (1 byte)
func (s *CovenantState) Encode() []byte {
	buf := make([]byte, covenantStateEncodedSize)
	copy(buf[0:32], s.StateRoot[:])
	binary.LittleEndian.PutUint64(buf[32:40], s.BlockNumber)
	buf[40] = s.Frozen
	buf[41] = s.AdvancesSinceInbox
	return buf
}

// DecodeCovenantState deserializes covenant state from the locking script data.
// It expects exactly 42 bytes in the format produced by Encode (v2).
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
	s.AdvancesSinceInbox = data[41]
	return s, nil
}
