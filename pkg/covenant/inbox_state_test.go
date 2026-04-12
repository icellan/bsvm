package covenant

import (
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

func TestInboxState_EncodeDecode_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		state InboxState
	}{
		{
			name: "zero values",
			state: InboxState{
				TxQueueHash: types.Hash{},
				TxCount:     0,
			},
		},
		{
			name: "populated state",
			state: InboxState{
				TxQueueHash: testStateRoot(77),
				TxCount:     42,
			},
		},
		{
			name: "max count",
			state: InboxState{
				TxQueueHash: testStateRoot(255),
				TxCount:     ^uint64(0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.state.Encode()
			if len(encoded) != inboxStateEncodedSize {
				t.Fatalf("expected %d bytes, got %d", inboxStateEncodedSize, len(encoded))
			}

			decoded, err := DecodeInboxState(encoded)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			if decoded.TxQueueHash != tt.state.TxQueueHash {
				t.Errorf("queue hash mismatch: got %x, want %x", decoded.TxQueueHash, tt.state.TxQueueHash)
			}
			if decoded.TxCount != tt.state.TxCount {
				t.Errorf("tx count mismatch: got %d, want %d", decoded.TxCount, tt.state.TxCount)
			}
		})
	}
}

func TestInboxState_EmptyState(t *testing.T) {
	empty := EmptyInboxState()

	// Count must be zero.
	if empty.TxCount != 0 {
		t.Errorf("expected zero count, got %d", empty.TxCount)
	}

	// Queue hash must be hash256(zeroes(32)), which is non-zero.
	zeroHash := types.Hash{}
	if empty.TxQueueHash == zeroHash {
		t.Error("expected non-zero queue hash for empty state (it should be hash256 of 32 zero bytes)")
	}

	// Verify round-trip.
	encoded := empty.Encode()
	decoded, err := DecodeInboxState(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.TxQueueHash != empty.TxQueueHash {
		t.Errorf("queue hash mismatch after round-trip")
	}
	if decoded.TxCount != 0 {
		t.Errorf("tx count should be 0 after round-trip, got %d", decoded.TxCount)
	}
}

func TestInboxState_Decode_WrongSize(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: make([]byte, 10),
		},
		{
			name: "too long",
			data: make([]byte, 50),
		},
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "one byte short",
			data: make([]byte, inboxStateEncodedSize-1),
		},
		{
			name: "one byte long",
			data: make([]byte, inboxStateEncodedSize+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeInboxState(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
