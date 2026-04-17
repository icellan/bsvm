package covenant

import (
	"math"
	"testing"
)

// ---------------------------------------------------------------------------
// TestBridgeState_EncodeDecode_RoundTrip
// ---------------------------------------------------------------------------

func TestBridgeState_EncodeDecode_RoundTrip(t *testing.T) {
	// mkCommitment makes a distinctive 32-byte commitment so the
	// encode/decode round-trip would fail visibly if the field were
	// dropped or the offset were miscomputed.
	mkCommitment := func(seed byte) [32]byte {
		var out [32]byte
		for i := range out {
			out[i] = seed + byte(i)
		}
		return out
	}

	tests := []struct {
		name  string
		state BridgeState
	}{
		{
			name: "zero state",
			state: BridgeState{
				Balance:         0,
				WithdrawalNonce: 0,
			},
		},
		{
			name: "typical state",
			state: BridgeState{
				Balance:               1_000_000,
				WithdrawalNonce:       42,
				WithdrawalsCommitment: mkCommitment(0x11),
			},
		},
		{
			name: "large balance",
			state: BridgeState{
				Balance:               21_000_000 * 100_000_000, // 21M BSV in satoshis
				WithdrawalNonce:       999_999,
				WithdrawalsCommitment: mkCommitment(0x22),
			},
		},
		{
			name: "high nonce",
			state: BridgeState{
				Balance:               1,
				WithdrawalNonce:       1_000_000_000,
				WithdrawalsCommitment: mkCommitment(0x33),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.state.Encode()
			if len(encoded) != bridgeStateEncodedSize {
				t.Fatalf("expected %d bytes, got %d", bridgeStateEncodedSize, len(encoded))
			}

			decoded, err := DecodeBridgeState(encoded)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			if decoded.Balance != tt.state.Balance {
				t.Errorf("balance mismatch: got %d, want %d", decoded.Balance, tt.state.Balance)
			}
			if decoded.WithdrawalNonce != tt.state.WithdrawalNonce {
				t.Errorf("withdrawal nonce mismatch: got %d, want %d", decoded.WithdrawalNonce, tt.state.WithdrawalNonce)
			}
			if decoded.WithdrawalsCommitment != tt.state.WithdrawalsCommitment {
				t.Errorf("withdrawals commitment mismatch: got %x, want %x",
					decoded.WithdrawalsCommitment, tt.state.WithdrawalsCommitment)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBridgeState_EmptyState
// ---------------------------------------------------------------------------

func TestBridgeState_EmptyState(t *testing.T) {
	s := EmptyBridgeState()
	if s.Balance != 0 {
		t.Errorf("expected zero balance, got %d", s.Balance)
	}
	if s.WithdrawalNonce != 0 {
		t.Errorf("expected zero nonce, got %d", s.WithdrawalNonce)
	}
	var zero [32]byte
	if s.WithdrawalsCommitment != zero {
		t.Errorf("expected zero commitment, got %x", s.WithdrawalsCommitment)
	}
}

// ---------------------------------------------------------------------------
// TestBridgeState_Decode_WrongSize
// ---------------------------------------------------------------------------

func TestBridgeState_Decode_WrongSize(t *testing.T) {
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
			data: make([]byte, 20),
		},
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "one byte short",
			data: make([]byte, bridgeStateEncodedSize-1),
		},
		{
			name: "one byte long",
			data: make([]byte, bridgeStateEncodedSize+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBridgeState(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBridgeState_MaxValues
// ---------------------------------------------------------------------------

func TestBridgeState_MaxValues(t *testing.T) {
	var allOnes [32]byte
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	s := BridgeState{
		Balance:               math.MaxUint64,
		WithdrawalNonce:       math.MaxUint64,
		WithdrawalsCommitment: allOnes,
	}
	encoded := s.Encode()
	if len(encoded) != bridgeStateEncodedSize {
		t.Fatalf("expected %d bytes, got %d", bridgeStateEncodedSize, len(encoded))
	}

	decoded, err := DecodeBridgeState(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Balance != math.MaxUint64 {
		t.Errorf("balance mismatch: got %d, want %d", decoded.Balance, uint64(math.MaxUint64))
	}
	if decoded.WithdrawalNonce != math.MaxUint64 {
		t.Errorf("nonce mismatch: got %d, want %d", decoded.WithdrawalNonce, uint64(math.MaxUint64))
	}
	if decoded.WithdrawalsCommitment != allOnes {
		t.Errorf("commitment mismatch: got %x, want %x", decoded.WithdrawalsCommitment, allOnes)
	}
}
