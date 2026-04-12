package bsv

import (
	"encoding/hex"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// TestHash256 verifies double-SHA256 against a known test vector.
func TestHash256(t *testing.T) {
	// double-SHA256("") is a well-known constant.
	// SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	// SHA256(above) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
	result := Hash256([]byte{})
	expected := "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
	got := hex.EncodeToString(result[:])
	if got != expected {
		t.Errorf("Hash256('') = %s, want %s", got, expected)
	}

	// Hash256 of a single byte 0x00.
	result2 := Hash256([]byte{0x00})
	if result2 == result {
		t.Error("Hash256(0x00) should differ from Hash256('')")
	}

	// Verify determinism.
	result3 := Hash256([]byte{})
	if result3 != result {
		t.Error("Hash256 is not deterministic")
	}
}

// TestIsP2PKH verifies P2PKH script detection.
func TestIsP2PKH(t *testing.T) {
	// Build a valid P2PKH script.
	pubKeyHash := make([]byte, 20)
	for i := range pubKeyHash {
		pubKeyHash[i] = byte(i + 1)
	}
	validScript := BuildP2PKH(pubKeyHash)

	if !IsP2PKH(validScript) {
		t.Error("expected valid P2PKH script to be detected")
	}

	// Too short.
	if IsP2PKH([]byte{0x76, 0xa9, 0x14}) {
		t.Error("short script should not be P2PKH")
	}

	// Wrong opcode.
	invalid := make([]byte, 25)
	copy(invalid, validScript)
	invalid[0] = 0x00
	if IsP2PKH(invalid) {
		t.Error("wrong OP_DUP should not be P2PKH")
	}

	// Empty.
	if IsP2PKH(nil) {
		t.Error("nil should not be P2PKH")
	}
	if IsP2PKH([]byte{}) {
		t.Error("empty should not be P2PKH")
	}
}

// TestExtractP2PKHAddress verifies address extraction from P2PKH scripts.
func TestExtractP2PKHAddress(t *testing.T) {
	pubKeyHash := make([]byte, 20)
	for i := range pubKeyHash {
		pubKeyHash[i] = byte(i + 1)
	}
	script := BuildP2PKH(pubKeyHash)

	addr, ok := ExtractP2PKHAddress(script)
	if !ok {
		t.Fatal("expected extraction to succeed")
	}

	for i := 0; i < 20; i++ {
		if addr[i] != pubKeyHash[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, addr[i], pubKeyHash[i])
		}
	}

	// Non-P2PKH script should fail.
	_, ok = ExtractP2PKHAddress([]byte{0x00, 0x01, 0x02})
	if ok {
		t.Error("expected extraction from non-P2PKH to fail")
	}
}

// TestSatoshisToBSV verifies satoshi-to-BSV string conversion.
func TestSatoshisToBSV(t *testing.T) {
	tests := []struct {
		satoshis uint64
		want     string
	}{
		{100_000_000, "1"},
		{150_000_000, "1.50000000"},
		{1, "0.00000001"},
		{0, "0"},
		{200_000_000, "2"},
		{12345678, "0.12345678"},
		{1_000_000_000, "10"},
		{100_000_001, "1.00000001"},
	}

	for _, tc := range tests {
		got := SatoshisToBSV(tc.satoshis)
		if got != tc.want {
			t.Errorf("SatoshisToBSV(%d) = %q, want %q", tc.satoshis, got, tc.want)
		}
	}
}

// TestOutPointBytes verifies OutPoint serialization.
func TestOutPointBytes(t *testing.T) {
	op := OutPoint{
		TxID: types.HexToHash("0x0102030405060708091011121314151617181920212223242526272829303132"),
		Vout: 1,
	}
	b := op.Bytes()
	if len(b) != 36 {
		t.Fatalf("expected 36 bytes, got %d", len(b))
	}
	// Vout should be in little-endian at bytes 32-35.
	if b[32] != 1 || b[33] != 0 || b[34] != 0 || b[35] != 0 {
		t.Errorf("vout encoding wrong: %v", b[32:36])
	}
}

// TestBuildP2PKH verifies round-trip: build then extract.
func TestBuildP2PKH(t *testing.T) {
	hash := make([]byte, 20)
	hash[0] = 0xab
	hash[19] = 0xcd

	script := BuildP2PKH(hash)
	if script == nil {
		t.Fatal("BuildP2PKH returned nil")
	}
	if len(script) != 25 {
		t.Fatalf("expected 25-byte script, got %d", len(script))
	}

	extracted, ok := ExtractP2PKHAddress(script)
	if !ok {
		t.Fatal("round-trip extraction failed")
	}
	if extracted[0] != 0xab || extracted[19] != 0xcd {
		t.Error("round-trip data mismatch")
	}

	// Invalid length should return nil.
	if BuildP2PKH([]byte{1, 2, 3}) != nil {
		t.Error("BuildP2PKH should return nil for invalid-length input")
	}
}
