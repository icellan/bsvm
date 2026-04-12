package vm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/icellan/bsvm/pkg/crypto"
)

func TestKZGVersionedHash(t *testing.T) {
	// A known commitment (48 bytes).
	commitment := make([]byte, 48)
	for i := range commitment {
		commitment[i] = byte(i + 1)
	}

	got := kzgVersionedHash(commitment)

	// Compute expected: SHA256(commitment) with first byte replaced by 0x01.
	expected := sha256.Sum256(commitment)
	expected[0] = 0x01

	if got != expected {
		t.Fatalf("kzgVersionedHash mismatch:\n  got:  %x\n  want: %x", got, expected)
	}

	// Verify version byte is 0x01.
	if got[0] != 0x01 {
		t.Fatalf("version byte should be 0x01, got 0x%02x", got[0])
	}
}

func TestKZGVersionedHashDifferentInputs(t *testing.T) {
	c1 := make([]byte, 48)
	c2 := make([]byte, 48)
	c2[0] = 0xff

	h1 := kzgVersionedHash(c1)
	h2 := kzgVersionedHash(c2)

	if h1 == h2 {
		t.Fatal("different commitments should produce different versioned hashes")
	}
}

func TestPointEvaluationWrongInputLength(t *testing.T) {
	pe := &pointEvaluation{}

	cases := []struct {
		name string
		len  int
	}{
		{"empty", 0},
		{"too short", 100},
		{"too long", 200},
		{"one byte short", 191},
		{"one byte long", 193},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, tc.len)
			_, err := pe.Run(input)
			if err == nil {
				t.Fatal("expected error for wrong input length")
			}
			if err.Error() != "invalid input length for point evaluation" {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPointEvaluationMismatchedVersionedHash(t *testing.T) {
	pe := &pointEvaluation{}

	// Build a 192-byte input with a commitment but wrong versioned hash.
	input := make([]byte, 192)
	// Set commitment (bytes 96..143) to some known value.
	for i := 96; i < 144; i++ {
		input[i] = byte(i - 95)
	}
	// Set versioned hash (bytes 0..31) to all zeros -- this won't match.
	// (The correct hash would be kzgVersionedHash(input[96:144]))

	_, err := pe.Run(input)
	if err == nil {
		t.Fatal("expected error for mismatched versioned hash")
	}
	if err.Error() != "versioned hash does not match commitment" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPointEvaluationCorrectHashButKZGNotReady(t *testing.T) {
	// This test runs without loading the KZG setup, so we expect
	// ErrKZGNotReady when the versioned hash is valid.
	if crypto.KZGReady() {
		t.Skip("KZG already initialized by another test")
	}

	pe := &pointEvaluation{}

	// Build a 192-byte input with a matching versioned hash.
	input := make([]byte, 192)
	// Set commitment (bytes 96..143).
	for i := 96; i < 144; i++ {
		input[i] = byte(i - 95)
	}
	// Compute the correct versioned hash and place it in bytes 0..31.
	expectedHash := kzgVersionedHash(input[96:144])
	copy(input[0:32], expectedHash[:])

	_, err := pe.Run(input)
	if err == nil {
		t.Fatal("expected error when KZG is not ready")
	}
	if !errors.Is(err, ErrKZGNotReady) {
		t.Fatalf("expected ErrKZGNotReady, got: %v", err)
	}
}

func TestPointEvaluationRequiredGas(t *testing.T) {
	pe := &pointEvaluation{}
	gas := pe.RequiredGas(nil)
	if gas != 50000 {
		t.Fatalf("expected RequiredGas 50000, got %d", gas)
	}

	// Gas should be the same regardless of input.
	gas2 := pe.RequiredGas(make([]byte, 192))
	if gas2 != 50000 {
		t.Fatalf("expected RequiredGas 50000 for 192-byte input, got %d", gas2)
	}
}

// precompileTestVector matches the JSON structure in testdata/precompiles/.
type precompileTestVector struct {
	Input       string `json:"Input"`
	Expected    string `json:"Expected"`
	Name        string `json:"Name"`
	Gas         uint64 `json:"Gas"`
	NoBenchmark bool   `json:"NoBenchmark"`
}

func TestPointEvaluationWithTrustedSetup(t *testing.T) {
	// Load the KZG trusted setup.
	if err := InitKZGTrustedSetup(""); err != nil {
		t.Fatalf("failed to load KZG trusted setup: %v", err)
	}
	if !crypto.KZGReady() {
		t.Fatal("KZG should be ready after loading trusted setup")
	}

	// Load test vectors.
	data, err := os.ReadFile("testdata/precompiles/pointEvaluation.json")
	if err != nil {
		t.Fatalf("failed to read test vectors: %v", err)
	}
	var vectors []precompileTestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse test vectors: %v", err)
	}

	pe := &pointEvaluation{}

	for _, vec := range vectors {
		t.Run(vec.Name, func(t *testing.T) {
			input, err := hex.DecodeString(vec.Input)
			if err != nil {
				t.Fatalf("invalid input hex: %v", err)
			}

			gas := pe.RequiredGas(input)
			if gas != vec.Gas {
				t.Fatalf("gas mismatch: got %d, want %d", gas, vec.Gas)
			}

			output, err := pe.Run(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedOutput, err := hex.DecodeString(vec.Expected)
			if err != nil {
				t.Fatalf("invalid expected hex: %v", err)
			}
			if len(output) != len(expectedOutput) {
				t.Fatalf("output length mismatch: got %d, want %d", len(output), len(expectedOutput))
			}
			for i := range output {
				if output[i] != expectedOutput[i] {
					t.Fatalf("output mismatch at byte %d: got %02x, want %02x\n  got:  %x\n  want: %x",
						i, output[i], expectedOutput[i], output, expectedOutput)
				}
			}
		})
	}
}

func TestPointEvaluationInvalidProof(t *testing.T) {
	// Load the KZG trusted setup.
	if err := InitKZGTrustedSetup(""); err != nil {
		t.Fatalf("failed to load KZG trusted setup: %v", err)
	}

	// Load a valid test vector and corrupt the proof to test rejection.
	data, err := os.ReadFile("testdata/precompiles/pointEvaluation.json")
	if err != nil {
		t.Fatalf("failed to read test vectors: %v", err)
	}
	var vectors []precompileTestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse test vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no test vectors found")
	}

	input, err := hex.DecodeString(vectors[0].Input)
	if err != nil {
		t.Fatalf("invalid input hex: %v", err)
	}

	// Corrupt the proof bytes (last 48 bytes).
	corrupted := make([]byte, len(input))
	copy(corrupted, input)
	corrupted[191] ^= 0xff

	pe := &pointEvaluation{}
	_, err = pe.Run(corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted proof")
	}
}

func TestPointEvaluationReturnValue(t *testing.T) {
	// Verify the constant return value matches the expected output from
	// the Ethereum test vectors.
	expected := "000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
	got := hex.EncodeToString(pointEvaluationReturnValue)
	if got != expected {
		t.Fatalf("pointEvaluationReturnValue mismatch:\n  got:  %s\n  want: %s", got, expected)
	}
}
