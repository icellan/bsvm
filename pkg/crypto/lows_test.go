package crypto

import (
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestLowSRejectsHighS covers EIP-2: any signature whose s value is greater
// than secp256k1n/2 must be rejected by ValidateSignatureValues when the
// homestead rule set is active. It also verifies that Ecrecover still works
// on the high-S form (recovery is a pure cryptographic operation that does
// not enforce EIP-2), so the rejection must happen at the validation layer.
func TestLowSRejectsHighS(t *testing.T) {
	curveN := new(big.Int).Set(secp256k1.S256().N)
	if curveN.Cmp(secp256k1N) != 0 {
		t.Fatalf("curve order mismatch: decred=%s package=%s", curveN.Text(16), secp256k1N.Text(16))
	}

	// Generate a fresh key and sign a well-known message hash.
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := Keccak256([]byte("low-s enforcement test"))

	sig, err := Sign(msg, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("unexpected signature length: got %d want 65", len(sig))
	}

	// Our Sign() always produces canonical low-S signatures. Sanity check
	// that the emitted s value sits in [1, N/2].
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[64]

	if s.Sign() <= 0 {
		t.Fatalf("signing produced non-positive s: %s", s.String())
	}
	if s.Cmp(secp256k1HalfN) > 0 {
		t.Fatalf("signing produced high-S (s > N/2): s=%s halfN=%s", s.String(), secp256k1HalfN.String())
	}

	// ValidateSignatureValues accepts the canonical low-S signature under
	// both frontier (homestead=false) and homestead (homestead=true) rules.
	if !ValidateSignatureValues(v, r, s, false) {
		t.Fatal("ValidateSignatureValues rejected a valid low-S signature (frontier)")
	}
	if !ValidateSignatureValues(v, r, s, true) {
		t.Fatal("ValidateSignatureValues rejected a valid low-S signature (homestead)")
	}

	// Recover the public key from the low-S signature and cross-check that
	// it matches the signer. This confirms the baseline signature is valid.
	pubLow, err := Ecrecover(msg, sig)
	if err != nil {
		t.Fatalf("Ecrecover(low-S): %v", err)
	}
	if len(pubLow) != 65 || pubLow[0] != 0x04 {
		t.Fatalf("unexpected pubkey format: %x", pubLow[:1])
	}
	lowAddr := keccakAddress(pubLow[1:])
	wantAddr := PubkeyToAddress(key.PublicKey)
	if lowAddr != wantAddr {
		t.Fatalf("low-S recovery returned wrong address: got %x want %x", lowAddr, wantAddr)
	}

	// Build the malleated high-S counterpart: s' = N - s. Keep r identical
	// and flip the parity bit in v (recovery id toggles when s is negated).
	highS := new(big.Int).Sub(curveN, s)
	if highS.Cmp(secp256k1HalfN) <= 0 {
		t.Fatalf("expected N-s > N/2 but got %s", highS.String())
	}

	highSig := make([]byte, 65)
	copy(highSig[0:32], sig[0:32])
	highSBytes := highS.Bytes()
	copy(highSig[64-len(highSBytes):64], highSBytes)
	highSig[64] = v ^ 1 // flip recovery id parity

	// EIP-2 enforcement: ValidateSignatureValues MUST reject the high-S
	// form when homestead is true.
	if ValidateSignatureValues(highSig[64], r, highS, true) {
		t.Fatal("ValidateSignatureValues accepted high-S signature under homestead rules (EIP-2 violation)")
	}

	// Non-homestead (frontier) rules do not check the low-S bound, so the
	// high-S form must be accepted there. This confirms the gate really is
	// the homestead flag.
	if !ValidateSignatureValues(highSig[64], r, highS, false) {
		t.Fatal("ValidateSignatureValues rejected high-S signature under frontier rules")
	}

	// Ecrecover itself does not enforce EIP-2 and must still return the
	// same public key for the malleated signature. This is the exact
	// malleability window EIP-2 closes at the validation layer.
	pubHigh, err := Ecrecover(msg, highSig)
	if err != nil {
		t.Fatalf("Ecrecover(high-S): %v", err)
	}
	highAddr := keccakAddress(pubHigh[1:])
	if highAddr != wantAddr {
		t.Fatalf("high-S recovery returned wrong address: got %x want %x (signatures are malleable but must recover the same key)", highAddr, wantAddr)
	}
}

// TestValidateSignatureValuesBoundary exercises the exact boundaries of
// EIP-2 low-S enforcement.
func TestValidateSignatureValuesBoundary(t *testing.T) {
	r := big.NewInt(1)

	tests := []struct {
		name      string
		s         *big.Int
		homestead bool
		want      bool
	}{
		{
			name:      "s == halfN accepted under homestead",
			s:         new(big.Int).Set(secp256k1HalfN),
			homestead: true,
			want:      true,
		},
		{
			name:      "s == halfN+1 rejected under homestead",
			s:         new(big.Int).Add(secp256k1HalfN, big.NewInt(1)),
			homestead: true,
			want:      false,
		},
		{
			name:      "s == N-1 rejected under homestead",
			s:         new(big.Int).Sub(secp256k1N, big.NewInt(1)),
			homestead: true,
			want:      false,
		},
		{
			name:      "s == N-1 accepted under frontier",
			s:         new(big.Int).Sub(secp256k1N, big.NewInt(1)),
			homestead: false,
			want:      true,
		},
		{
			name:      "s == N rejected (>= N)",
			s:         new(big.Int).Set(secp256k1N),
			homestead: false,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSignatureValues(0, r, tt.s, tt.homestead)
			if got != tt.want {
				t.Errorf("ValidateSignatureValues(0, 1, %s, %v) = %v, want %v",
					tt.s.String(), tt.homestead, got, tt.want)
			}
		})
	}
}

// keccakAddress mirrors PubkeyToAddress for a raw 64-byte X||Y pubkey body.
func keccakAddress(pubBody []byte) [20]byte {
	h := Keccak256(pubBody)
	var addr [20]byte
	copy(addr[:], h[12:])
	return addr
}
