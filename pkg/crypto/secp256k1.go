package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var (
	secp256k1N     *big.Int
	secp256k1HalfN *big.Int
)

func init() {
	secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1HalfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
}

// S256 returns the secp256k1 curve.
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// GenerateKey generates a new secp256k1 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// ToECDSA creates a private key from a 32-byte big-endian byte slice.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	if len(d) != 32 {
		return nil, fmt.Errorf("invalid private key length, want 32 got %d", len(d))
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = secp256k1.S256()
	priv.D = new(big.Int).SetBytes(d)
	if priv.D.Sign() == 0 {
		return nil, errors.New("invalid private key, zero value")
	}
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalid private key, exceeds curve order")
	}
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	return priv, nil
}

// FromECDSA exports a private key as a 32-byte big-endian byte slice.
func FromECDSA(key *ecdsa.PrivateKey) []byte {
	if key == nil {
		return nil
	}
	d := key.D.Bytes()
	// Left-pad to 32 bytes
	padded := make([]byte, 32)
	copy(padded[32-len(d):], d)
	return padded
}

// PubkeyToAddress converts a public key to an Ethereum address.
// address = keccak256(pubkey_uncompressed_without_prefix)[12:]
func PubkeyToAddress(p ecdsa.PublicKey) [20]byte {
	pubBytes := elliptic.Marshal(p.Curve, p.X, p.Y)
	// Remove the 0x04 prefix byte
	hash := Keccak256(pubBytes[1:])
	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr
}

// CompressPubkey compresses a public key to 33 bytes.
func CompressPubkey(p *ecdsa.PublicKey) []byte {
	if p == nil || p.X == nil || p.Y == nil {
		return nil
	}
	// Set the X and Y fields by parsing from uncompressed format
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	// Pad to 32 bytes each
	var x, y [32]byte
	copy(x[32-len(xBytes):], xBytes)
	copy(y[32-len(yBytes):], yBytes)

	// Build the 65-byte uncompressed pubkey: 0x04 || X || Y
	var uncompressed [65]byte
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], x[:])
	copy(uncompressed[33:65], y[:])

	pk, err := secp256k1.ParsePubKey(uncompressed[:])
	if err != nil {
		return nil
	}
	return pk.SerializeCompressed()
}

// DecompressPubkey decompresses a 33-byte public key.
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	if len(pubkey) != 33 {
		return nil, fmt.Errorf("invalid compressed public key length: %d", len(pubkey))
	}
	key, err := secp256k1.ParsePubKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid compressed public key: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     key.X(),
		Y:     key.Y(),
	}, nil
}

// Sign produces a recoverable ECDSA signature.
// The hash should be the Keccak256 hash of the data to sign (32 bytes).
// Returns 65-byte [R || S || V] signature where V is 0 or 1.
func Sign(hash []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}
	if prv == nil {
		return nil, errors.New("private key is nil")
	}

	// Convert to decred private key
	privBytes := FromECDSA(prv)
	privKey := secp256k1.PrivKeyFromBytes(privBytes)

	// SignCompact returns [recovery_flag || R || S] where recovery_flag = 27 + recovery_id + 4 (compressed)
	sig := decredecdsa.SignCompact(privKey, hash, false)

	// sig format from decred: [V || R(32) || S(32)] where V = 27 + recovery_id (+ 4 if compressed)
	// We want: [R(32) || S(32) || V] where V = 0 or 1
	v := sig[0] - 27
	result := make([]byte, 65)
	copy(result[0:32], sig[1:33]) // R
	copy(result[32:64], sig[33:]) // S
	result[64] = v
	return result, nil
}

// Ecrecover recovers the uncompressed public key from a signature.
// hash is the Keccak256 hash that was signed (32 bytes).
// sig is 65 bytes [R || S || V] where V is 0 or 1.
// Returns the 65-byte uncompressed public key (with 0x04 prefix).
func Ecrecover(hash, sig []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}
	if len(sig) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}

	// Convert from [R || S || V] to decred's [recovery_flag || R || S] format
	// recovery_flag = 27 + V for uncompressed keys
	v := sig[64]
	if v > 1 {
		return nil, fmt.Errorf("invalid recovery id: %d", v)
	}

	// Build decred compact signature: [27+v || R(32) || S(32)]
	compactSig := make([]byte, 65)
	compactSig[0] = 27 + v
	copy(compactSig[1:33], sig[0:32])
	copy(compactSig[33:65], sig[32:64])

	pub, _, err := decredecdsa.RecoverCompact(compactSig, hash)
	if err != nil {
		return nil, fmt.Errorf("recovery failed: %w", err)
	}

	// Return 65-byte uncompressed public key: 0x04 || X(32) || Y(32)
	var result [65]byte
	result[0] = 0x04
	xBytes := pub.X().Bytes()
	yBytes := pub.Y().Bytes()
	copy(result[1+32-len(xBytes):33], xBytes)
	copy(result[33+32-len(yBytes):65], yBytes)
	return result[:], nil
}

// SigToPub recovers the public key from a signature and returns it
// as an *ecdsa.PublicKey.
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	pub, err := Ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}
	if len(pub) != 65 || pub[0] != 0x04 {
		return nil, errors.New("invalid recovered public key")
	}
	x := new(big.Int).SetBytes(pub[1:33])
	y := new(big.Int).SetBytes(pub[33:65])
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     x,
		Y:     y,
	}, nil
}

// VerifySignature checks that the given pubkey created the signature over the hash.
// The pubkey should be 65 bytes uncompressed (0x04 || X || Y) or 33 bytes compressed.
// The signature should be 64 bytes [R || S] (no V byte).
// The hash should be 32 bytes.
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	if len(hash) != 32 {
		return false
	}
	var pub *secp256k1.PublicKey
	var err error
	switch len(pubkey) {
	case 33:
		pub, err = secp256k1.ParsePubKey(pubkey)
	case 65:
		pub, err = secp256k1.ParsePubKey(pubkey)
	default:
		return false
	}
	if err != nil {
		return false
	}

	// Parse R and S from the 64-byte signature
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(signature[0:32]); overflow {
		return false
	}
	if overflow := s.SetByteSlice(signature[32:64]); overflow {
		return false
	}
	if r.IsZero() || s.IsZero() {
		return false
	}

	sig := decredecdsa.NewSignature(&r, &s)
	return sig.Verify(hash, pub)
}

// ValidateSignatureValues verifies whether the signature values r, s, v are valid.
// The v value is expected to be 0 or 1.
// If homestead is true, the s value must be less than or equal to secp256k1n/2 (EIP-2).
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if v > 1 {
		return false
	}
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(secp256k1N) >= 0 || s.Cmp(secp256k1N) >= 0 {
		return false
	}
	if homestead && s.Cmp(secp256k1HalfN) > 0 {
		return false
	}
	return true
}
