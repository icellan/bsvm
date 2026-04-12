package vm

import (
	"crypto/sha256"
	"errors"

	"github.com/icellan/bsvm/pkg/crypto"
)

// ErrKZGNotReady is returned when KZG trusted setup is not loaded.
var ErrKZGNotReady = errors.New("kzg trusted setup not loaded")

// kzgVersionedHash computes the versioned hash of a KZG commitment.
// versioned_hash = 0x01 || SHA256(commitment)[1:]
func kzgVersionedHash(commitment []byte) [32]byte {
	h := sha256.Sum256(commitment)
	h[0] = 0x01 // Version byte
	return h
}

// InitKZGTrustedSetup initializes the KZG trusted setup. The path
// parameter is passed to crypto.LoadKZGTrustedSetup but is currently
// unused because the library embeds the Ethereum ceremony data.
func InitKZGTrustedSetup(path string) error {
	return crypto.LoadKZGTrustedSetup(path)
}
