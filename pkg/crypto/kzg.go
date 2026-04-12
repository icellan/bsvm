package crypto

import (
	"sync"

	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
)

// kzgContext holds the KZG trusted setup state.
var (
	kzgOnce    sync.Once
	kzgCtx     *gokzg4844.Context
	kzgInitErr error
)

// LoadKZGTrustedSetup initializes the KZG trusted setup. The dataDir
// parameter is currently unused because the go-kzg-4844 library embeds
// the Ethereum ceremony trusted setup. This function is safe to call
// multiple times; only the first call performs initialization.
func LoadKZGTrustedSetup(_ string) error {
	kzgOnce.Do(func() {
		kzgCtx, kzgInitErr = gokzg4844.NewContext4096Secure()
	})
	return kzgInitErr
}

// KZGReady reports whether the KZG trusted setup has been loaded.
func KZGReady() bool {
	return kzgCtx != nil
}

// VerifyKZGProof verifies a KZG proof for a point evaluation.
// commitment must be 48 bytes, z and y must be 32 bytes, proof must be 48 bytes.
func VerifyKZGProof(commitment, z, y, proof []byte) error {
	if kzgCtx == nil {
		return errKZGNotLoaded
	}

	var comm gokzg4844.KZGCommitment
	copy(comm[:], commitment)

	var zScalar gokzg4844.Scalar
	copy(zScalar[:], z)

	var yScalar gokzg4844.Scalar
	copy(yScalar[:], y)

	var kzgProof gokzg4844.KZGProof
	copy(kzgProof[:], proof)

	return kzgCtx.VerifyKZGProof(comm, zScalar, yScalar, kzgProof)
}

var errKZGNotLoaded = kzgNotLoadedError{}

type kzgNotLoadedError struct{}

func (kzgNotLoadedError) Error() string { return "kzg trusted setup not loaded" }
