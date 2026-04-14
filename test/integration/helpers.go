//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// kbP is the KoalaBear field prime used by the on-chain BasefoldRollup
// verifier (runar.KbFieldMul). The old rollup.runar.go used BabyBear
// (p = 2^31 - 2^27 + 1 = 2013265921); the new rollup_basefold.runar.go
// uses KoalaBear (p = 2^31 - 2^24 + 1 = 2130706433).
const kbP = 2_130_706_433

// kbMul multiplies two int64 values modulo the KoalaBear field prime.
// Used by tests to build a valid proofFieldC = proofFieldA * proofFieldB
// that the on-chain verifier will accept.
func kbMul(a, b int64) int64 { return (a * b) % kbP }

func hexSha256(h string) string {
	data, _ := hex.DecodeString(h)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hexHash256(h string) string { return hexSha256(hexSha256(h)) }

func hexStateRoot(n int) string { return hexSha256(fmt.Sprintf("%02x", n)) }

func hexZeros32() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

const chainID = int64(8453111)
