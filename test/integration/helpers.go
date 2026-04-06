//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const bbPrime = 2013265921

func bbMul(a, b int64) int64 { return (a * b) % bbPrime }

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
