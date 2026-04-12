package vm

import (
	"errors"
	"math/big"

	"github.com/icellan/bsvm/pkg/vm/bn256"
)

// runBn256Add implements the bn256 point addition precompile.
func runBn256Add(input []byte) ([]byte, error) {
	input = padInput(input, 128)

	a := new(bn256.G1)
	if _, err := a.Unmarshal(input[0:64]); err != nil {
		return nil, err
	}
	b := new(bn256.G1)
	if _, err := b.Unmarshal(input[64:128]); err != nil {
		return nil, err
	}

	result := new(bn256.G1)
	result.Add(a, b)
	return result.Marshal(), nil
}

// runBn256ScalarMul implements the bn256 scalar multiplication precompile.
func runBn256ScalarMul(input []byte) ([]byte, error) {
	input = padInput(input, 96)

	a := new(bn256.G1)
	if _, err := a.Unmarshal(input[0:64]); err != nil {
		return nil, err
	}

	scalar := new(big.Int).SetBytes(input[64:96])

	result := new(bn256.G1)
	result.ScalarMult(a, scalar)
	return result.Marshal(), nil
}

// runBn256Pairing implements the bn256 pairing check precompile.
func runBn256Pairing(input []byte) ([]byte, error) {
	// Input must be a multiple of 192 bytes (64 for G1 + 128 for G2)
	if len(input)%192 != 0 {
		return nil, errors.New("bn256: invalid input length for pairing check")
	}

	n := len(input) / 192
	g1s := make([]*bn256.G1, n)
	g2s := make([]*bn256.G2, n)

	for i := 0; i < n; i++ {
		offset := i * 192
		g1s[i] = new(bn256.G1)
		if _, err := g1s[i].Unmarshal(input[offset : offset+64]); err != nil {
			return nil, err
		}
		g2s[i] = new(bn256.G2)
		if _, err := g2s[i].Unmarshal(input[offset+64 : offset+192]); err != nil {
			return nil, err
		}
	}

	if bn256.PairingCheck(g1s, g2s) {
		// Return 1 (32 bytes, big-endian)
		result := make([]byte, 32)
		result[31] = 1
		return result, nil
	}
	// Return 0
	return make([]byte, 32), nil
}
