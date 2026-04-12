package types

import (
	"encoding/hex"
	"math/big"
	"strings"
)

const (
	// HashLength is the expected length of a hash in bytes.
	HashLength = 32
	// AddressLength is the expected length of an address in bytes.
	AddressLength = 20
)

// Hash represents a 32-byte Keccak256 hash.
type Hash [HashLength]byte

// Address represents a 20-byte Ethereum address.
type Address [AddressLength]byte

// BytesToHash converts a byte slice to Hash. Left-pads if shorter than 32 bytes.
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// BytesToAddress converts a byte slice to Address. Left-pads if shorter than 20 bytes.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// HexToHash converts a hex string (with or without 0x prefix) to Hash.
func HexToHash(s string) Hash {
	return BytesToHash(fromHex(s))
}

// HexToAddress converts a hex string (with or without 0x prefix) to Address.
func HexToAddress(s string) Address {
	return BytesToAddress(fromHex(s))
}

// BigToHash converts a *big.Int to Hash.
func BigToHash(b *big.Int) Hash {
	return BytesToHash(b.Bytes())
}

// Hex returns the hex string representation with 0x prefix.
func (h Hash) Hex() string {
	return "0x" + hex.EncodeToString(h[:])
}

// Hex returns the hex string representation with 0x prefix.
func (a Address) Hex() string {
	return "0x" + hex.EncodeToString(a[:])
}

// Bytes returns the byte representation of the hash.
func (h Hash) Bytes() []byte { return h[:] }

// Bytes returns the byte representation of the address.
func (a Address) Bytes() []byte { return a[:] }

// Big returns the hash as a big.Int.
func (h Hash) Big() *big.Int {
	return new(big.Int).SetBytes(h[:])
}

// String implements fmt.Stringer for Hash.
func (h Hash) String() string { return h.Hex() }

// String implements fmt.Stringer for Address.
func (a Address) String() string { return a.Hex() }

// SetBytes sets the hash from bytes, left-padding if shorter than HashLength.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > HashLength {
		b = b[len(b)-HashLength:]
	}
	copy(h[HashLength-len(b):], b)
}

// SetBytes sets the address from bytes, left-padding if shorter than AddressLength.
func (a *Address) SetBytes(b []byte) {
	if len(b) > AddressLength {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// Common big.Int constants matching geth's common package.
var (
	Big0   = big.NewInt(0)
	Big1   = big.NewInt(1)
	Big2   = big.NewInt(2)
	Big3   = big.NewInt(3)
	Big32  = big.NewInt(32)
	Big256 = big.NewInt(256)
	Big257 = big.NewInt(257)
)

// EmptyRootHash is the root hash of an empty Merkle Patricia Trie.
var EmptyRootHash = HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

// EmptyCodeHash is the keccak256 hash of empty code.
var EmptyCodeHash = HexToHash("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

// UnmarshalJSON implements json.Unmarshaler for Hash.
func (h *Hash) UnmarshalJSON(input []byte) error {
	// Remove quotes.
	if len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"' {
		input = input[1 : len(input)-1]
	}
	b := fromHex(string(input))
	h.SetBytes(b)
	return nil
}

// MarshalJSON implements json.Marshaler for Hash.
func (h Hash) MarshalJSON() ([]byte, error) {
	return []byte(`"` + h.Hex() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler for Address.
func (a *Address) UnmarshalJSON(input []byte) error {
	// Remove quotes.
	if len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"' {
		input = input[1 : len(input)-1]
	}
	b := fromHex(string(input))
	a.SetBytes(b)
	return nil
}

// MarshalJSON implements json.Marshaler for Address.
func (a Address) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.Hex() + `"`), nil
}

// fromHex decodes a hex string, stripping the optional 0x prefix.
func fromHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ := hex.DecodeString(s)
	return b
}

// RightPadBytes right-pads a byte slice to the given length.
func RightPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}
	padded := make([]byte, l)
	copy(padded, slice)
	return padded
}

// LeftPadBytes left-pads a byte slice to the given length.
func LeftPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}
	padded := make([]byte, l)
	copy(padded[l-len(slice):], slice)
	return padded
}

// CopyBytes returns a deep copy of the provided byte slice.
func CopyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}
