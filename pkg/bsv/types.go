// Package bsv provides BSV primitive types and utilities used
// across the BSVM project. This includes BSV transaction types,
// script builders, and address encoding.
package bsv

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// UTXO represents an unspent BSV transaction output.
type UTXO struct {
	TxID     types.Hash
	Vout     uint32
	Satoshis uint64
	Script   []byte
}

// OutPoint identifies a specific output of a BSV transaction.
type OutPoint struct {
	TxID types.Hash
	Vout uint32
}

// Bytes serializes the OutPoint as 32-byte txid (little-endian) + 4-byte vout
// (little-endian), matching BSV's serialization format.
func (o OutPoint) Bytes() []byte {
	buf := make([]byte, 36)
	// TxID is stored as-is (already in internal byte order).
	copy(buf[:32], o.TxID[:])
	binary.LittleEndian.PutUint32(buf[32:], o.Vout)
	return buf
}

// Hash256 computes double-SHA256, matching BSV's OP_HASH256.
func Hash256(data []byte) types.Hash {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return types.Hash(second)
}

// SHA256 computes a single SHA256 hash.
func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// Standard Bitcoin Script opcodes used for P2PKH detection.
const (
	opDUP         = 0x76
	opHASH160     = 0xa9
	opPUSH20      = 0x14
	opEQUALVERIFY = 0x88
	opCHECKSIG    = 0xac
)

// IsP2PKH checks if a script is a standard P2PKH script.
// A P2PKH script has the form: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
func IsP2PKH(script []byte) bool {
	return len(script) == 25 &&
		script[0] == opDUP &&
		script[1] == opHASH160 &&
		script[2] == opPUSH20 &&
		script[23] == opEQUALVERIFY &&
		script[24] == opCHECKSIG
}

// ExtractP2PKHAddress extracts the 20-byte public key hash from a P2PKH script.
// Returns the hash and true if the script is P2PKH, or nil and false otherwise.
func ExtractP2PKHAddress(script []byte) ([]byte, bool) {
	if !IsP2PKH(script) {
		return nil, false
	}
	addr := make([]byte, 20)
	copy(addr, script[3:23])
	return addr, true
}

// BuildP2PKH constructs a standard P2PKH locking script for the given 20-byte
// public key hash.
func BuildP2PKH(pubKeyHash []byte) []byte {
	if len(pubKeyHash) != 20 {
		return nil
	}
	script := make([]byte, 25)
	script[0] = opDUP
	script[1] = opHASH160
	script[2] = opPUSH20
	copy(script[3:23], pubKeyHash)
	script[23] = opEQUALVERIFY
	script[24] = opCHECKSIG
	return script
}

// SatoshisToBSV converts satoshis to a human-readable BSV string.
func SatoshisToBSV(satoshis uint64) string {
	whole := satoshis / 100_000_000
	frac := satoshis % 100_000_000
	if frac == 0 {
		return fmt.Sprintf("%d", whole)
	}
	// Format with exactly 8 decimal places, then trim trailing zeros
	// but keep at least one digit after the decimal point.
	s := fmt.Sprintf("%d.%08d", whole, frac)
	return s
}

// BSVToSatoshis parses a BSV amount string and returns the value in satoshis.
// It handles both integer and decimal formats.
func BSVToSatoshis(bsv string) (uint64, error) {
	var whole, frac uint64
	n, err := fmt.Sscanf(bsv, "%d.%08d", &whole, &frac)
	if err != nil || n == 0 {
		// Try integer-only.
		n, err = fmt.Sscanf(bsv, "%d", &whole)
		if err != nil || n == 0 {
			return 0, fmt.Errorf("invalid BSV amount: %s", bsv)
		}
		frac = 0
	}
	return whole*100_000_000 + frac, nil
}
