package covenant

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/icellan/bsvm/pkg/types"
)

// BSVTx represents a raw BSV transaction for serialization.
type BSVTx struct {
	Version  uint32
	Inputs   []BSVInput
	Outputs  []BSVOutput
	LockTime uint32
}

// BSVInput represents a transaction input.
type BSVInput struct {
	PrevTxID types.Hash
	PrevVout uint32
	Script   []byte
	Sequence uint32
}

// BSVOutput represents a transaction output.
type BSVOutput struct {
	Value  uint64
	Script []byte
}

// Serialize serializes the transaction in BSV wire format.
// Format: version(4 LE) + varint(inputs) + inputs + varint(outputs) + outputs + locktime(4 LE)
func (tx *BSVTx) Serialize() []byte {
	buf := make([]byte, 0, 256)

	// Version (4 bytes, little-endian).
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, tx.Version)
	buf = append(buf, v...)

	// Input count.
	buf = append(buf, writeVarInt(uint64(len(tx.Inputs)))...)

	// Inputs.
	for _, in := range tx.Inputs {
		// Previous tx hash (32 bytes, internal byte order — not reversed).
		buf = append(buf, in.PrevTxID[:]...)
		// Previous output index (4 bytes, little-endian).
		idx := make([]byte, 4)
		binary.LittleEndian.PutUint32(idx, in.PrevVout)
		buf = append(buf, idx...)
		// Script length + script.
		buf = append(buf, writeVarInt(uint64(len(in.Script)))...)
		buf = append(buf, in.Script...)
		// Sequence (4 bytes, little-endian).
		seq := make([]byte, 4)
		binary.LittleEndian.PutUint32(seq, in.Sequence)
		buf = append(buf, seq...)
	}

	// Output count.
	buf = append(buf, writeVarInt(uint64(len(tx.Outputs)))...)

	// Outputs.
	for _, out := range tx.Outputs {
		// Value (8 bytes, little-endian).
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, out.Value)
		buf = append(buf, val...)
		// Script length + script.
		buf = append(buf, writeVarInt(uint64(len(out.Script)))...)
		buf = append(buf, out.Script...)
	}

	// Lock time (4 bytes, little-endian).
	lt := make([]byte, 4)
	binary.LittleEndian.PutUint32(lt, tx.LockTime)
	buf = append(buf, lt...)

	return buf
}

// TxID computes the double-SHA256 hash of the serialized transaction.
// The result is byte-reversed per Bitcoin convention (little-endian txid).
func (tx *BSVTx) TxID() types.Hash {
	raw := tx.Serialize()
	first := sha256.Sum256(raw)
	second := sha256.Sum256(first[:])
	// Reverse for display convention.
	var txid types.Hash
	for i := 0; i < 32; i++ {
		txid[i] = second[31-i]
	}
	return txid
}

// writeVarInt encodes a uint64 as a Bitcoin variable-length integer.
func writeVarInt(v uint64) []byte {
	switch {
	case v < 0xfd:
		return []byte{byte(v)}
	case v <= 0xffff:
		buf := make([]byte, 3)
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:], uint16(v))
		return buf
	case v <= 0xffffffff:
		buf := make([]byte, 5)
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:], uint32(v))
		return buf
	default:
		buf := make([]byte, 9)
		buf[0] = 0xff
		binary.LittleEndian.PutUint64(buf[1:], v)
		return buf
	}
}

// buildOpReturnScript creates an OP_FALSE OP_RETURN script with the given data.
// Format: 0x00 (OP_FALSE) 0x6a (OP_RETURN) + pushdata(data)
func buildOpReturnScript(data []byte) []byte {
	script := []byte{0x00, 0x6a}
	script = append(script, pushData(data)...)
	return script
}

// pushData encodes data as a Bitcoin Script push operation (standard encoding
// used for OP_RETURN payloads and similar contexts).
func pushData(data []byte) []byte {
	l := len(data)
	switch {
	case l <= 75:
		return append([]byte{byte(l)}, data...)
	case l <= 255:
		return append([]byte{0x4c, byte(l)}, data...)
	case l <= 65535:
		buf := []byte{0x4d, 0, 0}
		binary.LittleEndian.PutUint16(buf[1:], uint16(l))
		return append(buf, data...)
	default:
		buf := []byte{0x4e, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(buf[1:], uint32(l))
		return append(buf, data...)
	}
}
