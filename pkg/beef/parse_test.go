package beef

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// buildMinimalTx builds a syntactically-valid 1-input 1-output BSV tx
// for parser tests. Inputs and outputs use empty scripts so the wire
// length is predictable.
func buildMinimalTx() []byte {
	var b bytes.Buffer
	// version
	b.Write([]byte{1, 0, 0, 0})
	// 1 input
	b.WriteByte(0x01)
	prevTxid := bytes.Repeat([]byte{0xaa}, 32)
	b.Write(prevTxid)
	b.Write([]byte{0, 0, 0, 0}) // vout
	b.WriteByte(0x00)           // empty unlocking script
	b.Write([]byte{0xff, 0xff, 0xff, 0xff})
	// 1 output
	b.WriteByte(0x01)
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, 1000)
	b.Write(val)
	b.WriteByte(0x00) // empty locking script
	// locktime
	b.Write([]byte{0, 0, 0, 0})
	return b.Bytes()
}

func TestParseBEEFEmptyBumps(t *testing.T) {
	txBody := buildMinimalTx()
	var beef bytes.Buffer
	// magic V1
	binary.Write(&beef, binary.LittleEndian, uint32(beefMagicV1))
	// 0 BUMPs
	beef.WriteByte(0x00)
	// 1 tx
	beef.WriteByte(0x01)
	beef.Write(txBody)
	// has-bump flag = 0
	beef.WriteByte(0x00)

	parsed, err := ParseBEEF(beef.Bytes())
	if err != nil {
		t.Fatalf("ParseBEEF: %v", err)
	}
	if len(parsed.Txs) != 1 {
		t.Fatalf("got %d txs, want 1", len(parsed.Txs))
	}
	t1 := parsed.Target()
	if t1 == nil {
		t.Fatal("nil target")
	}
	a := sha256.Sum256(txBody)
	want := sha256.Sum256(a[:])
	if t1.TxID != want {
		t.Fatalf("txid mismatch")
	}
}

func TestParseBEEFBadMagic(t *testing.T) {
	if _, err := ParseBEEF([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseBEEFTruncated(t *testing.T) {
	if _, err := ParseBEEF([]byte{0xef, 0xbe}); err == nil {
		t.Fatal("expected error")
	}
}

func TestReadVarInt(t *testing.T) {
	cases := []struct {
		buf  []byte
		want uint64
		n    int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0xfd, 0x00, 0x01}, 256, 3},
		{[]byte{0xfe, 0x00, 0x00, 0x01, 0x00}, 65536, 5},
		{[]byte{0xff, 1, 0, 0, 0, 0, 0, 0, 0}, 1, 9},
	}
	for _, c := range cases {
		v, n, err := readVarInt(c.buf)
		if err != nil || v != c.want || n != c.n {
			t.Fatalf("%v: got %d/%d/%v want %d/%d", c.buf, v, n, err, c.want, c.n)
		}
	}
}
