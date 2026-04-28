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

// TestParseEncodeRoundtrip asserts ParsedBEEF.Encode() is a true
// inverse of ParseBEEF for canonical-encoded inputs: parse, encode,
// parse again, and the resulting structures must compare equal.
//
// Three fixtures are exercised:
//
//   - Synthetic minimal envelope (1 tx, 0 BUMPs) — same shape the
//     bridge happy-path uses.
//   - Synthetic envelope with multiple txs, none with a BUMP — covers
//     the multi-tx encoding path.
//   - SDK-built envelope from buildValidBEEF (verify_test.go) — a real
//     wallet-shape BEEF with a populated BUMP, the only fixture this
//     package owns that exercises the BUMP raw-bytes round-trip.
func TestParseEncodeRoundtrip(t *testing.T) {
	type fixture struct {
		name string
		body []byte
	}
	fixtures := []fixture{
		{"minimal-single-tx", buildSeedSingleTxBEEF()},
		{"two-tx-no-bumps", buildTwoTxBEEF()},
		{"sdk-built-envelope-with-bump", func() []byte {
			body, _, _ := buildValidBEEF(t, 800_042, 6)
			return body
		}()},
	}
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			parsed, err := ParseBEEF(fx.body)
			if err != nil {
				t.Fatalf("ParseBEEF first pass: %v", err)
			}
			encoded := parsed.Encode()
			if len(encoded) == 0 {
				t.Fatalf("Encode produced empty bytes")
			}

			// Re-parse the encoded form and compare.
			roundtripped, err := ParseBEEF(encoded)
			if err != nil {
				t.Fatalf("ParseBEEF on encoded body failed: %v\nbytes=%x", err, encoded)
			}

			if roundtripped.Version != parsed.Version {
				t.Fatalf("version mismatch: got %x want %x", roundtripped.Version, parsed.Version)
			}
			if len(roundtripped.BUMPs) != len(parsed.BUMPs) {
				t.Fatalf("bump count mismatch: got %d want %d",
					len(roundtripped.BUMPs), len(parsed.BUMPs))
			}
			for i := range parsed.BUMPs {
				if parsed.BUMPs[i].BlockHeight != roundtripped.BUMPs[i].BlockHeight {
					t.Errorf("bump %d block height mismatch", i)
				}
				if !bytes.Equal(parsed.BUMPs[i].Raw, roundtripped.BUMPs[i].Raw) {
					t.Errorf("bump %d raw mismatch:\n got  %x\n want %x",
						i, roundtripped.BUMPs[i].Raw, parsed.BUMPs[i].Raw)
				}
			}
			if len(roundtripped.Txs) != len(parsed.Txs) {
				t.Fatalf("tx count mismatch: got %d want %d",
					len(roundtripped.Txs), len(parsed.Txs))
			}
			for i := range parsed.Txs {
				if parsed.Txs[i].TxID != roundtripped.Txs[i].TxID {
					t.Errorf("tx %d txid mismatch", i)
				}
				if !bytes.Equal(parsed.Txs[i].RawTx, roundtripped.Txs[i].RawTx) {
					t.Errorf("tx %d raw mismatch", i)
				}
				if parsed.Txs[i].HasBUMP != roundtripped.Txs[i].HasBUMP {
					t.Errorf("tx %d has-bump mismatch", i)
				}
				if parsed.Txs[i].BUMPRef != roundtripped.Txs[i].BUMPRef {
					t.Errorf("tx %d bump ref mismatch", i)
				}
			}
			if parsed.TargetID != roundtripped.TargetID {
				t.Errorf("target ID mismatch")
			}
		})
	}
}

// buildTwoTxBEEF returns a hand-built two-tx envelope used by the
// roundtrip test to exercise the multi-tx encoding path.
func buildTwoTxBEEF() []byte {
	tx1 := buildMinimalTx()
	tx2 := buildMinimalTx()
	var beef bytes.Buffer
	binary.Write(&beef, binary.LittleEndian, uint32(beefMagicV1))
	beef.WriteByte(0x00) // 0 bumps
	beef.WriteByte(0x02) // 2 txs
	beef.Write(tx1)
	beef.WriteByte(0x00) // tx1 has-bump = 0
	beef.Write(tx2)
	beef.WriteByte(0x00) // tx2 has-bump = 0
	return beef.Bytes()
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
