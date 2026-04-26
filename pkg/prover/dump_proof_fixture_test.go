package prover

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/mpt"
)

// TestDumpProofFixtureForRust generates a deterministic MPT and writes its
// inclusion / exclusion proofs to a binary file consumed by the Rust
// integration test in `prover/proof-verify-test/tests/cross_check.rs`.
// This is the only cross-implementation correctness check binding the Go
// `pkg/mpt` proof producer to the Rust `proof_verify` consumer that the
// SP1 guest uses for the W4-1 / Gate-0 anti-host-trust check.
//
// Skipped under -short. Re-run when either side of the proof format
// changes; the assertion is the file's content equality across runs.
//
// Binary format (all integers little-endian):
//   u32 root_len                 = 32
//   [32]u8 root
//   u32 case_count
//   for each case:
//     u32 key_len; key
//     u8  has_value
//     u32 value_len; value (only if has_value)
//     u32 node_count
//     for each node: u32 node_len; node bytes
func TestDumpProofFixtureForRust(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fixture dump in -short mode")
	}
	tdb := db.NewMemoryDB()
	trieDB := mpt.NewDatabase(tdb)
	tr := mpt.NewEmpty(trieDB)

	type kv struct {
		k, v []byte
	}
	pairs := []kv{
		{[]byte{0x10}, []byte{0xAA}},
		{[]byte{0x20}, []byte{0xBB}},
		{[]byte{0xab, 0xcd, 0x10}, []byte("hello")},
		{[]byte{0xab, 0xcd, 0x20}, []byte("world")},
		{[]byte{0xff, 0xff, 0xff, 0xff}, make([]byte, 64)}, // long value
	}
	for _, p := range pairs {
		if err := tr.Update(p.k, p.v); err != nil {
			t.Fatalf("update: %v", err)
		}
	}
	root := tr.Hash()

	// Inclusion cases plus one exclusion.
	cases := append([]kv(nil), pairs...)
	cases = append(cases, kv{k: []byte{0x99, 0x99, 0x99}, v: nil})

	var buf bytes.Buffer
	writeU32 := func(v uint32) { binary.Write(&buf, binary.LittleEndian, v) }
	writeBytes := func(b []byte) {
		writeU32(uint32(len(b)))
		buf.Write(b)
	}
	writeU32(32)
	buf.Write(root[:])
	writeU32(uint32(len(cases)))

	for _, p := range cases {
		writeBytes(p.k)
		if p.v == nil {
			buf.WriteByte(0)
		} else {
			buf.WriteByte(1)
			writeBytes(p.v)
		}
		// Build proof.
		proofDB := db.NewMemoryDB()
		if err := tr.Prove(p.k, proofDB); err != nil {
			t.Fatalf("prove: %v", err)
		}
		var nodes [][]byte
		it := proofDB.NewIterator(nil, nil)
		for it.Next() {
			n := make([]byte, len(it.Value()))
			copy(n, it.Value())
			nodes = append(nodes, n)
		}
		it.Release()
		writeU32(uint32(len(nodes)))
		for _, n := range nodes {
			writeBytes(n)
		}
	}

	// Locate the worktree root from the test's cwd: pkg/prover -> root.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root2 := filepath.Clean(filepath.Join(cwd, "..", ".."))
	target := filepath.Join(root2, "prover", "proof-verify-test", "tests", "fixture.bin")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote fixture: %s (%d bytes, %d cases)", target, buf.Len(), len(cases))
}
