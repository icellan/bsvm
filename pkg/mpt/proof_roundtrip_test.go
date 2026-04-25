// Copyright 2026 The BSVM Authors.
// Thorough proof roundtrip and trie equivalence tests.

package mpt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

// buildTrie builds a Trie from the given (key, value) pairs and returns it
// along with its root hash. The trie is NOT committed so proofs can be
// generated from the in-memory structure.
func buildTrie(t *testing.T, kvs [][2][]byte) (*Trie, types.Hash) {
	t.Helper()
	tr := NewEmpty(newTestDB())
	for _, kv := range kvs {
		if err := tr.Update(kv[0], kv[1]); err != nil {
			t.Fatalf("update failed: %v", err)
		}
	}
	return tr, tr.Hash()
}

// randomKVs produces n deterministic-looking random (32-byte key, 32-byte value)
// pairs. Dedup is performed so no collisions exist.
func randomKVs(n int) [][2][]byte {
	out := make([][2][]byte, 0, n)
	seen := make(map[string]struct{}, n)
	for len(out) < n {
		var k, v [32]byte
		_, _ = rand.Read(k[:])
		_, _ = rand.Read(v[:])
		if _, ok := seen[string(k[:])]; ok {
			continue
		}
		seen[string(k[:])] = struct{}{}
		// Value must be non-empty; 32 random bytes essentially never is.
		out = append(out, [2][]byte{k[:], v[:]})
	}
	return out
}

// proofDBNodeCount returns the number of proof nodes stored in the MemoryDB.
func proofDBNodeCount(m *db.MemoryDB) int {
	return m.Len()
}

// ------------------------------------------------------------------
// 1. Inclusion proofs
// ------------------------------------------------------------------

func TestInclusionProofs(t *testing.T) {
	sizes := []int{1, 10, 100, 1000}
	for _, n := range sizes {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			kvs := randomKVs(n)
			tr, root := buildTrie(t, kvs)

			for i, kv := range kvs {
				proof := db.NewMemoryDB()
				if err := tr.Prove(kv[0], proof); err != nil {
					t.Fatalf("prove key %d: %v", i, err)
				}
				if proofDBNodeCount(proof) == 0 {
					t.Fatalf("proof for key %d is empty", i)
				}

				// Happy path.
				got, err := VerifyProof(root, kv[0], proof)
				if err != nil {
					t.Fatalf("verify key %d: %v", i, err)
				}
				if !bytes.Equal(got, kv[1]) {
					t.Fatalf("key %d: verified value mismatch, want %x got %x", i, kv[1], got)
				}

				// Sub-sample for tampering (full sweep is quadratic and slow).
				if n > 50 && i%(n/20) != 0 {
					continue
				}

				// Tamper: for each proof node, flip one byte and verify that
				// at least one such mutation makes the proof fail to return
				// the correct value (either errors out from a hash mismatch
				// OR returns a different value). A tampered leaf-value alone
				// may decode fine and return wrong bytes; a tampered interior
				// node will fail the next-hop hash lookup.
				if !anyTamperDetected(t, proof, root, kv[0], kv[1]) {
					t.Fatalf("key %d: no single-byte tamper of the proof was detected", i)
				}
			}
		})
	}
}

// anyTamperDetected iterates over every node in the proof DB and for each
// one produces a one-byte-flipped copy of the DB. It returns true as soon as
// some tampering causes VerifyProof either to error out OR to return a value
// that does not equal the original. Returns false if *every* single-byte
// flip leaves the original value intact (which would be a red flag).
func anyTamperDetected(t *testing.T, src *db.MemoryDB, root types.Hash, key, origValue []byte) bool {
	t.Helper()

	// Snapshot (k, v) pairs.
	type kvPair struct {
		k, v []byte
	}
	var pairs []kvPair
	it := src.NewIterator(nil, nil)
	for it.Next() {
		kk := make([]byte, len(it.Key()))
		vv := make([]byte, len(it.Value()))
		copy(kk, it.Key())
		copy(vv, it.Value())
		pairs = append(pairs, kvPair{kk, vv})
	}
	it.Release()
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].k, pairs[j].k) < 0 })

	if len(pairs) == 0 {
		t.Fatalf("proof DB is empty — cannot tamper")
	}

	// For each proof node, try flipping either the first or last byte.
	for idx := range pairs {
		for _, flipPos := range []int{0, len(pairs[idx].v) - 1} {
			if flipPos < 0 {
				continue
			}
			cand := db.NewMemoryDB()
			for j, p := range pairs {
				v := make([]byte, len(p.v))
				copy(v, p.v)
				if j == idx && len(v) > 0 {
					v[flipPos] ^= 0x01
				}
				if err := cand.Put(p.k, v); err != nil {
					t.Fatalf("copy proof db: %v", err)
				}
			}
			got, err := VerifyProof(root, key, cand)
			if err != nil {
				return true
			}
			if !bytes.Equal(got, origValue) {
				return true
			}
		}
	}
	return false
}

// VerifyProof returns (nil, nil) when the claimed value is absent. For a
// present key, supplying a bogus expected value is a caller-side check: we
// verify it returns the REAL value, and that real != bogus.
func TestInclusionProofWrongValueDetected(t *testing.T) {
	kvs := randomKVs(50)
	tr, root := buildTrie(t, kvs)
	for _, kv := range kvs[:5] {
		proof := db.NewMemoryDB()
		if err := tr.Prove(kv[0], proof); err != nil {
			t.Fatalf("prove: %v", err)
		}
		got, err := VerifyProof(root, kv[0], proof)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		bogus := make([]byte, len(kv[1]))
		copy(bogus, kv[1])
		bogus[0] ^= 0xff
		if bytes.Equal(got, bogus) {
			t.Fatalf("proof returned bogus value (expected to differ)")
		}
		if !bytes.Equal(got, kv[1]) {
			t.Fatalf("proof returned wrong value: want %x got %x", kv[1], got)
		}
	}
}

// ------------------------------------------------------------------
// 2. Exclusion proofs
// ------------------------------------------------------------------

func TestExclusionProofs(t *testing.T) {
	n := 1000
	kvs := randomKVs(n)
	tr, root := buildTrie(t, kvs)

	// Set of present keys for quick membership check.
	present := make(map[string]struct{}, n)
	for _, kv := range kvs {
		present[string(kv[0])] = struct{}{}
	}

	// Build a handful of absent keys.
	absent := make([][]byte, 0, 20)
	for len(absent) < 20 {
		var k [32]byte
		_, _ = rand.Read(k[:])
		if _, ok := present[string(k[:])]; ok {
			continue
		}
		absent = append(absent, k[:])
	}

	// An exclusion proof over a trie with n leaves should contain O(log n)
	// nodes. For n=1000 with 16-ary branching that is well under 32.
	const bound = 32

	for i, k := range absent {
		proof := db.NewMemoryDB()
		if err := tr.Prove(k, proof); err != nil {
			t.Fatalf("prove absent key %d: %v", i, err)
		}
		got, err := VerifyProof(root, k, proof)
		if err != nil {
			t.Fatalf("verify absent key %d: %v", i, err)
		}
		if got != nil {
			t.Fatalf("absent key %d: expected nil value, got %x", i, got)
		}
		if c := proofDBNodeCount(proof); c > bound {
			t.Fatalf("exclusion proof too large for N=%d: %d nodes (bound %d)", n, c, bound)
		}
	}
}

// ------------------------------------------------------------------
// 3. Key encoding edge cases
// ------------------------------------------------------------------

func TestProofKeyEncodingEdgeCases(t *testing.T) {
	type tc struct {
		name string
		key  []byte
		val  []byte
	}

	// Note: the raw Trie allows an empty key, the stacktrie does not (it
	// panics when indexing). Empty key is exercised here only for Trie/Proof.
	emptyKey := []byte{}
	singleByte := []byte{0xab}
	bigKey := make([]byte, 32)
	for i := range bigKey {
		bigKey[i] = byte(i * 7)
	}
	cases := []tc{
		{"empty-key", emptyKey, []byte("root-value")},
		{"single-byte", singleByte, []byte("sb-value")},
		{"thirty-two-byte", bigKey, []byte("long-key-value")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewEmpty(newTestDB())
			if err := tr.Update(c.key, c.val); err != nil {
				t.Fatalf("update: %v", err)
			}
			root := tr.Hash()
			proof := db.NewMemoryDB()
			if err := tr.Prove(c.key, proof); err != nil {
				t.Fatalf("prove: %v", err)
			}
			got, err := VerifyProof(root, c.key, proof)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !bytes.Equal(got, c.val) {
				t.Fatalf("want %x got %x", c.val, got)
			}
		})
	}

	// Common-prefix keys (forces an extension node).
	t.Run("common-prefix", func(t *testing.T) {
		pairs := [][2][]byte{
			{[]byte("abcdefghij0000"), []byte("v0")},
			{[]byte("abcdefghij1111"), []byte("v1")},
			{[]byte("abcdefghij2222"), []byte("v2")},
			{[]byte("abcdefghij3333"), []byte("v3")},
		}
		tr, root := buildTrie(t, pairs)
		for _, kv := range pairs {
			proof := db.NewMemoryDB()
			if err := tr.Prove(kv[0], proof); err != nil {
				t.Fatalf("prove: %v", err)
			}
			got, err := VerifyProof(root, kv[0], proof)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !bytes.Equal(got, kv[1]) {
				t.Fatalf("want %x got %x", kv[1], got)
			}
		}
	})

	// Keys that differ in last nibble only (forces a deep branch).
	t.Run("differ-last-nibble", func(t *testing.T) {
		// Same 31 bytes, last byte varies in its low nibble.
		base := make([]byte, 32)
		_, _ = rand.Read(base)
		pairs := make([][2][]byte, 0, 4)
		for _, nib := range []byte{0x00, 0x01, 0x0a, 0x0f} {
			k := make([]byte, 32)
			copy(k, base)
			k[31] = (base[31] & 0xf0) | nib
			v := []byte{nib}
			pairs = append(pairs, [2][]byte{k, v})
		}
		tr, root := buildTrie(t, pairs)
		for _, kv := range pairs {
			proof := db.NewMemoryDB()
			if err := tr.Prove(kv[0], proof); err != nil {
				t.Fatalf("prove: %v", err)
			}
			got, err := VerifyProof(root, kv[0], proof)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !bytes.Equal(got, kv[1]) {
				t.Fatalf("want %x got %x", kv[1], got)
			}
		}
	})
}

// ------------------------------------------------------------------
// 4. Determinism
// ------------------------------------------------------------------

func TestTrieInsertOrderIndependence(t *testing.T) {
	const n = 500
	kvs := randomKVs(n)

	tr1, _ := buildTrie(t, kvs)

	reversed := make([][2][]byte, n)
	for i, kv := range kvs {
		reversed[n-1-i] = kv
	}
	tr2, _ := buildTrie(t, reversed)

	if tr1.Hash() != tr2.Hash() {
		h1, h2 := tr1.Hash(), tr2.Hash()
		t.Fatalf("forward vs reverse insert order differ: %x vs %x", h1.Bytes(), h2.Bytes())
	}
}

// StackTrie vs Trie vs StateTrie must all agree on the root for the same
// key/value set. StackTrie requires sorted, deduplicated insertion. StateTrie
// hashes keys, so we compare it against a Trie that uses the *hashed* keys
// rather than the raw ones.
func TestStackTrieSecureTrieTrieEquivalence(t *testing.T) {
	const n = 300
	kvs := randomKVs(n)

	// --- Plain Trie vs StackTrie on raw keys ---
	sorted := make([][2][]byte, len(kvs))
	copy(sorted, kvs)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][0], sorted[j][0]) < 0 })

	tr := NewEmpty(newTestDB())
	st := NewStackTrie(nil)
	for _, kv := range sorted {
		if err := tr.Update(kv[0], kv[1]); err != nil {
			t.Fatalf("trie update: %v", err)
		}
		if err := st.Update(kv[0], kv[1]); err != nil {
			t.Fatalf("stacktrie update: %v", err)
		}
	}
	if tr.Hash() != st.Hash() {
		trH, stH := tr.Hash(), st.Hash()
		t.Fatalf("Trie root %x != StackTrie root %x", trH.Bytes(), stH.Bytes())
	}

	// --- StateTrie (hashed keys) vs Trie on explicitly hashed keys ---
	trieDB := newTestDB()
	sec, err := NewSecureTrie(types.EmptyRootHash, trieDB)
	if err != nil {
		t.Fatalf("NewSecureTrie: %v", err)
	}
	hashedTrie := NewEmpty(newTestDB())
	for _, kv := range kvs {
		if err := sec.Update(kv[0], kv[1]); err != nil {
			t.Fatalf("secure update: %v", err)
		}
		hk := crypto.Keccak256(kv[0])
		if err := hashedTrie.Update(hk, kv[1]); err != nil {
			t.Fatalf("hashed trie update: %v", err)
		}
	}
	if sec.Hash() != hashedTrie.Hash() {
		secH, htH := sec.Hash(), hashedTrie.Hash()
		t.Fatalf("StateTrie root %x != manually-hashed Trie root %x", secH.Bytes(), htH.Bytes())
	}

	// Also feed the StackTrie with the pre-hashed keys (sorted) and check it
	// matches the StateTrie — this is how DeriveSha-style and range-proof
	// code relies on the three implementations agreeing.
	hashedPairs := make([][2][]byte, len(kvs))
	for i, kv := range kvs {
		hk := crypto.Keccak256(kv[0])
		hashedPairs[i] = [2][]byte{hk, kv[1]}
	}
	sort.Slice(hashedPairs, func(i, j int) bool {
		return bytes.Compare(hashedPairs[i][0], hashedPairs[j][0]) < 0
	})
	sth := NewStackTrie(nil)
	for _, kv := range hashedPairs {
		if err := sth.Update(kv[0], kv[1]); err != nil {
			t.Fatalf("stacktrie hashed update: %v", err)
		}
	}
	if sth.Hash() != sec.Hash() {
		sthH, secH := sth.Hash(), sec.Hash()
		t.Fatalf("StackTrie(hashed) root %x != StateTrie root %x", sthH.Bytes(), secH.Bytes())
	}
}

// ------------------------------------------------------------------
// 5. DeriveSha
// ------------------------------------------------------------------

// byteSliceList is a DerivableList over a slice of byte slices.
type byteSliceList [][]byte

func (l byteSliceList) Len() int { return len(l) }
func (l byteSliceList) EncodeIndex(i int, buf *bytes.Buffer) {
	// Items are RLP-encoded byte strings.
	b, _ := rlp.EncodeToBytes(l[i])
	buf.Write(b)
}

// emptyList is a list with zero entries.
type emptyList struct{}

func (emptyList) Len() int                       { return 0 }
func (emptyList) EncodeIndex(int, *bytes.Buffer) {}

func TestDeriveShaEmptyMatchesKeccakOfRLPEmpty(t *testing.T) {
	got := DeriveSha(emptyList{})
	if got != types.EmptyRootHash {
		er := types.EmptyRootHash
		t.Fatalf("DeriveSha(empty) = %x, want EmptyRootHash %x",
			got.Bytes(), er.Bytes())
	}
	// Cross-check the published constant value: keccak256(rlp("")).
	rlpEmpty, _ := rlp.EncodeToBytes([]byte{})
	kh := crypto.Keccak256(rlpEmpty)
	wantHex := "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
	if fmt.Sprintf("%x", kh) != wantHex {
		t.Fatalf("keccak256(rlp(\"\")) mismatch: got %x want %s", kh, wantHex)
	}
	constHex := fmt.Sprintf("%x", types.EmptyRootHash.Bytes())
	if constHex != wantHex {
		t.Fatalf("EmptyRootHash constant mismatch: %s vs %s", constHex, wantHex)
	}
}

// Internal consistency check: DeriveSha over {1, 10, 1000} items must match
// a Trie built with the exact same (key = RLP(index), value = encoded item)
// pairs. This is the structural guarantee we need even without a geth vendor
// to compare against.
func TestDeriveShaMatchesTrie(t *testing.T) {
	for _, n := range []int{1, 10, 1000} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			items := make([][]byte, n)
			for i := 0; i < n; i++ {
				// Deterministic per-index payload.
				buf := make([]byte, 8)
				binary.BigEndian.PutUint64(buf, uint64(i))
				items[i] = buf
			}
			derived := DeriveSha(byteSliceList(items))

			// Build reference via Trie with the same {key, value} pairs.
			tr := NewEmpty(newTestDB())
			var valBuf bytes.Buffer
			for i := 0; i < n; i++ {
				key, _ := rlp.EncodeToBytes(uint64(i))
				valBuf.Reset()
				byteSliceList(items).EncodeIndex(i, &valBuf)
				if err := tr.Update(key, valBuf.Bytes()); err != nil {
					t.Fatalf("update: %v", err)
				}
			}
			ref := tr.Hash()
			if derived != ref {
				t.Fatalf("DeriveSha != Trie root for N=%d: %x vs %x",
					n, derived.Bytes(), ref.Bytes())
			}
		})
	}
}

// ------------------------------------------------------------------
// 6. Stress: 10k random keys
// ------------------------------------------------------------------

func TestStressTenThousandKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}
	const n = 10000
	kvs := randomKVs(n)

	start := time.Now()
	tr, root := buildTrie(t, kvs)
	buildElapsed := time.Since(start)

	// All keys reachable.
	for i, kv := range kvs {
		got, err := tr.Get(kv[0])
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if !bytes.Equal(got, kv[1]) {
			t.Fatalf("get %d: want %x got %x", i, kv[1], got)
		}
	}

	// All proofs verify. Don't prove every key (that's quadratic with the
	// trie-walk cost); 1000 random samples is ample.
	const samples = 1000
	step := n / samples
	proveStart := time.Now()
	for i := 0; i < n; i += step {
		kv := kvs[i]
		proof := db.NewMemoryDB()
		if err := tr.Prove(kv[0], proof); err != nil {
			t.Fatalf("prove %d: %v", i, err)
		}
		got, err := VerifyProof(root, kv[0], proof)
		if err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
		if !bytes.Equal(got, kv[1]) {
			t.Fatalf("verify %d: want %x got %x", i, kv[1], got)
		}
	}
	proveElapsed := time.Since(proveStart)
	total := time.Since(start)

	t.Logf("10k stress: build=%s, sample-prove/verify(x%d)=%s, total=%s",
		buildElapsed, samples, proveElapsed, total)

	// Soft time budget.
	if total > 5*time.Second {
		t.Logf("WARNING: stress test exceeded 5s budget: %s", total)
	}
}

// ------------------------------------------------------------------
// 7. Iterator determinism
// ------------------------------------------------------------------

// The trie iterator must produce keys in lexicographic order, and the order
// must not depend on insertion order. Build the same data in two orders and
// compare the iterator outputs byte-for-byte.
func TestIteratorDeterminism(t *testing.T) {
	const n = 300
	kvs := randomKVs(n)

	collect := func(tr *Trie) [][2][]byte {
		var out [][2][]byte
		it := NewIterator(tr.MustNodeIterator(nil))
		for it.Next() {
			k := make([]byte, len(it.Key))
			v := make([]byte, len(it.Value))
			copy(k, it.Key)
			copy(v, it.Value)
			out = append(out, [2][]byte{k, v})
		}
		if it.Err != nil {
			t.Fatalf("iterator err: %v", it.Err)
		}
		return out
	}

	tr1 := NewEmpty(newTestDB())
	for _, kv := range kvs {
		tr1.MustUpdate(kv[0], kv[1])
	}
	tr2 := NewEmpty(newTestDB())
	for i := n - 1; i >= 0; i-- {
		tr2.MustUpdate(kvs[i][0], kvs[i][1])
	}

	o1 := collect(tr1)
	o2 := collect(tr2)

	if len(o1) != n || len(o2) != n {
		t.Fatalf("iterator yielded wrong count: %d / %d (want %d)", len(o1), len(o2), n)
	}
	for i := 0; i < n; i++ {
		if !bytes.Equal(o1[i][0], o2[i][0]) || !bytes.Equal(o1[i][1], o2[i][1]) {
			t.Fatalf("iterator order differs at %d: %x vs %x", i, o1[i][0], o2[i][0])
		}
		if i > 0 && bytes.Compare(o1[i-1][0], o1[i][0]) >= 0 {
			t.Fatalf("iterator not lexicographic at %d: %x then %x", i, o1[i-1][0], o1[i][0])
		}
	}

	// Also must match a sorted sweep of the input.
	expected := make([][2][]byte, len(kvs))
	copy(expected, kvs)
	sort.Slice(expected, func(i, j int) bool { return bytes.Compare(expected[i][0], expected[j][0]) < 0 })
	for i, kv := range expected {
		if !bytes.Equal(o1[i][0], kv[0]) || !bytes.Equal(o1[i][1], kv[1]) {
			t.Fatalf("iterator mismatch vs sorted input at %d", i)
		}
	}
}
