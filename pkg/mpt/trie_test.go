// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Adapted for github.com/icellan/bsvm.

package mpt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sort"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

func newTestDB() *Database {
	return NewDatabase(db.NewMemoryDB())
}

func TestEmptyTrie(t *testing.T) {
	trie := NewEmpty(newTestDB())
	res := trie.Hash()
	exp := types.EmptyRootHash
	if res != exp {
		t.Errorf("expected %x got %x", exp, res)
	}
}

func TestNull(t *testing.T) {
	trie := NewEmpty(newTestDB())
	key := make([]byte, 32)
	value := []byte("test")
	trie.MustUpdate(key, value)
	if !bytes.Equal(trie.MustGet(key), value) {
		t.Fatal("wrong value")
	}
}

func TestMissingRoot(t *testing.T) {
	root := types.HexToHash("0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33")
	trie, err := New(TrieID(root), newTestDB())
	if trie != nil {
		t.Error("New returned non-nil trie for invalid root")
	}
	if _, ok := err.(*MissingNodeError); !ok {
		t.Errorf("New returned wrong error: %v", err)
	}
}

func TestInsert(t *testing.T) {
	trie := NewEmpty(newTestDB())
	updateString(trie, "doe", "reindeer")
	updateString(trie, "dog", "puppy")
	updateString(trie, "dogglesworth", "cat")

	root := trie.Hash()
	if root == types.EmptyRootHash {
		t.Error("case 1: root should not be empty")
	}

	// Verify the root is deterministic.
	trie2 := NewEmpty(newTestDB())
	updateString(trie2, "doe", "reindeer")
	updateString(trie2, "dog", "puppy")
	updateString(trie2, "dogglesworth", "cat")
	if trie2.Hash() != root {
		t.Errorf("case 1: determinism failure, got different roots")
	}

	trie3 := NewEmpty(newTestDB())
	updateString(trie3, "A", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	root3 := trie3.Hash()
	if root3 == types.EmptyRootHash {
		t.Error("case 2: root should not be empty")
	}
	if root3 == root {
		t.Error("case 2: different data should produce different roots")
	}
}

func TestGet(t *testing.T) {
	trie := NewEmpty(newTestDB())
	updateString(trie, "doe", "reindeer")
	updateString(trie, "dog", "puppy")
	updateString(trie, "dogglesworth", "cat")

	res := getString(trie, "dog")
	if !bytes.Equal(res, []byte("puppy")) {
		t.Errorf("expected puppy got %x", res)
	}
	unknown := getString(trie, "unknown")
	if unknown != nil {
		t.Errorf("expected nil got %x", unknown)
	}

	// After commit, the trie is no longer usable (geth semantics).
	// Verify that commit + reopen works.
	trieDB := newTestDB()
	trie2 := NewEmpty(trieDB)
	updateString(trie2, "doe", "reindeer")
	updateString(trie2, "dog", "puppy")
	updateString(trie2, "dogglesworth", "cat")
	root, nodes, err := trie2.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	trieDB.CommitNodeSet(nodes)
	trieDB.Commit(root)

	trie3, err := New(TrieID(root), trieDB)
	if err != nil {
		t.Fatal(err)
	}
	res3 := getString(trie3, "dog")
	if !bytes.Equal(res3, []byte("puppy")) {
		t.Errorf("after reopen: expected puppy got %x", res3)
	}
}

func TestDelete(t *testing.T) {
	trie := NewEmpty(newTestDB())
	vals := []struct{ k, v string }{
		{"do", "verb"},
		{"ether", "wbn"},
		{"horse", "stallion"},
		{"shaman", "horse"},
		{"doge", "coin"},
		{"dog", "puppy"},
		{"somethingveryoddindeedthis is", "myothernodedata"},
	}
	for _, val := range vals {
		if val.v != "" {
			updateString(trie, val.k, val.v)
		} else {
			deleteString(trie, val.k)
		}
	}

	hash := trie.Hash()
	deleteString(trie, "dog")
	if v := getString(trie, "dog"); v != nil {
		t.Errorf("expected nil got %x", v)
	}
	// Ensure hash changed after deletion.
	if trie.Hash() == hash {
		t.Error("hash did not change after deletion")
	}
}

func TestDeleteLargeKey(t *testing.T) {
	trie := NewEmpty(newTestDB())
	key := make([]byte, 32)
	value := []byte("test")
	trie.MustUpdate(key, value)
	if !bytes.Equal(trie.MustGet(key), value) {
		t.Fatal("wrong value")
	}
	trie.MustDelete(key)
	if v := trie.MustGet(key); v != nil {
		t.Fatalf("expected nil, got %x", v)
	}
}

func TestCommitReopen(t *testing.T) {
	trieDB := newTestDB()
	trie := NewEmpty(trieDB)

	updateString(trie, "doe", "reindeer")
	updateString(trie, "dog", "puppy")
	updateString(trie, "dogglesworth", "cat")

	root, nodes, err := trie.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	trieDB.CommitNodeSet(nodes)
	trieDB.Commit(root)

	// Re-open the trie from disk.
	trie2, err := New(TrieID(root), trieDB)
	if err != nil {
		t.Fatal(err)
	}
	if v := getString(trie2, "dog"); !bytes.Equal(v, []byte("puppy")) {
		t.Errorf("expected puppy got %x", v)
	}
}

func TestLargeValueCommitReopen(t *testing.T) {
	trieDB := newTestDB()
	trie := NewEmpty(trieDB)

	// Insert a large value
	key := make([]byte, 32)
	value := make([]byte, 100)
	rand.Read(key)
	rand.Read(value)

	trie.MustUpdate(key, value)
	root, nodes, err := trie.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	trieDB.CommitNodeSet(nodes)
	trieDB.Commit(root)

	// Re-open and verify
	trie2, err := New(TrieID(root), trieDB)
	if err != nil {
		t.Fatal(err)
	}
	got, err := trie2.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("value mismatch after reopen")
	}
}

func TestRandomInsertGet(t *testing.T) {
	trie := NewEmpty(newTestDB())

	const N = 500
	keys := make([][]byte, N)
	vals := make([][]byte, N)
	for i := 0; i < N; i++ {
		k := make([]byte, 32)
		rand.Read(k)
		v := make([]byte, 8)
		binary.BigEndian.PutUint64(v, uint64(i))
		keys[i] = k
		vals[i] = v
		trie.MustUpdate(k, v)
	}

	for i := 0; i < N; i++ {
		got := trie.MustGet(keys[i])
		if !bytes.Equal(got, vals[i]) {
			t.Fatalf("key %d: expected %x got %x", i, vals[i], got)
		}
	}
}

func TestRandomInsertDeleteGet(t *testing.T) {
	trie := NewEmpty(newTestDB())

	const N = 500
	keys := make([][]byte, N)
	vals := make([][]byte, N)
	for i := 0; i < N; i++ {
		k := make([]byte, 32)
		rand.Read(k)
		v := make([]byte, 8)
		binary.BigEndian.PutUint64(v, uint64(i))
		keys[i] = k
		vals[i] = v
		trie.MustUpdate(k, v)
	}

	// Delete every other key.
	for i := 0; i < N; i += 2 {
		trie.MustDelete(keys[i])
	}

	// Verify.
	for i := 0; i < N; i++ {
		got := trie.MustGet(keys[i])
		if i%2 == 0 {
			if got != nil {
				t.Fatalf("key %d should be deleted, got %x", i, got)
			}
		} else {
			if !bytes.Equal(got, vals[i]) {
				t.Fatalf("key %d: expected %x got %x", i, vals[i], got)
			}
		}
	}
}

func TestDeterminism(t *testing.T) {
	// Insert the same data in different order and verify identical roots.
	const N = 100
	keys := make([][]byte, N)
	vals := make([][]byte, N)
	for i := 0; i < N; i++ {
		k := make([]byte, 32)
		rand.Read(k)
		v := make([]byte, 8)
		binary.BigEndian.PutUint64(v, uint64(i))
		keys[i] = k
		vals[i] = v
	}

	trie1 := NewEmpty(newTestDB())
	for i := 0; i < N; i++ {
		trie1.MustUpdate(keys[i], vals[i])
	}

	// Insert in reverse order.
	trie2 := NewEmpty(newTestDB())
	for i := N - 1; i >= 0; i-- {
		trie2.MustUpdate(keys[i], vals[i])
	}

	if trie1.Hash() != trie2.Hash() {
		t.Error("tries with same data but different insertion order have different roots")
	}
}

func TestSecureTrie(t *testing.T) {
	trieDB := newTestDB()
	st, err := NewSecureTrie(types.EmptyRootHash, trieDB)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("some-key")
	value := []byte("some-value")
	st.Update(key, value)

	got, err := st.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("expected %x got %x", value, got)
	}

	root, nodes, err := st.Commit(false)
	if err != nil {
		t.Fatal(err)
	}
	trieDB.CommitNodeSet(nodes)
	trieDB.Commit(root)

	// Re-open.
	st2, err := NewSecureTrie(root, trieDB)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := st2.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, value) {
		t.Errorf("after reopen: expected %x got %x", value, got2)
	}
}

func TestSecureTrieDelete(t *testing.T) {
	trieDB := newTestDB()
	st, err := NewSecureTrie(types.EmptyRootHash, trieDB)
	if err != nil {
		t.Fatal(err)
	}
	st.Update([]byte("key1"), []byte("val1"))
	st.Update([]byte("key2"), []byte("val2"))
	st.Delete([]byte("key1"))

	got, _ := st.Get([]byte("key1"))
	if got != nil {
		t.Errorf("expected nil for deleted key, got %x", got)
	}
	got2, _ := st.Get([]byte("key2"))
	if !bytes.Equal(got2, []byte("val2")) {
		t.Errorf("expected val2, got %x", got2)
	}
}

func TestStackTrieInsertOrder(t *testing.T) {
	// Stack trie requires keys in ascending order.
	st := NewStackTrie(nil)

	keys := []string{"aa", "ab", "ac", "ba", "bb"}
	for _, k := range keys {
		err := st.Update([]byte(k), []byte("val-"+k))
		if err != nil {
			t.Fatal(err)
		}
	}

	// Build the same trie with the regular trie.
	trie := NewEmpty(newTestDB())
	for _, k := range keys {
		trie.MustUpdate([]byte(k), []byte("val-"+k))
	}

	if st.Hash() != trie.Hash() {
		t.Errorf("stack trie and regular trie hash mismatch: %x != %x", st.Hash(), trie.Hash())
	}
}

func TestStackTrieVsTrie(t *testing.T) {
	// Random keys, sorted.
	const N = 200
	keys := make([][]byte, N)
	for i := 0; i < N; i++ {
		k := make([]byte, 32)
		rand.Read(k)
		keys[i] = k
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i], keys[j]) < 0
	})
	// Deduplicate (unlikely but possible).
	deduped := keys[:1]
	for i := 1; i < len(keys); i++ {
		if !bytes.Equal(keys[i], keys[i-1]) {
			deduped = append(deduped, keys[i])
		}
	}
	keys = deduped

	value := []byte("value-data-here!")

	st := NewStackTrie(nil)
	trie := NewEmpty(newTestDB())
	for _, k := range keys {
		st.Update(k, value)
		trie.MustUpdate(k, value)
	}

	if st.Hash() != trie.Hash() {
		t.Errorf("stack trie and regular trie hash mismatch: %x != %x", st.Hash(), trie.Hash())
	}
}

func TestIterator(t *testing.T) {
	trie := NewEmpty(newTestDB())
	vals := map[string]string{
		"doe":          "reindeer",
		"dog":          "puppy",
		"dogglesworth": "cat",
	}
	for k, v := range vals {
		updateString(trie, k, v)
	}

	found := make(map[string]string)
	it := NewIterator(trie.MustNodeIterator(nil))
	for it.Next() {
		found[string(it.Key)] = string(it.Value)
	}
	if it.Err != nil {
		t.Fatal(it.Err)
	}
	for k, v := range vals {
		if found[k] != v {
			t.Errorf("key %q: expected %q, got %q", k, v, found[k])
		}
	}
}

func TestDeriveSha(t *testing.T) {
	// Empty list should produce EmptyRootHash.
	h := DeriveSha(testList{})
	if h != types.EmptyRootHash {
		t.Errorf("empty list: expected %x got %x", types.EmptyRootHash, h)
	}
}

// Test helpers

func updateString(trie *Trie, k, v string) {
	trie.MustUpdate([]byte(k), []byte(v))
}

func deleteString(trie *Trie, k string) {
	trie.MustDelete([]byte(k))
}

func getString(trie *Trie, k string) []byte {
	return trie.MustGet([]byte(k))
}

type testList struct{}

func (l testList) Len() int                       { return 0 }
func (l testList) EncodeIndex(int, *bytes.Buffer) {}
