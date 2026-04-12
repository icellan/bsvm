package fuzz

import (
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/types"
)

// kvEntry holds a key-value pair for MPT insertion.
type kvEntry struct {
	key   []byte
	value []byte
}

// FuzzMPTInsertDelete inserts random key-value pairs into a trie, then
// deletes a subset, and verifies: (1) the root is deterministic for
// the same input, and (2) no panics occur during insert/delete/hash.
func FuzzMPTInsertDelete(f *testing.F) {
	// Each seed is a byte slice interpreted as pairs of (key, value)
	// followed by a bitmask of which entries to delete.
	f.Add([]byte{0x01, 0xaa, 0x02, 0xbb, 0x03, 0xcc, 0x01})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x00})
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x03})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Need at least 2 bytes for one key-value pair.
		if len(data) < 2 {
			return
		}

		// Limit to prevent excessive runtime.
		if len(data) > 512 {
			data = data[:512]
		}

		// Parse key-value pairs. Use the last byte as the deletion bitmask.
		deleteMask := data[len(data)-1]
		pairs := data[:len(data)-1]

		// Build key-value entries (each pair is 2 bytes: key suffix, value byte).
		var entries []kvEntry
		for i := 0; i+1 < len(pairs); i += 2 {
			// Pad the key to make it a more realistic trie key.
			key := make([]byte, 8)
			key[7] = pairs[i]
			key[6] = byte(i / 2) // prevent all keys from colliding
			value := []byte{pairs[i+1]}
			if pairs[i+1] == 0 {
				// Use a longer value to test non-trivial storage.
				value = []byte{0x01, 0x02, 0x03, 0x04}
			}
			entries = append(entries, kvEntry{key: key, value: value})
		}

		if len(entries) == 0 {
			return
		}

		// Run twice for determinism check.
		root1 := runMPTOps(t, entries, deleteMask)
		root2 := runMPTOps(t, entries, deleteMask)

		if root1 != root2 {
			t.Fatalf("non-deterministic trie root: first %s, second %s", root1.Hex(), root2.Hex())
		}
	})
}

// runMPTOps inserts entries into a fresh trie, deletes entries selected by
// the bitmask, and returns the trie root hash.
func runMPTOps(t *testing.T, entries []kvEntry, deleteMask byte) types.Hash {
	t.Helper()

	diskdb := db.NewMemoryDB()
	trieDB := mpt.NewDatabase(diskdb)
	trie, err := mpt.New(mpt.TrieID(types.Hash{}), trieDB)
	if err != nil {
		t.Fatalf("failed to create trie: %v", err)
	}

	// Insert all entries.
	for _, e := range entries {
		if err := trie.Update(e.key, e.value); err != nil {
			// Some inputs may fail to insert; this is acceptable
			// as long as there is no panic.
			return trie.Hash()
		}
	}

	// Delete entries selected by the bitmask.
	for i, e := range entries {
		if i >= 8 {
			break // only 8 bits in the mask
		}
		if deleteMask&(1<<uint(i)) != 0 {
			if err := trie.Delete(e.key); err != nil {
				// Deletion failure is acceptable as long as no panic.
				return trie.Hash()
			}
		}
	}

	return trie.Hash()
}
