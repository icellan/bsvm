// Package mpt_conformance runs conformance tests against the MPT implementation
// using JSON test fixtures. Each fixture describes a sequence of put/delete
// operations and the expected trie root after all operations are applied.
package mpt_conformance

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/types"
)

// MPTTestCase represents a single test case in a fixture file.
type MPTTestCase struct {
	Name         string         `json:"name"`
	Operations   []MPTOperation `json:"operations"`
	ExpectedRoot string         `json:"expectedRoot"`
}

// MPTOperation represents a single trie operation.
type MPTOperation struct {
	Action string `json:"action"` // "put" or "delete"
	Key    string `json:"key"`    // hex-encoded
	Value  string `json:"value"`  // hex-encoded (empty for delete)
}

// applyOperations creates a fresh trie, applies the given operations, and
// returns the resulting root hash.
func applyOperations(t *testing.T, ops []MPTOperation) types.Hash {
	t.Helper()

	memdb := db.NewMemoryDB()
	trieDB := mpt.NewDatabase(memdb)
	trie := mpt.NewEmpty(trieDB)

	for i, op := range ops {
		key, err := hex.DecodeString(op.Key)
		if err != nil {
			t.Fatalf("operation %d: invalid key hex %q: %v", i, op.Key, err)
		}

		switch op.Action {
		case "put":
			val, err := hex.DecodeString(op.Value)
			if err != nil {
				t.Fatalf("operation %d: invalid value hex %q: %v", i, op.Value, err)
			}
			if err := trie.Update(key, val); err != nil {
				t.Fatalf("operation %d: trie update failed: %v", i, err)
			}
		case "delete":
			if err := trie.Delete(key); err != nil {
				t.Fatalf("operation %d: trie delete failed: %v", i, err)
			}
		default:
			t.Fatalf("operation %d: unknown action %q", i, op.Action)
		}
	}

	return trie.Hash()
}

// loadFixture reads and parses a JSON fixture file.
func loadFixture(t *testing.T, filename string) []MPTTestCase {
	t.Helper()

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", filename, err)
	}

	var cases []MPTTestCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("failed to parse fixture %s: %v", filename, err)
	}
	return cases
}

// TestEmptyTrie verifies that an empty trie produces the canonical empty root.
func TestEmptyTrie(t *testing.T) {
	cases := loadFixture(t, filepath.Join(".", "empty_trie.json"))
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			root := applyOperations(t, tc.Operations)
			if tc.ExpectedRoot != "" {
				want := types.HexToHash(tc.ExpectedRoot)
				if root != want {
					t.Errorf("root mismatch: got %s, want %s", root.Hex(), want.Hex())
				}
			}
		})
	}
}

// TestSingleAccount verifies that single key-value inserts produce
// deterministic and distinct roots.
func TestSingleAccount(t *testing.T) {
	cases := loadFixture(t, filepath.Join(".", "single_account.json"))

	// Compute roots for all cases.
	roots := make([]types.Hash, len(cases))
	for i, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			root := applyOperations(t, tc.Operations)
			roots[i] = root

			// Verify against expected root if provided.
			if tc.ExpectedRoot != "" {
				want := types.HexToHash(tc.ExpectedRoot)
				if root != want {
					t.Errorf("root mismatch: got %s, want %s", root.Hex(), want.Hex())
				}
			}

			// Root must not be the empty root.
			if root == types.EmptyRootHash {
				t.Error("single-entry trie should not have empty root")
			}
		})
	}

	// Verify determinism: same operations must produce same root.
	for i, tc := range cases {
		root2 := applyOperations(t, tc.Operations)
		if root2 != roots[i] {
			t.Errorf("case %q: not deterministic, got %s then %s", tc.Name, roots[i].Hex(), root2.Hex())
		}
	}

	// Verify distinctness: different inputs must produce different roots.
	if len(roots) >= 2 && roots[0] == roots[1] {
		t.Error("different keys with same value should produce different roots")
	}
	if len(roots) >= 3 && roots[0] == roots[2] {
		t.Error("same key with different values should produce different roots")
	}
}

// TestDeleteAllAccounts verifies that deleting all entries returns the trie
// to the empty root hash.
func TestDeleteAllAccounts(t *testing.T) {
	cases := loadFixture(t, filepath.Join(".", "delete_all_accounts.json"))
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			root := applyOperations(t, tc.Operations)
			if tc.ExpectedRoot != "" {
				want := types.HexToHash(tc.ExpectedRoot)
				if root != want {
					t.Errorf("root mismatch: got %s, want %s", root.Hex(), want.Hex())
				}
			}
		})
	}
}

// TestMixedOperations verifies put-delete-put sequences, overwrites, and
// deleting nonexistent keys.
func TestMixedOperations(t *testing.T) {
	cases := loadFixture(t, filepath.Join(".", "mixed_operations.json"))
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			root := applyOperations(t, tc.Operations)

			// Verify against expected root if provided.
			if tc.ExpectedRoot != "" {
				want := types.HexToHash(tc.ExpectedRoot)
				if root != want {
					t.Errorf("root mismatch: got %s, want %s", root.Hex(), want.Hex())
				}
			}

			// Determinism check: same operations must produce same root.
			root2 := applyOperations(t, tc.Operations)
			if root != root2 {
				t.Errorf("non-deterministic: run1=%s run2=%s", root.Hex(), root2.Hex())
			}
		})
	}
}

// TestOverwriteEquivalence verifies that overwriting a key produces the same
// root as inserting the final value directly.
func TestOverwriteEquivalence(t *testing.T) {
	// Overwrite scenario: put(k, old), put(k, new)
	overwriteOps := []MPTOperation{
		{Action: "put", Key: "0000000000000000000000000000000000000000000000000000000000000001", Value: "aabb"},
		{Action: "put", Key: "0000000000000000000000000000000000000000000000000000000000000001", Value: "ccdd"},
	}
	rootOverwrite := applyOperations(t, overwriteOps)

	// Direct scenario: put(k, new)
	directOps := []MPTOperation{
		{Action: "put", Key: "0000000000000000000000000000000000000000000000000000000000000001", Value: "ccdd"},
	}
	rootDirect := applyOperations(t, directOps)

	if rootOverwrite != rootDirect {
		t.Errorf("overwrite root %s != direct root %s", rootOverwrite.Hex(), rootDirect.Hex())
	}
}

// TestDeleteNonexistentKeyIsNoOp verifies that deleting a key that was never
// inserted does not change the root.
func TestDeleteNonexistentKeyIsNoOp(t *testing.T) {
	ops1 := []MPTOperation{
		{Action: "put", Key: "0000000000000000000000000000000000000000000000000000000000000001", Value: "aa"},
	}
	root1 := applyOperations(t, ops1)

	ops2 := []MPTOperation{
		{Action: "put", Key: "0000000000000000000000000000000000000000000000000000000000000001", Value: "aa"},
		{Action: "delete", Key: "0000000000000000000000000000000000000000000000000000000000000099", Value: ""},
	}
	root2 := applyOperations(t, ops2)

	if root1 != root2 {
		t.Errorf("deleting nonexistent key changed root: %s != %s", root1.Hex(), root2.Hex())
	}
}
