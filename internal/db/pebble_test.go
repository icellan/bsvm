//go:build pebble

package db

import (
	"bytes"
	"testing"
)

func newTestPebbleDB(t *testing.T) (*PebbleDB, func()) {
	t.Helper()
	dir := t.TempDir()
	pdb, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	return pdb, func() { pdb.Close() }
}

func TestPebbleDB(t *testing.T) {
	testDatabase(t, func(t *testing.T) (Database, Iteratee, func()) {
		pdb, cleanup := newTestPebbleDB(t)
		return pdb, pdb, cleanup
	})
}

func TestPebbleDB_GetPutDelete(t *testing.T) {
	pdb, cleanup := newTestPebbleDB(t)
	defer cleanup()

	key := []byte("hello")
	val := []byte("world")

	// put
	if err := pdb.Put(key, val); err != nil {
		t.Fatal(err)
	}

	// get
	got, err := pdb.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, val) {
		t.Fatalf("expected %q, got %q", val, got)
	}

	// delete
	if err := pdb.Delete(key); err != nil {
		t.Fatal(err)
	}

	_, err = pdb.Get(key)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestPebbleDB_Batch(t *testing.T) {
	pdb, cleanup := newTestPebbleDB(t)
	defer cleanup()

	batch := pdb.NewBatch()
	if err := batch.Put([]byte("k1"), []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := batch.Put([]byte("k2"), []byte("v2")); err != nil {
		t.Fatal(err)
	}

	// keys should not exist before write
	if has, _ := pdb.Has([]byte("k1")); has {
		t.Fatal("key should not exist before batch write")
	}

	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}

	// keys should exist after write
	got, err := pdb.Get([]byte("k1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("expected %q, got %q", "v1", got)
	}

	got, err = pdb.Get([]byte("k2"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Fatalf("expected %q, got %q", "v2", got)
	}
}

func TestPebbleDB_Has(t *testing.T) {
	pdb, cleanup := newTestPebbleDB(t)
	defer cleanup()

	key := []byte("exists")

	has, err := pdb.Has(key)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("expected false for non-existent key")
	}

	if err := pdb.Put(key, []byte("yes")); err != nil {
		t.Fatal(err)
	}

	has, err = pdb.Has(key)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("expected true for existing key")
	}
}

func TestPebbleDB_GetNotFound(t *testing.T) {
	pdb, cleanup := newTestPebbleDB(t)
	defer cleanup()

	_, err := pdb.Get([]byte("missing"))
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPebbleDB_Close(t *testing.T) {
	dir := t.TempDir()
	pdb, err := NewPebbleDB(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := pdb.Close(); err != nil {
		t.Fatal(err)
	}

	// second close returns an error but must not panic
	_ = pdb.Close()
}

func TestPebbleDB_BatchReset(t *testing.T) {
	pdb, cleanup := newTestPebbleDB(t)
	defer cleanup()

	batch := pdb.NewBatch()
	if err := batch.Put([]byte("reset-key"), []byte("reset-val")); err != nil {
		t.Fatal(err)
	}

	if batch.ValueSize() == 0 {
		t.Fatal("expected non-zero value size before reset")
	}

	batch.Reset()

	if batch.ValueSize() != 0 {
		t.Fatalf("expected value size 0 after reset, got %d", batch.ValueSize())
	}

	// writing an empty batch should be a no-op
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}

	has, err := pdb.Has([]byte("reset-key"))
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("expected key to not exist after reset batch write")
	}
}

func TestPebbleDB_Iterator(t *testing.T) {
	pdb, cleanup := newTestPebbleDB(t)
	defer cleanup()

	entries := []struct {
		key, val []byte
	}{
		{[]byte("iter-charlie"), []byte("3")},
		{[]byte("iter-alpha"), []byte("1")},
		{[]byte("iter-bravo"), []byte("2")},
		{[]byte("other-key"), []byte("x")},
	}

	for _, e := range entries {
		if err := pdb.Put(e.key, e.val); err != nil {
			t.Fatal(err)
		}
	}

	iter := pdb.NewIterator([]byte("iter-"), nil)
	defer iter.Release()

	expected := []struct {
		key, val string
	}{
		{"iter-alpha", "1"},
		{"iter-bravo", "2"},
		{"iter-charlie", "3"},
	}

	i := 0
	for iter.Next() {
		if i >= len(expected) {
			t.Fatalf("too many iterator results, expected %d", len(expected))
		}
		if string(iter.Key()) != expected[i].key {
			t.Fatalf("key[%d]: expected %q, got %q", i, expected[i].key, string(iter.Key()))
		}
		if string(iter.Value()) != expected[i].val {
			t.Fatalf("value[%d]: expected %q, got %q", i, expected[i].val, string(iter.Value()))
		}
		i++
	}
	if i != len(expected) {
		t.Fatalf("expected %d items, got %d", len(expected), i)
	}
	if err := iter.Error(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}
}
