package db

import (
	"bytes"
	"os"
	"testing"
)

// testDatabase runs the shared test suite against any Database+Iteratee implementation.
func testDatabase(t *testing.T, newDB func(t *testing.T) (Database, Iteratee, func())) {
	t.Helper()

	t.Run("PutGetHasDelete", func(t *testing.T) {
		database, _, cleanup := newDB(t)
		defer cleanup()

		key := []byte("testkey")
		val := []byte("testvalue")

		// key should not exist yet
		has, err := database.Has(key)
		if err != nil {
			t.Fatal(err)
		}
		if has {
			t.Fatal("expected key to not exist")
		}

		// get should return ErrNotFound
		_, err = database.Get(key)
		if err != ErrNotFound {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}

		// put the key
		if err := database.Put(key, val); err != nil {
			t.Fatal(err)
		}

		// now it should exist
		has, err = database.Has(key)
		if err != nil {
			t.Fatal(err)
		}
		if !has {
			t.Fatal("expected key to exist")
		}

		// get should return the value
		got, err := database.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, val) {
			t.Fatalf("expected %q, got %q", val, got)
		}

		// delete the key
		if err := database.Delete(key); err != nil {
			t.Fatal(err)
		}

		// key should not exist anymore
		has, err = database.Has(key)
		if err != nil {
			t.Fatal(err)
		}
		if has {
			t.Fatal("expected key to not exist after delete")
		}

		_, err = database.Get(key)
		if err != ErrNotFound {
			t.Fatalf("expected ErrNotFound after delete, got %v", err)
		}
	})

	t.Run("PutOverwrite", func(t *testing.T) {
		database, _, cleanup := newDB(t)
		defer cleanup()

		key := []byte("overwrite")
		val1 := []byte("first")
		val2 := []byte("second")

		if err := database.Put(key, val1); err != nil {
			t.Fatal(err)
		}
		if err := database.Put(key, val2); err != nil {
			t.Fatal(err)
		}

		got, err := database.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, val2) {
			t.Fatalf("expected %q, got %q", val2, got)
		}
	})

	t.Run("BatchOperations", func(t *testing.T) {
		database, _, cleanup := newDB(t)
		defer cleanup()

		batch := database.NewBatch()

		pairs := []struct {
			key, val []byte
		}{
			{[]byte("batch-a"), []byte("val-a")},
			{[]byte("batch-b"), []byte("val-b")},
			{[]byte("batch-c"), []byte("val-c")},
		}

		for _, p := range pairs {
			if err := batch.Put(p.key, p.val); err != nil {
				t.Fatal(err)
			}
		}

		// before write, keys should not exist
		for _, p := range pairs {
			has, err := database.Has(p.key)
			if err != nil {
				t.Fatal(err)
			}
			if has {
				t.Fatalf("key %q should not exist before batch write", p.key)
			}
		}

		// check value size is non-zero
		if batch.ValueSize() == 0 {
			t.Fatal("expected non-zero value size")
		}

		// write the batch
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}

		// now verify all keys exist
		for _, p := range pairs {
			got, err := database.Get(p.key)
			if err != nil {
				t.Fatalf("get %q: %v", p.key, err)
			}
			if !bytes.Equal(got, p.val) {
				t.Fatalf("key %q: expected %q, got %q", p.key, p.val, got)
			}
		}
	})

	t.Run("BatchDelete", func(t *testing.T) {
		database, _, cleanup := newDB(t)
		defer cleanup()

		key := []byte("to-delete")
		if err := database.Put(key, []byte("exists")); err != nil {
			t.Fatal(err)
		}

		batch := database.NewBatch()
		if err := batch.Delete(key); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}

		has, err := database.Has(key)
		if err != nil {
			t.Fatal(err)
		}
		if has {
			t.Fatal("expected key to be deleted by batch")
		}
	})

	t.Run("BatchReset", func(t *testing.T) {
		database, _, cleanup := newDB(t)
		defer cleanup()

		batch := database.NewBatch()
		if err := batch.Put([]byte("reset-key"), []byte("reset-val")); err != nil {
			t.Fatal(err)
		}
		batch.Reset()

		if batch.ValueSize() != 0 {
			t.Fatalf("expected value size 0 after reset, got %d", batch.ValueSize())
		}

		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}

		has, err := database.Has([]byte("reset-key"))
		if err != nil {
			t.Fatal(err)
		}
		if has {
			t.Fatal("expected key to not exist after reset batch write")
		}
	})

	t.Run("IteratorPrefixOrdering", func(t *testing.T) {
		database, iteratee, cleanup := newDB(t)
		defer cleanup()

		entries := []struct {
			key, val []byte
		}{
			{[]byte("prefix-charlie"), []byte("3")},
			{[]byte("prefix-alpha"), []byte("1")},
			{[]byte("prefix-bravo"), []byte("2")},
			{[]byte("other-key"), []byte("x")},
		}

		for _, e := range entries {
			if err := database.Put(e.key, e.val); err != nil {
				t.Fatal(err)
			}
		}

		iter := iteratee.NewIterator([]byte("prefix-"), nil)
		defer iter.Release()

		expected := []struct {
			key, val string
		}{
			{"prefix-alpha", "1"},
			{"prefix-bravo", "2"},
			{"prefix-charlie", "3"},
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
	})

	t.Run("IteratorWithStart", func(t *testing.T) {
		database, iteratee, cleanup := newDB(t)
		defer cleanup()

		entries := []struct {
			key, val []byte
		}{
			{[]byte("iter-alpha"), []byte("1")},
			{[]byte("iter-bravo"), []byte("2")},
			{[]byte("iter-charlie"), []byte("3")},
			{[]byte("iter-delta"), []byte("4")},
		}

		for _, e := range entries {
			if err := database.Put(e.key, e.val); err != nil {
				t.Fatal(err)
			}
		}

		// start at "charlie"
		iter := iteratee.NewIterator([]byte("iter-"), []byte("charlie"))
		defer iter.Release()

		expected := []string{"iter-charlie", "iter-delta"}
		i := 0
		for iter.Next() {
			if i >= len(expected) {
				t.Fatalf("too many iterator results")
			}
			if string(iter.Key()) != expected[i] {
				t.Fatalf("key[%d]: expected %q, got %q", i, expected[i], string(iter.Key()))
			}
			i++
		}
		if i != len(expected) {
			t.Fatalf("expected %d items, got %d", len(expected), i)
		}
	})

	t.Run("EmptyIterator", func(t *testing.T) {
		_, iteratee, cleanup := newDB(t)
		defer cleanup()

		iter := iteratee.NewIterator([]byte("nonexistent-"), nil)
		defer iter.Release()

		if iter.Next() {
			t.Fatal("expected empty iterator")
		}
		if err := iter.Error(); err != nil {
			t.Fatalf("iterator error: %v", err)
		}
	})
}

func TestMemoryDB(t *testing.T) {
	testDatabase(t, func(t *testing.T) (Database, Iteratee, func()) {
		db := NewMemoryDB()
		return db, db, func() { db.Close() }
	})
}

func TestMemoryDBLen(t *testing.T) {
	db := NewMemoryDB()
	defer db.Close()

	if db.Len() != 0 {
		t.Fatalf("expected len 0, got %d", db.Len())
	}

	if err := db.Put([]byte("a"), []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := db.Put([]byte("b"), []byte("2")); err != nil {
		t.Fatal(err)
	}

	if db.Len() != 2 {
		t.Fatalf("expected len 2, got %d", db.Len())
	}
}

func TestLevelDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping leveldb test in short mode")
	}

	testDatabase(t, func(t *testing.T) (Database, Iteratee, func()) {
		dir, err := os.MkdirTemp("", "bsvm-leveldb-test-*")
		if err != nil {
			t.Fatal(err)
		}
		ldb, err := NewLevelDB(dir, 16, 16)
		if err != nil {
			os.RemoveAll(dir)
			t.Fatal(err)
		}
		return ldb, ldb, func() {
			ldb.Close()
			os.RemoveAll(dir)
		}
	})
}

func TestLevelDBCloseReopen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping leveldb test in short mode")
	}

	dir, err := os.MkdirTemp("", "bsvm-leveldb-reopen-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// open, write, close
	ldb, err := NewLevelDB(dir, 16, 16)
	if err != nil {
		t.Fatal(err)
	}

	key := []byte("persist-key")
	val := []byte("persist-val")

	if err := ldb.Put(key, val); err != nil {
		t.Fatal(err)
	}
	if err := ldb.Close(); err != nil {
		t.Fatal(err)
	}

	// reopen and verify
	ldb2, err := NewLevelDB(dir, 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer ldb2.Close()

	got, err := ldb2.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, val) {
		t.Fatalf("expected %q after reopen, got %q", val, got)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	db := NewMemoryDB()
	defer db.Close()

	// deleting a non-existent key should not error
	if err := db.Delete([]byte("no-such-key")); err != nil {
		t.Fatalf("expected no error deleting non-existent key, got %v", err)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	db := NewMemoryDB()
	defer db.Close()

	key := []byte("copy-test")
	val := []byte("original")

	if err := db.Put(key, val); err != nil {
		t.Fatal(err)
	}

	got, err := db.Get(key)
	if err != nil {
		t.Fatal(err)
	}

	// mutate the returned value
	got[0] = 'X'

	// original should be unchanged
	got2, err := db.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, val) {
		t.Fatalf("mutation leaked: expected %q, got %q", val, got2)
	}
}

func TestPutCopiesInput(t *testing.T) {
	db := NewMemoryDB()
	defer db.Close()

	key := []byte("input-copy")
	val := []byte("original")

	if err := db.Put(key, val); err != nil {
		t.Fatal(err)
	}

	// mutate the input slice after Put
	val[0] = 'X'

	got, err := db.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 'o' {
		t.Fatalf("Put did not copy input: expected 'o', got %q", string(got[0]))
	}
}
