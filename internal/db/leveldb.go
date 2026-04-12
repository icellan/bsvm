package db

import (
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// LevelDB is a persistent key-value store backed by LevelDB.
type LevelDB struct {
	db *leveldb.DB
}

// NewLevelDB creates a new LevelDB database at the given path.
// cache is the size of the internal LevelDB cache in megabytes.
// handles is the number of open file handles to allow.
func NewLevelDB(path string, cache int, handles int) (*LevelDB, error) {
	o := &opt.Options{
		OpenFilesCacheCapacity: handles,
		BlockCacheCapacity:     cache / 2 * opt.MiB,
		WriteBuffer:            cache / 4 * opt.MiB,
		Filter:                 filter.NewBloomFilter(10),
	}
	innerDB, err := leveldb.OpenFile(path, o)
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		innerDB, err = leveldb.RecoverFile(path, nil)
	}
	if err != nil {
		return nil, err
	}
	return &LevelDB{db: innerDB}, nil
}

// Get retrieves a value by key. Returns ErrNotFound if key does not exist.
func (l *LevelDB) Get(key []byte) ([]byte, error) {
	val, err := l.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, ErrNotFound
	}
	return val, err
}

// Has checks if a key exists.
func (l *LevelDB) Has(key []byte) (bool, error) {
	return l.db.Has(key, nil)
}

// Put stores a key-value pair.
func (l *LevelDB) Put(key []byte, value []byte) error {
	return l.db.Put(key, value, nil)
}

// Delete removes a key.
func (l *LevelDB) Delete(key []byte) error {
	return l.db.Delete(key, nil)
}

// NewBatch creates a new write batch.
func (l *LevelDB) NewBatch() Batch {
	return &levelBatch{
		db:    l.db,
		batch: new(leveldb.Batch),
	}
}

// Close closes the database.
func (l *LevelDB) Close() error {
	return l.db.Close()
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of the database content with the given key prefix, starting at or
// after the given start key.
func (l *LevelDB) NewIterator(prefix []byte, start []byte) Iterator {
	r := util.BytesPrefix(prefix)
	if len(start) > 0 {
		begin := make([]byte, len(prefix)+len(start))
		copy(begin, prefix)
		copy(begin[len(prefix):], start)
		if string(begin) > string(r.Start) {
			r.Start = begin
		}
	}
	return &levelIterator{iter: l.db.NewIterator(r, nil)}
}

// levelBatch implements the Batch interface for LevelDB.
type levelBatch struct {
	db    *leveldb.DB
	batch *leveldb.Batch
	valSz int
}

// Put stages a key-value pair for writing.
func (b *levelBatch) Put(key []byte, value []byte) error {
	b.batch.Put(key, value)
	b.valSz += len(value)
	return nil
}

// Delete stages a key for deletion.
func (b *levelBatch) Delete(key []byte) error {
	b.batch.Delete(key)
	return nil
}

// Write applies all staged operations atomically.
func (b *levelBatch) Write() error {
	return b.db.Write(b.batch, nil)
}

// Reset clears all staged operations.
func (b *levelBatch) Reset() {
	b.batch.Reset()
	b.valSz = 0
}

// ValueSize returns the total size of staged values.
func (b *levelBatch) ValueSize() int {
	return b.valSz
}

// levelIterator wraps goleveldb's iterator to implement our Iterator interface.
type levelIterator struct {
	iter iterator.Iterator
}

// Next moves to the next key/value pair. Returns false at the end.
func (it *levelIterator) Next() bool {
	return it.iter.Next()
}

// Key returns the key of the current key/value pair.
func (it *levelIterator) Key() []byte {
	return it.iter.Key()
}

// Value returns the value of the current key/value pair.
func (it *levelIterator) Value() []byte {
	return it.iter.Value()
}

// Release releases the iterator.
func (it *levelIterator) Release() {
	it.iter.Release()
}

// Error returns any accumulated error.
func (it *levelIterator) Error() error {
	return it.iter.Error()
}
