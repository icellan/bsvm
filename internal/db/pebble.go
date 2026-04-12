//go:build pebble

package db

import (
	"github.com/cockroachdb/pebble"
)

// PebbleDB is a persistent key-value store backed by Pebble.
type PebbleDB struct {
	db *pebble.DB
}

// NewPebbleDB creates a new Pebble database at the given path.
func NewPebbleDB(path string) (*PebbleDB, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, err
	}
	return &PebbleDB{db: db}, nil
}

// Get retrieves a value by key. Returns ErrNotFound if key does not exist.
func (p *PebbleDB) Get(key []byte) ([]byte, error) {
	val, closer, err := p.db.Get(key)
	if err == pebble.ErrNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// Copy the value before closing, since pebble invalidates it on close.
	ret := make([]byte, len(val))
	copy(ret, val)
	if err := closer.Close(); err != nil {
		return nil, err
	}
	return ret, nil
}

// Has checks if a key exists.
func (p *PebbleDB) Has(key []byte) (bool, error) {
	_, closer, err := p.db.Get(key)
	if err == pebble.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := closer.Close(); err != nil {
		return false, err
	}
	return true, nil
}

// Put stores a key-value pair.
func (p *PebbleDB) Put(key []byte, value []byte) error {
	return p.db.Set(key, value, pebble.Sync)
}

// Delete removes a key.
func (p *PebbleDB) Delete(key []byte) error {
	return p.db.Delete(key, pebble.Sync)
}

// NewBatch creates a new write batch.
func (p *PebbleDB) NewBatch() Batch {
	return &pebbleBatch{
		db:    p.db,
		batch: p.db.NewBatch(),
	}
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of the database content with the given key prefix, starting at or
// after the given start key.
func (p *PebbleDB) NewIterator(prefix []byte, start []byte) Iterator {
	opts := &pebble.IterOptions{}

	if len(prefix) > 0 {
		opts.LowerBound = prefix
		// Upper bound is the prefix with the last byte incremented.
		upper := make([]byte, len(prefix))
		copy(upper, prefix)
		for i := len(upper) - 1; i >= 0; i-- {
			upper[i]++
			if upper[i] != 0 {
				break
			}
			// Overflow: drop this byte and carry. If all bytes overflow,
			// there is no upper bound (prefix is all 0xff).
			if i == 0 {
				upper = nil
			}
		}
		opts.UpperBound = upper
	}

	begin := prefix
	if len(start) > 0 {
		begin = make([]byte, len(prefix)+len(start))
		copy(begin, prefix)
		copy(begin[len(prefix):], start)
		// If begin is greater than prefix, use it as lower bound.
		if string(begin) > string(opts.LowerBound) {
			opts.LowerBound = begin
		}
	}

	iter, err := p.db.NewIter(opts)
	if err != nil {
		return &pebbleIterator{err: err}
	}
	// Position at the first key.
	iter.First()
	return &pebbleIterator{iter: iter, first: true}
}

// Close closes the database.
func (p *PebbleDB) Close() error {
	return p.db.Close()
}

// pebbleBatch implements the Batch interface for Pebble.
type pebbleBatch struct {
	db    *pebble.DB
	batch *pebble.Batch
	valSz int
}

// Put stages a key-value pair for writing.
func (b *pebbleBatch) Put(key []byte, value []byte) error {
	if err := b.batch.Set(key, value, nil); err != nil {
		return err
	}
	b.valSz += len(value)
	return nil
}

// Delete stages a key for deletion.
func (b *pebbleBatch) Delete(key []byte) error {
	return b.batch.Delete(key, nil)
}

// Write applies all staged operations atomically.
func (b *pebbleBatch) Write() error {
	return b.batch.Commit(pebble.Sync)
}

// Reset clears all staged operations.
func (b *pebbleBatch) Reset() {
	b.batch.Reset()
	b.valSz = 0
}

// ValueSize returns the total size of staged values.
func (b *pebbleBatch) ValueSize() int {
	return b.valSz
}

// pebbleIterator wraps pebble's iterator to implement our Iterator interface.
type pebbleIterator struct {
	iter  *pebble.Iterator
	first bool // true if First() was called but Next() hasn't consumed it yet
	err   error
}

// Next moves to the next key/value pair. Returns false at the end.
func (it *pebbleIterator) Next() bool {
	if it.iter == nil {
		return false
	}
	if it.first {
		// First() was already called in NewIterator; check if it's valid.
		it.first = false
		return it.iter.Valid()
	}
	return it.iter.Next()
}

// Key returns the key of the current key/value pair.
func (it *pebbleIterator) Key() []byte {
	if it.iter == nil || !it.iter.Valid() {
		return nil
	}
	return it.iter.Key()
}

// Value returns the value of the current key/value pair.
func (it *pebbleIterator) Value() []byte {
	if it.iter == nil || !it.iter.Valid() {
		return nil
	}
	return it.iter.Value()
}

// Release releases the iterator.
func (it *pebbleIterator) Release() {
	if it.iter != nil {
		it.err = it.iter.Close()
		it.iter = nil
	}
}

// Error returns any accumulated error.
func (it *pebbleIterator) Error() error {
	if it.err != nil {
		return it.err
	}
	if it.iter != nil {
		return it.iter.Error()
	}
	return nil
}
