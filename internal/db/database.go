package db

import "errors"

// ErrNotFound is returned when a key is not found in the database.
var ErrNotFound = errors.New("not found")

// Database wraps all database operations.
type Database interface {
	// Get retrieves a value by key. Returns ErrNotFound if key does not exist.
	Get(key []byte) ([]byte, error)
	// Has checks if a key exists.
	Has(key []byte) (bool, error)
	// Put stores a key-value pair.
	Put(key []byte, value []byte) error
	// Delete removes a key.
	Delete(key []byte) error
	// NewBatch creates a new write batch.
	NewBatch() Batch
	// Close closes the database.
	Close() error
}

// Batch is a batch of database operations that are applied atomically.
type Batch interface {
	// Put stages a key-value pair for writing.
	Put(key []byte, value []byte) error
	// Delete stages a key for deletion.
	Delete(key []byte) error
	// Write applies all staged operations atomically.
	Write() error
	// Reset clears all staged operations.
	Reset()
	// ValueSize returns the total size of staged values.
	ValueSize() int
}

// Iterator iterates over a database's key/value pairs in key order.
type Iterator interface {
	// Next moves to the next key/value pair. Returns false at the end.
	Next() bool
	// Key returns the key of the current key/value pair.
	Key() []byte
	// Value returns the value of the current key/value pair.
	Value() []byte
	// Release releases the iterator.
	Release()
	// Error returns any accumulated error.
	Error() error
}

// Iteratee wraps the NewIterator method.
type Iteratee interface {
	// NewIterator creates a binary-alphabetical iterator over a subset
	// of the database content with the given key prefix.
	NewIterator(prefix []byte, start []byte) Iterator
}
