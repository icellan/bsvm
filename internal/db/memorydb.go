package db

import (
	"sort"
	"strings"
	"sync"
)

// MemoryDB is an in-memory database implementation backed by a map.
// It is safe for concurrent use and suitable for testing.
type MemoryDB struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryDB creates a new in-memory database.
func NewMemoryDB() *MemoryDB {
	return &MemoryDB{
		data: make(map[string][]byte),
	}
}

// Get retrieves a value by key. Returns ErrNotFound if key does not exist.
func (m *MemoryDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.data[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	ret := make([]byte, len(val))
	copy(ret, val)
	return ret, nil
}

// Has checks if a key exists.
func (m *MemoryDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.data[string(key)]
	return ok, nil
}

// Put stores a key-value pair.
func (m *MemoryDB) Put(key []byte, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[string(key)] = cp
	return nil
}

// Delete removes a key.
func (m *MemoryDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, string(key))
	return nil
}

// NewBatch creates a new write batch.
func (m *MemoryDB) NewBatch() Batch {
	return &memoryBatch{db: m}
}

// Close closes the database. For MemoryDB this is a no-op.
func (m *MemoryDB) Close() error {
	return nil
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of the database content with the given key prefix, starting at or
// after the given start key.
func (m *MemoryDB) NewIterator(prefix []byte, start []byte) Iterator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pfx := string(prefix)
	begin := string(append(prefix, start...))

	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, pfx) && k >= begin {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	items := make([]iterItem, len(keys))
	for i, k := range keys {
		val := make([]byte, len(m.data[k]))
		copy(val, m.data[k])
		items[i] = iterItem{key: []byte(k), value: val}
	}

	return &memoryIterator{items: items, pos: -1}
}

// Len returns the number of entries in the database.
func (m *MemoryDB) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

// memoryBatch implements the Batch interface for MemoryDB.
type memoryBatch struct {
	db    *MemoryDB
	ops   []batchOp
	valSz int
}

type batchOp struct {
	key    []byte
	value  []byte
	delete bool
}

// Put stages a key-value pair for writing.
func (b *memoryBatch) Put(key []byte, value []byte) error {
	kcopy := make([]byte, len(key))
	copy(kcopy, key)
	vcopy := make([]byte, len(value))
	copy(vcopy, value)
	b.ops = append(b.ops, batchOp{key: kcopy, value: vcopy})
	b.valSz += len(value)
	return nil
}

// Delete stages a key for deletion.
func (b *memoryBatch) Delete(key []byte) error {
	kcopy := make([]byte, len(key))
	copy(kcopy, key)
	b.ops = append(b.ops, batchOp{key: kcopy, delete: true})
	return nil
}

// Write applies all staged operations atomically.
func (b *memoryBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()

	for _, op := range b.ops {
		if op.delete {
			delete(b.db.data, string(op.key))
		} else {
			b.db.data[string(op.key)] = op.value
		}
	}
	return nil
}

// Reset clears all staged operations.
func (b *memoryBatch) Reset() {
	b.ops = b.ops[:0]
	b.valSz = 0
}

// ValueSize returns the total size of staged values.
func (b *memoryBatch) ValueSize() int {
	return b.valSz
}

// iterItem holds a single key-value pair for iteration.
type iterItem struct {
	key   []byte
	value []byte
}

// memoryIterator implements the Iterator interface for MemoryDB.
type memoryIterator struct {
	items []iterItem
	pos   int
}

// Next moves to the next key/value pair. Returns false at the end.
func (it *memoryIterator) Next() bool {
	it.pos++
	return it.pos < len(it.items)
}

// Key returns the key of the current key/value pair.
func (it *memoryIterator) Key() []byte {
	if it.pos < 0 || it.pos >= len(it.items) {
		return nil
	}
	return it.items[it.pos].key
}

// Value returns the value of the current key/value pair.
func (it *memoryIterator) Value() []byte {
	if it.pos < 0 || it.pos >= len(it.items) {
		return nil
	}
	return it.items[it.pos].value
}

// Release releases the iterator. For memoryIterator this is a no-op.
func (it *memoryIterator) Release() {}

// Error returns any accumulated error. memoryIterator never errors.
func (it *memoryIterator) Error() error {
	return nil
}
