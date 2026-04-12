package state

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sort"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// snapshotMagic is the magic bytes that identify a state snapshot stream.
var snapshotMagic = [4]byte{'S', 'N', 'A', 'P'}

// snapshotVersion is the current snapshot format version.
const snapshotVersion = 1

// checksumSize is the size of the trailing SHA-256 checksum.
const checksumSize = 32

// hashWriter wraps an io.Writer and mirrors all writes to a hash.Hash
// so a checksum can be computed inline during serialization.
type hashWriter struct {
	w   io.Writer
	h   hash.Hash
	err error
}

// Write writes p to both the underlying writer and the hash.
func (hw *hashWriter) Write(p []byte) (int, error) {
	if hw.err != nil {
		return 0, hw.err
	}
	n, err := hw.w.Write(p)
	if err != nil {
		hw.err = err
		return n, err
	}
	hw.h.Write(p[:n])
	return n, nil
}

// writeUint32 writes a big-endian uint32.
func (hw *hashWriter) writeUint32(v uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	_, err := hw.Write(buf[:])
	return err
}

// writeUint64 writes a big-endian uint64.
func (hw *hashWriter) writeUint64(v uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, err := hw.Write(buf[:])
	return err
}

// hashReader wraps an io.Reader and mirrors all reads to a hash.Hash
// so a checksum can be verified inline during deserialization.
type hashReader struct {
	r   io.Reader
	h   hash.Hash
	err error
}

// Read reads from the underlying reader and mirrors to the hash.
func (hr *hashReader) Read(p []byte) (int, error) {
	if hr.err != nil {
		return 0, hr.err
	}
	n, err := hr.r.Read(p)
	if n > 0 {
		hr.h.Write(p[:n])
	}
	if err != nil {
		hr.err = err
	}
	return n, err
}

// readFull reads exactly len(buf) bytes.
func (hr *hashReader) readFull(buf []byte) error {
	_, err := io.ReadFull(hr, buf)
	return err
}

// readUint32 reads a big-endian uint32.
func (hr *hashReader) readUint32() (uint32, error) {
	var buf [4]byte
	if err := hr.readFull(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

// readUint64 reads a big-endian uint64.
func (hr *hashReader) readUint64() (uint64, error) {
	var buf [8]byte
	if err := hr.readFull(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// dbEntry is a key-value pair from the underlying database.
type dbEntry struct {
	Key   []byte
	Value []byte
}

// CreateSnapshot serializes the entire state at the current root to the
// provided writer. The snapshot is a database-level dump of all key-value
// pairs in the underlying storage, capturing the complete trie structure,
// account data, and contract code. The format is:
//
//   - 4 bytes: magic "SNAP"
//   - 1 byte: version (1)
//   - 32 bytes: state root hash
//   - 8 bytes: entry count (big-endian uint64)
//   - For each entry (sorted by key for determinism):
//   - 4 bytes: key length (big-endian uint32)
//   - N bytes: key
//   - 4 bytes: value length (big-endian uint32)
//   - M bytes: value
//   - 32 bytes: SHA-256 checksum of all preceding bytes
func (s *StateDB) CreateSnapshot(w io.Writer) error {
	// Finalize pending state changes.
	s.Finalise(true)

	// Commit to ensure all data is flushed to the database.
	root, err := s.Commit(true)
	if err != nil {
		return fmt.Errorf("commit before snapshot: %w", err)
	}

	// Get the underlying raw database and assert it supports iteration.
	rawDB := s.db.DiskDB()
	iterDB, ok := rawDB.(db.Iteratee)
	if !ok {
		return fmt.Errorf("underlying database does not support iteration")
	}

	// Collect all entries in sorted order for determinism.
	iter := iterDB.NewIterator(nil, nil)
	defer iter.Release()

	var entries []dbEntry
	for iter.Next() {
		entries = append(entries, dbEntry{
			Key:   append([]byte{}, iter.Key()...),
			Value: append([]byte{}, iter.Value()...),
		})
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error: %w", err)
	}

	// Sort entries by key for deterministic output.
	sort.Slice(entries, func(i, j int) bool {
		return string(entries[i].Key) < string(entries[j].Key)
	})

	// Set up the hash writer to compute checksum inline.
	hw := &hashWriter{w: w, h: sha256.New()}

	// Write header.
	if _, err := hw.Write(snapshotMagic[:]); err != nil {
		return fmt.Errorf("write magic: %w", err)
	}
	if _, err := hw.Write([]byte{snapshotVersion}); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	if _, err := hw.Write(root[:]); err != nil {
		return fmt.Errorf("write root: %w", err)
	}

	// Write entry count.
	if err := hw.writeUint64(uint64(len(entries))); err != nil {
		return fmt.Errorf("write entry count: %w", err)
	}

	// Write each entry.
	for _, e := range entries {
		if err := hw.writeUint32(uint32(len(e.Key))); err != nil {
			return fmt.Errorf("write key length: %w", err)
		}
		if _, err := hw.Write(e.Key); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
		if err := hw.writeUint32(uint32(len(e.Value))); err != nil {
			return fmt.Errorf("write value length: %w", err)
		}
		if _, err := hw.Write(e.Value); err != nil {
			return fmt.Errorf("write value: %w", err)
		}
	}

	// Write checksum footer directly to writer (not hashed).
	checksum := hw.h.Sum(nil)
	if _, err := w.Write(checksum); err != nil {
		return fmt.Errorf("write checksum: %w", err)
	}

	return nil
}

// RestoreSnapshot loads state from a snapshot stream previously created
// by CreateSnapshot. It populates the provided database with all key-value
// pairs from the snapshot and returns the state root hash embedded in the
// snapshot header. The caller can then use state.New(root, database) to
// obtain a fully functional StateDB.
func RestoreSnapshot(r io.Reader, database db.Database) (types.Hash, error) {
	// We need to read all data through the hashReader to compute checksum,
	// but the final 32 bytes are the checksum itself and must NOT be hashed.
	// Strategy: read everything into a buffer, split off the last 32 bytes,
	// hash the rest, then verify.
	data, err := io.ReadAll(r)
	if err != nil {
		return types.Hash{}, fmt.Errorf("read snapshot: %w", err)
	}

	if len(data) < 4+1+32+8+checksumSize {
		return types.Hash{}, fmt.Errorf("snapshot too short: %d bytes", len(data))
	}

	// Split payload and checksum.
	payload := data[:len(data)-checksumSize]
	storedChecksum := data[len(data)-checksumSize:]

	// Verify checksum.
	computed := sha256.Sum256(payload)
	for i := 0; i < checksumSize; i++ {
		if computed[i] != storedChecksum[i] {
			return types.Hash{}, fmt.Errorf("snapshot checksum mismatch")
		}
	}

	// Parse header from payload.
	pos := 0

	// Magic.
	if payload[0] != snapshotMagic[0] || payload[1] != snapshotMagic[1] ||
		payload[2] != snapshotMagic[2] || payload[3] != snapshotMagic[3] {
		return types.Hash{}, fmt.Errorf("invalid snapshot magic")
	}
	pos += 4

	// Version.
	version := payload[pos]
	if version != snapshotVersion {
		return types.Hash{}, fmt.Errorf("unsupported snapshot version %d", version)
	}
	pos++

	// State root.
	var root types.Hash
	copy(root[:], payload[pos:pos+types.HashLength])
	pos += types.HashLength

	// Entry count.
	if pos+8 > len(payload) {
		return types.Hash{}, fmt.Errorf("snapshot truncated at entry count")
	}
	count := binary.BigEndian.Uint64(payload[pos : pos+8])
	pos += 8

	// Read and insert entries.
	batch := database.NewBatch()
	for i := uint64(0); i < count; i++ {
		// Key length.
		if pos+4 > len(payload) {
			return types.Hash{}, fmt.Errorf("snapshot truncated at entry %d key length", i)
		}
		keyLen := binary.BigEndian.Uint32(payload[pos : pos+4])
		pos += 4

		// Key.
		if pos+int(keyLen) > len(payload) {
			return types.Hash{}, fmt.Errorf("snapshot truncated at entry %d key", i)
		}
		key := payload[pos : pos+int(keyLen)]
		pos += int(keyLen)

		// Value length.
		if pos+4 > len(payload) {
			return types.Hash{}, fmt.Errorf("snapshot truncated at entry %d value length", i)
		}
		valLen := binary.BigEndian.Uint32(payload[pos : pos+4])
		pos += 4

		// Value.
		if pos+int(valLen) > len(payload) {
			return types.Hash{}, fmt.Errorf("snapshot truncated at entry %d value", i)
		}
		value := payload[pos : pos+int(valLen)]
		pos += int(valLen)

		if err := batch.Put(key, value); err != nil {
			return types.Hash{}, fmt.Errorf("batch put entry %d: %w", i, err)
		}

		// Flush batch periodically to avoid unbounded memory.
		if batch.ValueSize() > 100*1024 {
			if err := batch.Write(); err != nil {
				return types.Hash{}, fmt.Errorf("batch write: %w", err)
			}
			batch.Reset()
		}
	}

	// Final batch flush.
	if batch.ValueSize() > 0 {
		if err := batch.Write(); err != nil {
			return types.Hash{}, fmt.Errorf("batch write: %w", err)
		}
	}

	// Verify we consumed exactly the payload (no trailing garbage).
	if pos != len(payload) {
		return types.Hash{}, fmt.Errorf("snapshot has %d trailing bytes after entries", len(payload)-pos)
	}

	return root, nil
}
