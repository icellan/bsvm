package beef

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/icellan/bsvm/internal/db"
)

// Envelope is the in-store representation of a BEEF, combining the
// gossip envelope metadata with the BRC-62 body and bookkeeping fields
// the overlay needs (confirmation state, block height, receive time).
//
// The byte layout when serialised to the LevelDB-backed store is:
//
//	[ 17 bytes ] gossip envelope header
//	[ 1 byte  ] confirmed flag (0x00 / 0x01)
//	[ 8 bytes ] block height (BE uint64; 0 when unconfirmed)
//	[ 8 bytes ] received-at unix nanoseconds (BE int64)
//	[ varint  ] BEEF body length
//	[ N bytes ] BEEF body
//
// This lets the in-memory and LevelDB stores share a single codec.
type Envelope struct {
	Header      EnvelopeHeader
	Beef        []byte
	TargetTxID  [32]byte
	Confirmed   bool
	BlockHeight uint64
	ReceivedAt  time.Time
}

// Encode serialises e into the on-disk byte layout.
func (e *Envelope) Encode() ([]byte, error) {
	hdr, err := e.Header.Encode()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, EnvelopeHeaderSize+1+8+8+9+len(e.Beef))
	out = append(out, hdr...)
	if e.Confirmed {
		out = append(out, 0x01)
	} else {
		out = append(out, 0x00)
	}
	var heightBuf [8]byte
	binary.BigEndian.PutUint64(heightBuf[:], e.BlockHeight)
	out = append(out, heightBuf[:]...)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.ReceivedAt.UnixNano()))
	out = append(out, tsBuf[:]...)
	out = append(out, encodeVarInt(uint64(len(e.Beef)))...)
	out = append(out, e.Beef...)
	return out, nil
}

// DecodeStoredEnvelope parses the on-disk byte layout produced by
// Envelope.Encode.
func DecodeStoredEnvelope(buf []byte) (*Envelope, error) {
	hdr, rest, err := DecodeEnvelopeHeader(buf)
	if err != nil {
		return nil, err
	}
	if len(rest) < 1+8+8 {
		return nil, errors.New("beef: stored envelope truncated")
	}
	out := &Envelope{Header: hdr}
	out.Confirmed = rest[0] == 0x01
	out.BlockHeight = binary.BigEndian.Uint64(rest[1:9])
	out.ReceivedAt = time.Unix(0, int64(binary.BigEndian.Uint64(rest[9:17]))).UTC()
	rest = rest[17:]
	bodyLen, n, err := readVarInt(rest)
	if err != nil {
		return nil, fmt.Errorf("beef: stored envelope body length: %w", err)
	}
	rest = rest[n:]
	if uint64(len(rest)) < bodyLen {
		return nil, errors.New("beef: stored envelope body truncated")
	}
	out.Beef = append([]byte(nil), rest[:bodyLen]...)
	return out, nil
}

// encodeVarInt writes a Bitcoin compact-size varint.
func encodeVarInt(v uint64) []byte {
	switch {
	case v < 0xfd:
		return []byte{byte(v)}
	case v <= 0xffff:
		out := make([]byte, 3)
		out[0] = 0xfd
		binary.LittleEndian.PutUint16(out[1:], uint16(v))
		return out
	case v <= 0xffffffff:
		out := make([]byte, 5)
		out[0] = 0xfe
		binary.LittleEndian.PutUint32(out[1:], uint32(v))
		return out
	default:
		out := make([]byte, 9)
		out[0] = 0xff
		binary.LittleEndian.PutUint64(out[1:], v)
		return out
	}
}

// Store is the persistence layer for BEEFs. Implementations are keyed
// by the target tx ID. Calls are safe for concurrent use.
type Store interface {
	// Put inserts or upgrades the envelope for env.TargetTxID. A
	// confirmed envelope replaces an unconfirmed one for the same
	// txid; among confirmed envelopes the deeper block-height wins.
	Put(env *Envelope) error
	// Get returns the envelope for txid, or nil if absent.
	Get(txid [32]byte) (*Envelope, error)
	// Has reports whether the store contains an envelope for txid.
	Has(txid [32]byte) (bool, error)
	// Delete removes the envelope for txid. No-op if absent.
	Delete(txid [32]byte) error
	// Iterate visits every envelope of the given intent in
	// receive-time order (oldest first). intent == 0 visits all.
	Iterate(intent byte, visit func(*Envelope) bool) error
}

// MemoryStore is an in-memory Store implementation backed by a
// concurrent map. Suitable for dev and tests; production wiring uses
// LevelStore for durability.
type MemoryStore struct {
	mu sync.RWMutex
	m  map[[32]byte]*Envelope
}

// NewMemoryStore returns a fresh MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{m: make(map[[32]byte]*Envelope)}
}

// Put implements Store.
func (s *MemoryStore) Put(env *Envelope) error {
	if env == nil {
		return errors.New("beef: nil envelope")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.m[env.TargetTxID]
	if ok && shouldKeepExisting(existing, env) {
		return nil
	}
	s.m[env.TargetTxID] = cloneEnvelope(env)
	return nil
}

// Get implements Store.
func (s *MemoryStore) Get(txid [32]byte) (*Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.m[txid]; ok {
		return cloneEnvelope(e), nil
	}
	return nil, nil
}

// Has implements Store.
func (s *MemoryStore) Has(txid [32]byte) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.m[txid]
	return ok, nil
}

// Delete implements Store.
func (s *MemoryStore) Delete(txid [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, txid)
	return nil
}

// Iterate implements Store.
func (s *MemoryStore) Iterate(intent byte, visit func(*Envelope) bool) error {
	s.mu.RLock()
	envs := make([]*Envelope, 0, len(s.m))
	for _, e := range s.m {
		if intent != 0 && e.Header.Intent != intent {
			continue
		}
		envs = append(envs, cloneEnvelope(e))
	}
	s.mu.RUnlock()
	// Sort oldest-first by ReceivedAt for deterministic iteration.
	sortEnvelopes(envs)
	for _, e := range envs {
		if !visit(e) {
			return nil
		}
	}
	return nil
}

// LevelStore is a durable Store backed by an internal/db.Database
// (typically LevelDB or Pebble). All envelopes share a `beef:` key
// prefix per spec 17.
type LevelStore struct {
	db db.Database
}

// NewLevelStore wraps a Database with the BEEF Store API. The same
// Database may host other keyspaces; this store only writes keys
// under the `beef:` prefix.
func NewLevelStore(database db.Database) *LevelStore {
	return &LevelStore{db: database}
}

var levelKeyPrefix = []byte("beef:")

func levelKey(txid [32]byte) []byte {
	out := make([]byte, 0, len(levelKeyPrefix)+32)
	out = append(out, levelKeyPrefix...)
	out = append(out, txid[:]...)
	return out
}

// Put implements Store.
func (s *LevelStore) Put(env *Envelope) error {
	if env == nil {
		return errors.New("beef: nil envelope")
	}
	key := levelKey(env.TargetTxID)
	existingBytes, err := s.db.Get(key)
	if err != nil && err != db.ErrNotFound {
		return fmt.Errorf("beef: get existing: %w", err)
	}
	if existingBytes != nil {
		existing, derr := DecodeStoredEnvelope(existingBytes)
		if derr == nil && shouldKeepExisting(existing, env) {
			return nil
		}
	}
	encoded, err := env.Encode()
	if err != nil {
		return err
	}
	return s.db.Put(key, encoded)
}

// Get implements Store.
func (s *LevelStore) Get(txid [32]byte) (*Envelope, error) {
	val, err := s.db.Get(levelKey(txid))
	if err == db.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("beef: get: %w", err)
	}
	return DecodeStoredEnvelope(val)
}

// Has implements Store.
func (s *LevelStore) Has(txid [32]byte) (bool, error) {
	ok, err := s.db.Has(levelKey(txid))
	if err != nil {
		return false, fmt.Errorf("beef: has: %w", err)
	}
	return ok, nil
}

// Delete implements Store.
func (s *LevelStore) Delete(txid [32]byte) error {
	return s.db.Delete(levelKey(txid))
}

// Iterate implements Store. It uses the underlying database's prefix
// iterator if available; otherwise it returns ErrIterateUnsupported.
func (s *LevelStore) Iterate(intent byte, visit func(*Envelope) bool) error {
	it, ok := s.db.(db.Iteratee)
	if !ok {
		return ErrIterateUnsupported
	}
	iter := it.NewIterator(levelKeyPrefix, nil)
	defer iter.Release()
	envs := make([]*Envelope, 0)
	for iter.Next() {
		env, err := DecodeStoredEnvelope(iter.Value())
		if err != nil {
			continue
		}
		if intent != 0 && env.Header.Intent != intent {
			continue
		}
		envs = append(envs, env)
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("beef: iterate: %w", err)
	}
	sortEnvelopes(envs)
	for _, e := range envs {
		if !visit(e) {
			return nil
		}
	}
	return nil
}

// ErrIterateUnsupported is returned by LevelStore.Iterate when the
// underlying database does not implement the Iteratee interface.
var ErrIterateUnsupported = errors.New("beef: iterate unsupported on this database")

// shouldKeepExisting reports whether the existing envelope in the
// store is "better" than the new one and should be retained per spec
// 17's "confirmed beats unconfirmed; deeper BUMP wins" rule.
func shouldKeepExisting(existing, incoming *Envelope) bool {
	if existing.Confirmed && !incoming.Confirmed {
		return true
	}
	if existing.Confirmed && incoming.Confirmed && existing.BlockHeight >= incoming.BlockHeight {
		return true
	}
	return false
}

func cloneEnvelope(e *Envelope) *Envelope {
	if e == nil {
		return nil
	}
	out := *e
	out.Beef = append([]byte(nil), e.Beef...)
	return &out
}

// sortEnvelopes orders envs oldest-first by ReceivedAt. Stable order
// across stores so tests can assert deterministic output.
func sortEnvelopes(envs []*Envelope) {
	for i := 1; i < len(envs); i++ {
		for j := i; j > 0 && envs[j-1].ReceivedAt.After(envs[j].ReceivedAt); j-- {
			envs[j-1], envs[j] = envs[j], envs[j-1]
		}
	}
}
