// Package governance manages the multisig proposal workflow described
// in spec 15. A proposal captures a pending freeze / unfreeze /
// upgrade action; governance key-holders sign it over libp2p gossip;
// once the signature count meets the threshold the proposal is
// broadcast to BSV.
//
// Design notes:
//
//   - Identity. Proposals are keyed by a content-addressed 32-byte ID
//     (sha256 over action || params). The content hash guarantees the
//     same proposal proposed from two nodes deduplicates naturally.
//   - Storage. v1 uses an in-memory sync.Map. The Store interface is
//     defined so a Pebble-backed implementation can drop in without
//     changing callers. v1 gossip replicates proposals across peers
//     on every join so a node restart isn't catastrophic.
//   - Signatures. Keyed by the hex-encoded compressed secp256k1
//     pubkey. Duplicate signatures from the same key are idempotent
//     — "merge" is set-union, not append.
package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Action identifies what the proposal will execute when the signature
// threshold is met.
type Action string

const (
	ActionFreeze   Action = "freeze"
	ActionUnfreeze Action = "unfreeze"
	ActionUpgrade  Action = "upgrade"
)

// DefaultExpiry is the maximum age an unsigned proposal is kept. Past
// this point the store sweeps it and peers ignore re-announcements.
// Matches the spec 15 default (24 hours).
const DefaultExpiry = 24 * time.Hour

// Proposal is the canonical on-wire governance proposal. The `ID`
// field is a content hash; everything else below it is content.
type Proposal struct {
	// ID is sha256(canonicalJSON({action, params})) — the content
	// hash identifying the proposal.
	ID string `json:"id"`

	// Action selects the governance entry point (freeze / unfreeze /
	// upgrade).
	Action Action `json:"action"`

	// Params is the opaque action-specific payload. For "freeze" and
	// "unfreeze" this is empty (the action speaks for itself); for
	// "upgrade" it's the new covenant script hex.
	Params json.RawMessage `json:"params,omitempty"`

	// Required is the number of signatures needed to broadcast.
	// Copied from the shard's governance config at create time.
	Required int `json:"required"`

	// Signatures is keyed by hex(compressedPubkey) → DER signature
	// bytes (hex). Duplicate entries are idempotent.
	Signatures map[string]string `json:"signatures,omitempty"`

	// CreatedAt is the wall-clock time the proposal was first seen.
	CreatedAt time.Time `json:"createdAt"`

	// ExpiresAt is CreatedAt + expiry window. Proposals past this
	// are pruned from local storage and ignored on gossip.
	ExpiresAt time.Time `json:"expiresAt"`

	// BroadcastTxID is the BSV txid once the proposal has been
	// submitted (ie. threshold met). Empty while awaiting signatures.
	BroadcastTxID string `json:"broadcastTxid,omitempty"`
}

// NewProposal constructs a new proposal with the content-hash ID
// derived from (action, params). The caller passes the governance
// threshold from the shard config.
func NewProposal(action Action, params json.RawMessage, required int, expiry time.Duration) (*Proposal, error) {
	if action == "" {
		return nil, errors.New("action is required")
	}
	if required < 1 {
		return nil, errors.New("required signatures must be >= 1")
	}
	if expiry <= 0 {
		expiry = DefaultExpiry
	}
	id, err := contentID(action, params)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &Proposal{
		ID:         id,
		Action:     action,
		Params:     params,
		Required:   required,
		Signatures: map[string]string{},
		CreatedAt:  now,
		ExpiresAt:  now.Add(expiry),
	}, nil
}

// contentID computes the canonical content hash keying a proposal.
// Two nodes independently constructing the same proposal (same
// action, same params) produce identical IDs — the foundation for
// idempotent gossip merges.
func contentID(action Action, params json.RawMessage) (string, error) {
	if params == nil {
		params = json.RawMessage("null")
	}
	body := struct {
		Action Action          `json:"action"`
		Params json.RawMessage `json:"params"`
	}{Action: action, Params: params}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// AddSignature records a signature by a governance key. Returns the
// post-merge proposal so the caller can check if Ready() is now true.
// Idempotent — the same key signing twice is a no-op.
func (p *Proposal) AddSignature(pubKeyHex, sigHex string) {
	if p.Signatures == nil {
		p.Signatures = make(map[string]string)
	}
	p.Signatures[pubKeyHex] = sigHex
}

// Ready reports whether enough valid signatures have been collected
// to broadcast. It does NOT re-verify individual signatures —
// callers enforce signature validity before AddSignature.
func (p *Proposal) Ready() bool {
	return len(p.Signatures) >= p.Required
}

// Expired reports whether the proposal is past its ExpiresAt.
func (p *Proposal) Expired() bool {
	return time.Now().UTC().After(p.ExpiresAt)
}

// MergeSignatures copies new signatures from `other` into this
// proposal, preserving any existing ones. Used by the gossip merger
// when two nodes see partial signature sets.
func (p *Proposal) MergeSignatures(other *Proposal) {
	if other == nil {
		return
	}
	if p.Signatures == nil {
		p.Signatures = make(map[string]string)
	}
	for k, v := range other.Signatures {
		if _, exists := p.Signatures[k]; !exists {
			p.Signatures[k] = v
		}
	}
}

// Store is the minimal interface the governance workflow uses to
// persist proposals. The default implementation is in-memory;
// Pebble-backed storage is a follow-up.
type Store interface {
	Put(p *Proposal) error
	Get(id string) (*Proposal, error)
	List() ([]*Proposal, error)
	Delete(id string) error
	ExpireBefore(t time.Time) error
}

// MemoryStore is an in-memory Store backed by sync.Map. Safe for
// concurrent use.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]*Proposal
}

// NewMemoryStore constructs an empty in-memory proposal store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]*Proposal)}
}

// Put inserts or replaces a proposal by its ID. Caller merges
// signatures before calling Put if necessary.
func (s *MemoryStore) Put(p *Proposal) error {
	if p == nil || p.ID == "" {
		return errors.New("proposal must have an ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[p.ID] = p
	return nil
}

// Get returns the stored proposal, or nil if the ID is unknown.
func (s *MemoryStore) Get(id string) (*Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[id]
	if !ok {
		return nil, nil
	}
	return clone(p), nil
}

// List returns a copy of every stored proposal. Callers treat the
// returned slice as read-only; storage retains its own copies.
func (s *MemoryStore) List() ([]*Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Proposal, 0, len(s.items))
	for _, p := range s.items {
		out = append(out, clone(p))
	}
	// Stable order by CreatedAt (oldest first) for predictable RPC output.
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// Delete removes a proposal by ID. Missing IDs are not an error.
func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
	return nil
}

// ExpireBefore removes every proposal whose ExpiresAt is strictly
// before the given time. Returns nil even if nothing was removed.
func (s *MemoryStore) ExpireBefore(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.items {
		if p.ExpiresAt.Before(t) {
			delete(s.items, id)
		}
	}
	return nil
}

// clone returns a deep copy of a proposal so the store's internal
// state can't be mutated by a caller that holds a pointer.
func clone(p *Proposal) *Proposal {
	if p == nil {
		return nil
	}
	out := *p
	if p.Signatures != nil {
		out.Signatures = make(map[string]string, len(p.Signatures))
		for k, v := range p.Signatures {
			out.Signatures[k] = v
		}
	}
	if p.Params != nil {
		out.Params = append(json.RawMessage(nil), p.Params...)
	}
	return &out
}
