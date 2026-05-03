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

// UpgradePayload carries the SP1 proof bundle and rotation-target
// bindings that pkg/covenant.BuildUpgradeUnlockScript needs to
// assemble an upgrade-tx unlock script. It is OPTIONAL on the
// Proposal struct — only `upgrade` proposals carry one. Freeze and
// unfreeze proposals leave it nil and the broadcaster's
// dispatchUpgrade is the only consumer.
//
// All hex fields are encoded WITHOUT a 0x prefix and without
// surrounding whitespace; the decoder uses encoding/hex directly.
//
// The struct is part of the canonical signing bytes — signers see
// the full upgrade-tx-they-are-authorising before signing. See
// docs/operator/vk-rotation.md §6 "Multisig flow via governance
// proposals" for the operator workflow.
type UpgradePayload struct {
	// PublicValuesHex is the 280-byte SP1 public-values blob the
	// rotation's STARK proof commits to (covenant.UpgradeRequest.PublicValues).
	// Decoded length MUST be 280; the broadcaster surfaces a typed
	// error if it isn't.
	PublicValuesHex string `json:"publicValuesHex"`

	// BatchDataHex is the canonical batch encoding the proof commits
	// to (covenant.UpgradeRequest.BatchData). Hex-encoded.
	BatchDataHex string `json:"batchDataHex"`

	// ProofBlobHex is the SP1 STARK proof bytes
	// (covenant.UpgradeRequest.ProofBlob). Hex-encoded.
	ProofBlobHex string `json:"proofBlobHex"`

	// CurrentStateRootHex is the live covenant's pre-upgrade StateRoot
	// (covenant.UpgradeRequest.CurrentStateRoot). 32 bytes hex.
	CurrentStateRootHex string `json:"currentStateRootHex"`

	// CurrentBlockNumber is the live covenant's pre-upgrade
	// BlockNumber (covenant.UpgradeRequest.CurrentBlockNumber). The
	// upgrade tx advances this to CurrentBlockNumber + 1.
	CurrentBlockNumber uint64 `json:"currentBlockNumber"`

	// NewCovenantAnfHashHex is the 32-byte hash256 of the canonical
	// ANF document for the new covenant
	// (covenant.UpgradeRequest.NewCovenantAnfHash). Bound into the
	// spec-10 migration OP_RETURN.
	NewCovenantAnfHashHex string `json:"newCovenantAnfHashHex"`

	// NewCovenantScriptHex is the new covenant locking script bytes
	// (covenant.UpgradeRequest.NewCovenantScript). The upgrade method
	// asserts pv[240..272) == hash256(NewCovenantScript) so the proof
	// binds the migration target.
	NewCovenantScriptHex string `json:"newCovenantScriptHex"`

	// ChainID is the EIP-155 chain id (covenant.UpgradeRequest.ChainID).
	// Encoded LE into pv[136..144). MUST match the live covenant's
	// ChainId readonly.
	ChainID uint64 `json:"chainId"`
}

// Proposal is the canonical on-wire governance proposal. The `ID`
// field is a content hash; everything else below it is content.
type Proposal struct {
	// ID is sha256(canonicalJSON({action, params, upgradePayload})) —
	// the content hash identifying the proposal. The upgrade payload
	// is folded into the hash so signers commit to the exact
	// rotation tx they are authorising; freeze/unfreeze proposals
	// leave UpgradePayload nil and only (action, params) feed the hash.
	ID string `json:"id"`

	// Action selects the governance entry point (freeze / unfreeze /
	// upgrade).
	Action Action `json:"action"`

	// Params is the opaque action-specific payload. For "freeze" and
	// "unfreeze" this is empty (the action speaks for itself); for
	// "upgrade" it MAY carry the new covenant script hex for backwards
	// compatibility, but the canonical payload now lives in
	// UpgradePayload.
	Params json.RawMessage `json:"params,omitempty"`

	// UpgradePayload is the rotation bundle for `upgrade` proposals.
	// nil for freeze/unfreeze. Carried omitempty so the gossip wire
	// format stays backwards-compatible: existing freeze/unfreeze
	// proposals serialise to the same bytes they did before this
	// field existed.
	UpgradePayload *UpgradePayload `json:"upgradePayload,omitempty"`

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
//
// For upgrade proposals carrying an SP1 proof bundle, prefer
// NewUpgradeProposal — it folds the upgrade-payload bindings into the
// content hash and the canonical JSON the signers see.
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
	id, err := contentID(action, params, nil)
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

// NewUpgradeProposal constructs an `upgrade` proposal with the SP1
// proof bundle + rotation-target bindings folded into the content
// hash. Two nodes independently building the same upgrade proposal
// (same payload) produce identical IDs — the foundation for the
// gossip-driven multisig coordination.
//
// The payload's hex fields are copied verbatim into the proposal —
// callers are expected to pass valid hex; the broadcaster's
// dispatchUpgrade re-validates lengths before assembling the
// unlock script.
func NewUpgradeProposal(payload UpgradePayload, required int, expiry time.Duration) (*Proposal, error) {
	if required < 1 {
		return nil, errors.New("required signatures must be >= 1")
	}
	if payload.NewCovenantScriptHex == "" {
		return nil, errors.New("upgrade payload: newCovenantScriptHex is required")
	}
	if payload.PublicValuesHex == "" {
		return nil, errors.New("upgrade payload: publicValuesHex is required")
	}
	if payload.BatchDataHex == "" {
		return nil, errors.New("upgrade payload: batchDataHex is required")
	}
	if payload.ProofBlobHex == "" {
		return nil, errors.New("upgrade payload: proofBlobHex is required")
	}
	if payload.CurrentStateRootHex == "" {
		return nil, errors.New("upgrade payload: currentStateRootHex is required")
	}
	if payload.NewCovenantAnfHashHex == "" {
		return nil, errors.New("upgrade payload: newCovenantAnfHashHex is required")
	}
	if expiry <= 0 {
		expiry = DefaultExpiry
	}
	pCopy := payload
	id, err := contentID(ActionUpgrade, nil, &pCopy)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &Proposal{
		ID:             id,
		Action:         ActionUpgrade,
		UpgradePayload: &pCopy,
		Required:       required,
		Signatures:     map[string]string{},
		CreatedAt:      now,
		ExpiresAt:      now.Add(expiry),
	}, nil
}

// contentID computes the canonical content hash keying a proposal.
// Two nodes independently constructing the same proposal (same
// action, same params, same upgrade payload) produce identical IDs —
// the foundation for idempotent gossip merges.
//
// For freeze/unfreeze proposals, upgradePayload is nil and the body
// shape is {action, params} — byte-identical to the pre-payload-extension
// hash so existing freeze/unfreeze proposal IDs do not drift.
//
// For upgrade proposals built via NewUpgradeProposal, upgradePayload
// is non-nil and the body shape is {action, params, upgradePayload};
// the payload bindings (state root, block number, new script, proof
// bundle) are folded in so signers commit to the exact upgrade tx
// they are authorising.
func contentID(action Action, params json.RawMessage, payload *UpgradePayload) (string, error) {
	if params == nil {
		params = json.RawMessage("null")
	}
	if payload == nil {
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
	body := struct {
		Action         Action          `json:"action"`
		Params         json.RawMessage `json:"params"`
		UpgradePayload *UpgradePayload `json:"upgradePayload"`
	}{Action: action, Params: params, UpgradePayload: payload}
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
	if p.UpgradePayload != nil {
		payloadCopy := *p.UpgradePayload
		out.UpgradePayload = &payloadCopy
	}
	return &out
}
