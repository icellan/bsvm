package governance

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// GossipBroadcaster is the minimal callback the workflow uses to
// announce a new proposal to peers. The governance package doesn't
// depend on libp2p — a simple broadcast-by-value callback is enough.
type GossipBroadcaster func(p *Proposal) error

// SigVerifier validates a governance signature. Returns the
// compressed pubkey that signed the proposal (if valid) so the
// workflow can key it into Proposal.Signatures. Returning an empty
// slice + non-nil error rejects the signature.
type SigVerifier func(proposalID string, sigHex string) (compressedPub []byte, err error)

// Workflow is the higher-level orchestration layer around Store +
// gossip. Admin handlers call Create / Sign; background sweeper
// calls ExpireLoop.
type Workflow struct {
	store         Store
	broadcaster   GossipBroadcaster
	sigVerifier   SigVerifier
	readyCallback func(p *Proposal)
	mu            sync.Mutex
}

// NewWorkflow constructs a workflow with the given storage backend,
// gossip broadcaster, and signature verifier. Any of the callbacks
// may be nil for tests — the workflow degrades gracefully.
func NewWorkflow(store Store, broadcaster GossipBroadcaster, verify SigVerifier) *Workflow {
	return &Workflow{
		store:       store,
		broadcaster: broadcaster,
		sigVerifier: verify,
	}
}

// OnReady registers a callback invoked exactly once per proposal the
// moment its signature count crosses the threshold. Used by the
// admin layer to schedule the BSV broadcast.
func (w *Workflow) OnReady(cb func(p *Proposal)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.readyCallback = cb
}

// CreateOrMerge stores the proposal. When the store already knows
// about the ID, signatures are merged rather than overwritten — a
// replay of a proposal from a peer must never erase local
// signatures.
func (w *Workflow) CreateOrMerge(p *Proposal) (*Proposal, error) {
	if p == nil {
		return nil, errors.New("proposal must not be nil")
	}
	if p.Expired() {
		return nil, errors.New("proposal has already expired")
	}

	existing, _ := w.store.Get(p.ID)
	if existing != nil {
		// Merge signatures; keep the older CreatedAt and ExpiresAt so
		// a gossip replay can't extend a proposal's lifetime.
		existing.MergeSignatures(p)
		if err := w.store.Put(existing); err != nil {
			return nil, err
		}
		w.maybeReady(existing)
		return clone(existing), nil
	}

	if err := w.store.Put(p); err != nil {
		return nil, err
	}
	if w.broadcaster != nil {
		// Best-effort gossip. A failure here is logged elsewhere;
		// local storage already reflects the new proposal.
		_ = w.broadcaster(p)
	}
	w.maybeReady(p)
	return clone(p), nil
}

// Sign adds a signature to an existing proposal. The workflow
// verifies the signature against `proposal.ID` — the content hash —
// and records the signer's compressed pubkey. Re-signs by the same
// key are idempotent.
func (w *Workflow) Sign(proposalID, sigHex string) (*Proposal, error) {
	if w.sigVerifier == nil {
		return nil, errors.New("workflow has no signature verifier")
	}
	existing, _ := w.store.Get(proposalID)
	if existing == nil {
		return nil, errors.New("proposal not found")
	}
	if existing.Expired() {
		return nil, errors.New("proposal has expired")
	}

	pub, err := w.sigVerifier(proposalID, sigHex)
	if err != nil {
		return nil, err
	}
	if len(pub) == 0 {
		return nil, errors.New("signature did not yield a valid pubkey")
	}

	existing.AddSignature(hex.EncodeToString(pub), sigHex)
	if err := w.store.Put(existing); err != nil {
		return nil, err
	}
	if w.broadcaster != nil {
		_ = w.broadcaster(existing)
	}
	w.maybeReady(existing)
	return clone(existing), nil
}

// List returns all stored proposals, newest first.
func (w *Workflow) List() ([]*Proposal, error) {
	return w.store.List()
}

// ExpireOnce runs a single expiry sweep, removing proposals whose
// ExpiresAt is before the given time. Production nodes spin this in
// a loop; tests call it deterministically with a pinned clock.
func (w *Workflow) ExpireOnce(now time.Time) error {
	return w.store.ExpireBefore(now)
}

// maybeReady fires the readyCallback the moment a proposal crosses
// the threshold. It's fine to call this every time Put runs — the
// callback itself is responsible for idempotency (e.g. by checking
// Proposal.BroadcastTxID before acting).
func (w *Workflow) maybeReady(p *Proposal) {
	w.mu.Lock()
	cb := w.readyCallback
	w.mu.Unlock()
	if cb != nil && p.Ready() && p.BroadcastTxID == "" {
		cb(clone(p))
	}
}
