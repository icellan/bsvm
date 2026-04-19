package governance

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestContentID_IsStableAndOrderAware(t *testing.T) {
	a, err := contentID(ActionFreeze, json.RawMessage(`{"x":1}`))
	if err != nil {
		t.Fatalf("contentID: %v", err)
	}
	b, err := contentID(ActionFreeze, json.RawMessage(`{"x":1}`))
	if err != nil {
		t.Fatalf("contentID: %v", err)
	}
	if a != b {
		t.Errorf("same inputs produced different IDs: %s vs %s", a, b)
	}
	c, _ := contentID(ActionUnfreeze, json.RawMessage(`{"x":1}`))
	if a == c {
		t.Errorf("different actions must produce different IDs")
	}
	d, _ := contentID(ActionFreeze, json.RawMessage(`{"x":2}`))
	if a == d {
		t.Errorf("different params must produce different IDs")
	}
}

func TestNewProposal_ValidationRejectsEmptyAction(t *testing.T) {
	_, err := NewProposal("", nil, 1, 0)
	if err == nil {
		t.Error("expected error for empty action")
	}
}

func TestNewProposal_ValidationRejectsZeroRequired(t *testing.T) {
	_, err := NewProposal(ActionFreeze, nil, 0, 0)
	if err == nil {
		t.Error("expected error for zero Required")
	}
}

func TestProposal_Ready(t *testing.T) {
	p, err := NewProposal(ActionFreeze, nil, 2, time.Hour)
	if err != nil {
		t.Fatalf("NewProposal: %v", err)
	}
	if p.Ready() {
		t.Error("brand new proposal should not be Ready")
	}
	p.AddSignature("02aa", "sig1")
	if p.Ready() {
		t.Error("1 of 2 should not be Ready")
	}
	p.AddSignature("02bb", "sig2")
	if !p.Ready() {
		t.Error("2 of 2 should be Ready")
	}
}

func TestProposal_MergeSignaturesIsIdempotent(t *testing.T) {
	p1, _ := NewProposal(ActionFreeze, nil, 3, time.Hour)
	p1.AddSignature("02aa", "sig1")
	p2, _ := NewProposal(ActionFreeze, nil, 3, time.Hour)
	p2.AddSignature("02bb", "sig2")
	p2.AddSignature("02aa", "sig1-DIFFERENT") // spoof attempt

	p1.MergeSignatures(p2)
	if got := p1.Signatures["02aa"]; got != "sig1" {
		t.Errorf("existing signature must be preserved on merge; got %q", got)
	}
	if got := p1.Signatures["02bb"]; got != "sig2" {
		t.Errorf("new signature must be added on merge; got %q", got)
	}
}

func TestMemoryStore_CRUD(t *testing.T) {
	s := NewMemoryStore()
	p, _ := NewProposal(ActionFreeze, nil, 1, time.Hour)
	if err := s.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, _ := s.Get(p.ID)
	if got == nil || got.ID != p.ID {
		t.Fatalf("Get: expected proposal, got %v", got)
	}

	list, _ := s.List()
	if len(list) != 1 {
		t.Errorf("List: expected 1 proposal, got %d", len(list))
	}

	if err := s.Delete(p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ = s.Get(p.ID)
	if got != nil {
		t.Errorf("Get after Delete should return nil, got %v", got)
	}
}

func TestMemoryStore_ExpireBefore(t *testing.T) {
	s := NewMemoryStore()
	p, _ := NewProposal(ActionFreeze, nil, 1, time.Hour)
	_ = s.Put(p)
	// Pretend we've arrived 2h after creation.
	future := p.CreatedAt.Add(2 * time.Hour)
	if err := s.ExpireBefore(future); err != nil {
		t.Fatalf("ExpireBefore: %v", err)
	}
	list, _ := s.List()
	if len(list) != 0 {
		t.Errorf("expired proposal should be swept; still have %d", len(list))
	}
}

func TestWorkflow_CreateOrMerge_DedupesBySameID(t *testing.T) {
	store := NewMemoryStore()
	broadcasts := 0
	wf := NewWorkflow(store, func(p *Proposal) error { broadcasts++; return nil }, nil)

	p1, _ := NewProposal(ActionFreeze, json.RawMessage("null"), 2, time.Hour)
	p1.AddSignature("02aa", "sigA")
	if _, err := wf.CreateOrMerge(p1); err != nil {
		t.Fatalf("CreateOrMerge #1: %v", err)
	}

	// Independent proposal with the SAME content hash, carrying a
	// different signature. Must merge rather than clobber.
	p2, _ := NewProposal(ActionFreeze, json.RawMessage("null"), 2, time.Hour)
	p2.AddSignature("02bb", "sigB")
	got, err := wf.CreateOrMerge(p2)
	if err != nil {
		t.Fatalf("CreateOrMerge #2: %v", err)
	}
	if len(got.Signatures) != 2 {
		t.Errorf("expected merged signatures (2), got %d", len(got.Signatures))
	}
	if broadcasts != 1 {
		t.Errorf("expected one broadcast (only the first create), got %d", broadcasts)
	}
}

func TestWorkflow_Sign_RejectsBadSignatures(t *testing.T) {
	store := NewMemoryStore()
	wf := NewWorkflow(store, nil, func(id, sig string) ([]byte, error) {
		return nil, errors.New("invalid signature")
	})
	p, _ := NewProposal(ActionFreeze, nil, 1, time.Hour)
	_, _ = wf.CreateOrMerge(p)
	_, err := wf.Sign(p.ID, "garbage")
	if err == nil {
		t.Error("expected Sign to reject bad signature")
	}
}

func TestWorkflow_Sign_ValidFiresReadyCallback(t *testing.T) {
	store := NewMemoryStore()
	firedID := ""
	wf := NewWorkflow(store, nil, func(id, sig string) ([]byte, error) {
		return []byte{0x02, 0xaa}, nil
	})
	wf.OnReady(func(p *Proposal) { firedID = p.ID })

	p, _ := NewProposal(ActionFreeze, nil, 1, time.Hour)
	if _, err := wf.CreateOrMerge(p); err != nil {
		t.Fatalf("CreateOrMerge: %v", err)
	}
	if _, err := wf.Sign(p.ID, "valid"); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if firedID != p.ID {
		t.Errorf("expected OnReady to fire for %s; fired for %q", p.ID, firedID)
	}
}
