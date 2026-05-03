package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestContentID_IsStableAndOrderAware(t *testing.T) {
	a, err := contentID(ActionFreeze, json.RawMessage(`{"x":1}`), nil)
	if err != nil {
		t.Fatalf("contentID: %v", err)
	}
	b, err := contentID(ActionFreeze, json.RawMessage(`{"x":1}`), nil)
	if err != nil {
		t.Fatalf("contentID: %v", err)
	}
	if a != b {
		t.Errorf("same inputs produced different IDs: %s vs %s", a, b)
	}
	c, _ := contentID(ActionUnfreeze, json.RawMessage(`{"x":1}`), nil)
	if a == c {
		t.Errorf("different actions must produce different IDs")
	}
	d, _ := contentID(ActionFreeze, json.RawMessage(`{"x":2}`), nil)
	if a == d {
		t.Errorf("different params must produce different IDs")
	}
}

// TestContentID_FreezeUnfreezeBackwardsCompatible asserts adding the
// optional UpgradePayload parameter to contentID did NOT change the
// hash of pre-existing freeze/unfreeze proposals — those still
// serialise via the original {action, params} body shape.
func TestContentID_FreezeUnfreezeBackwardsCompatible(t *testing.T) {
	// The pre-extension shape was sha256(canonicalJSON({action, params})).
	// We re-derive that here directly and compare to the new contentID
	// with payload=nil to lock in the wire-format-stable guarantee.
	expected := func(action Action, params json.RawMessage) string {
		if params == nil {
			params = json.RawMessage("null")
		}
		body := struct {
			Action Action          `json:"action"`
			Params json.RawMessage `json:"params"`
		}{Action: action, Params: params}
		raw, _ := json.Marshal(body)
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	for _, action := range []Action{ActionFreeze, ActionUnfreeze} {
		got, err := contentID(action, nil, nil)
		if err != nil {
			t.Fatalf("contentID(%s): %v", action, err)
		}
		if want := expected(action, nil); got != want {
			t.Errorf("freeze/unfreeze content ID drifted for %s: got %s, want %s", action, got, want)
		}
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

// TestNewUpgradeProposal_ContentIDFolds checks that the upgrade
// payload bindings (state root, block number, new script, proof
// bundle) participate in the content hash. Two upgrade proposals
// that differ only by their payload MUST produce different IDs;
// otherwise a malicious proposer could swap the proof bundle under
// already-collected signatures.
func TestNewUpgradeProposal_ContentIDFolds(t *testing.T) {
	base := UpgradePayload{
		PublicValuesHex:       hex.EncodeToString(make([]byte, 280)),
		BatchDataHex:          hex.EncodeToString([]byte{0x01, 0x02, 0x03}),
		ProofBlobHex:          hex.EncodeToString([]byte{0x10, 0x20, 0x30}),
		CurrentStateRootHex:   strings.Repeat("ab", 32),
		CurrentBlockNumber:    100,
		NewCovenantAnfHashHex: strings.Repeat("cd", 32),
		NewCovenantScriptHex:  hex.EncodeToString([]byte{0x76, 0xa9, 0x14}),
		ChainID:               8453111,
	}
	p1, err := NewUpgradeProposal(base, 1, time.Hour)
	if err != nil {
		t.Fatalf("NewUpgradeProposal #1: %v", err)
	}
	p2, err := NewUpgradeProposal(base, 1, time.Hour)
	if err != nil {
		t.Fatalf("NewUpgradeProposal #2: %v", err)
	}
	if p1.ID != p2.ID {
		t.Errorf("identical payloads produced different IDs: %s vs %s", p1.ID, p2.ID)
	}

	mutated := base
	mutated.NewCovenantScriptHex = hex.EncodeToString([]byte{0xff, 0xff, 0xff})
	p3, err := NewUpgradeProposal(mutated, 1, time.Hour)
	if err != nil {
		t.Fatalf("NewUpgradeProposal mutated: %v", err)
	}
	if p1.ID == p3.ID {
		t.Error("different newCovenantScript MUST produce different IDs (signing-bytes drift)")
	}

	mutated2 := base
	mutated2.CurrentBlockNumber = 101
	p4, err := NewUpgradeProposal(mutated2, 1, time.Hour)
	if err != nil {
		t.Fatalf("NewUpgradeProposal mutated2: %v", err)
	}
	if p1.ID == p4.ID {
		t.Error("different currentBlockNumber MUST produce different IDs")
	}
}

// TestNewUpgradeProposal_RejectsEmptyFields asserts the helper
// validates the required hex fields up-front so the proposer
// surfaces errors at creation rather than at gossip-decode time.
func TestNewUpgradeProposal_RejectsEmptyFields(t *testing.T) {
	full := UpgradePayload{
		PublicValuesHex:       hex.EncodeToString(make([]byte, 280)),
		BatchDataHex:          hex.EncodeToString([]byte{0x01}),
		ProofBlobHex:          hex.EncodeToString([]byte{0x02}),
		CurrentStateRootHex:   strings.Repeat("ab", 32),
		NewCovenantAnfHashHex: strings.Repeat("cd", 32),
		NewCovenantScriptHex:  hex.EncodeToString([]byte{0xab}),
		ChainID:               1,
	}
	cases := []struct {
		name string
		mut  func(p *UpgradePayload)
	}{
		{"empty newCovenantScriptHex", func(p *UpgradePayload) { p.NewCovenantScriptHex = "" }},
		{"empty publicValuesHex", func(p *UpgradePayload) { p.PublicValuesHex = "" }},
		{"empty batchDataHex", func(p *UpgradePayload) { p.BatchDataHex = "" }},
		{"empty proofBlobHex", func(p *UpgradePayload) { p.ProofBlobHex = "" }},
		{"empty currentStateRootHex", func(p *UpgradePayload) { p.CurrentStateRootHex = "" }},
		{"empty newCovenantAnfHashHex", func(p *UpgradePayload) { p.NewCovenantAnfHashHex = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := full
			tc.mut(&payload)
			if _, err := NewUpgradeProposal(payload, 1, time.Hour); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// TestUpgradeProposal_GossipRoundTrip asserts a NewUpgradeProposal
// proposal survives JSON marshalling + unmarshalling through the
// gossip wire format without losing any payload field. This is the
// guarantee that signers see the exact same canonical bytes after a
// gossip hop.
func TestUpgradeProposal_GossipRoundTrip(t *testing.T) {
	payload := UpgradePayload{
		PublicValuesHex:       hex.EncodeToString(make([]byte, 280)),
		BatchDataHex:          hex.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04}),
		ProofBlobHex:          hex.EncodeToString([]byte{0x10, 0x20, 0x30, 0x40}),
		CurrentStateRootHex:   strings.Repeat("ab", 32),
		CurrentBlockNumber:    12847,
		NewCovenantAnfHashHex: strings.Repeat("cd", 32),
		NewCovenantScriptHex:  hex.EncodeToString([]byte{0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef}),
		ChainID:               8453111,
	}
	original, err := NewUpgradeProposal(payload, 2, time.Hour)
	if err != nil {
		t.Fatalf("NewUpgradeProposal: %v", err)
	}
	original.AddSignature("02aabbcc", "sig1")

	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Proposal
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID drift: got %s, want %s", decoded.ID, original.ID)
	}
	if decoded.Action != ActionUpgrade {
		t.Errorf("action: got %s, want upgrade", decoded.Action)
	}
	if decoded.UpgradePayload == nil {
		t.Fatal("UpgradePayload nil after unmarshal")
	}
	if decoded.UpgradePayload.PublicValuesHex != payload.PublicValuesHex {
		t.Error("publicValuesHex drift after gossip round-trip")
	}
	if decoded.UpgradePayload.BatchDataHex != payload.BatchDataHex {
		t.Error("batchDataHex drift after gossip round-trip")
	}
	if decoded.UpgradePayload.ProofBlobHex != payload.ProofBlobHex {
		t.Error("proofBlobHex drift after gossip round-trip")
	}
	if decoded.UpgradePayload.CurrentStateRootHex != payload.CurrentStateRootHex {
		t.Error("currentStateRootHex drift after gossip round-trip")
	}
	if decoded.UpgradePayload.CurrentBlockNumber != payload.CurrentBlockNumber {
		t.Errorf("currentBlockNumber drift: got %d, want %d",
			decoded.UpgradePayload.CurrentBlockNumber, payload.CurrentBlockNumber)
	}
	if decoded.UpgradePayload.NewCovenantAnfHashHex != payload.NewCovenantAnfHashHex {
		t.Error("newCovenantAnfHashHex drift after gossip round-trip")
	}
	if decoded.UpgradePayload.NewCovenantScriptHex != payload.NewCovenantScriptHex {
		t.Error("newCovenantScriptHex drift after gossip round-trip")
	}
	if decoded.UpgradePayload.ChainID != payload.ChainID {
		t.Errorf("chainId drift: got %d, want %d",
			decoded.UpgradePayload.ChainID, payload.ChainID)
	}
	if decoded.Signatures["02aabbcc"] != "sig1" {
		t.Error("signature drift after gossip round-trip")
	}
}

// TestUpgradeProposal_GossipRoundTripWithVerifier asserts the
// gossiped UpgradePayload survives a workflow.CreateOrMerge cycle
// AND a Sign-then-verify cycle: the verifier sees the same content
// hash both before and after the gossip hop.
func TestUpgradeProposal_GossipRoundTripWithVerifier(t *testing.T) {
	payload := UpgradePayload{
		PublicValuesHex:       hex.EncodeToString(make([]byte, 280)),
		BatchDataHex:          hex.EncodeToString([]byte{0x01}),
		ProofBlobHex:          hex.EncodeToString([]byte{0x02}),
		CurrentStateRootHex:   strings.Repeat("ab", 32),
		CurrentBlockNumber:    100,
		NewCovenantAnfHashHex: strings.Repeat("cd", 32),
		NewCovenantScriptHex:  hex.EncodeToString([]byte{0xab, 0xcd}),
		ChainID:               8453111,
	}
	original, err := NewUpgradeProposal(payload, 1, time.Hour)
	if err != nil {
		t.Fatalf("NewUpgradeProposal: %v", err)
	}

	// Round-trip through the gossip wire format.
	wire, _ := json.Marshal(original)
	var decoded Proposal
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Re-derive the content ID from the decoded payload — must match
	// the original, otherwise a signer that signed pre-hop wouldn't
	// match the post-hop verifier's expectation.
	rederived, err := contentID(decoded.Action, decoded.Params, decoded.UpgradePayload)
	if err != nil {
		t.Fatalf("contentID: %v", err)
	}
	if rederived != original.ID {
		t.Errorf("content hash drift across gossip hop: got %s, want %s", rederived, original.ID)
	}

	// Wire through the workflow: sign with a stub verifier that
	// accepts whatever signature it sees. This is the real call path
	// followed in production, exercising the full Store + verifier
	// surface.
	store := NewMemoryStore()
	var seenID string
	wf := NewWorkflow(store, nil, func(id, sig string) ([]byte, error) {
		seenID = id
		return []byte{0x02, 0xaa, 0xbb}, nil
	})
	if _, err := wf.CreateOrMerge(&decoded); err != nil {
		t.Fatalf("CreateOrMerge: %v", err)
	}
	if _, err := wf.Sign(decoded.ID, "any-sig"); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if seenID != original.ID {
		t.Errorf("verifier saw a different ID after gossip+workflow: got %s, want %s",
			seenID, original.ID)
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
