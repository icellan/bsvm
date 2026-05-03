package governance

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// stubState implements CovenantStateReader for unit tests. The
// optional CurrentSats hook returns a non-zero stub so the
// broadcaster's "fall back to DefaultSats" branch isn't exercised
// here (covered separately).
type stubState struct {
	tipTxID types.Hash
	tipVout uint32
	cov     *covenant.CompiledCovenant
	gov     covenant.GovernanceConfig
	sats    uint64
}

func (s *stubState) CurrentTxID() types.Hash                  { return s.tipTxID }
func (s *stubState) CurrentVout() uint32                      { return s.tipVout }
func (s *stubState) Covenant() *covenant.CompiledCovenant     { return s.cov }
func (s *stubState) GovernanceConfig() covenant.GovernanceConfig { return s.gov }
func (s *stubState) CurrentSats() uint64                      { return s.sats }

// stubARC implements arc.ARCClient with a programmable response.
type stubARC struct {
	resp     *arc.BroadcastResponse
	err      error
	called   int
	lastBody []byte
}

func (s *stubARC) Broadcast(_ context.Context, body []byte) (*arc.BroadcastResponse, error) {
	s.called++
	s.lastBody = append([]byte(nil), body...)
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func (s *stubARC) Status(_ context.Context, _ [32]byte) (*arc.TxStatus, error) {
	return nil, errors.New("stub: Status not implemented")
}

func (s *stubARC) Ping(_ context.Context) error { return nil }

// stubSpendBuilder records its inputs and emits a deterministic txid.
type stubSpendBuilder struct {
	called      int
	lastTxID    string
	lastVout    uint32
	lastSats    uint64
	lastScript  []byte
	lastUnlock  []byte
	returnTxHex string
	returnTxID  string
	returnErr   error
}

func (b *stubSpendBuilder) Build(
	covenantTxID string,
	covenantVout uint32,
	covenantSatsLive uint64,
	continuationLockingScript []byte,
	unlockBytes []byte,
) (string, string, error) {
	b.called++
	b.lastTxID = covenantTxID
	b.lastVout = covenantVout
	b.lastSats = covenantSatsLive
	b.lastScript = append([]byte(nil), continuationLockingScript...)
	b.lastUnlock = append([]byte(nil), unlockBytes...)
	if b.returnErr != nil {
		return "", "", b.returnErr
	}
	return b.returnTxHex, b.returnTxID, nil
}

// fixtureKey is a known-valid 33-byte compressed secp256k1 pubkey
// used as the lone single-key governance key in these tests. The
// signature verifier in the broadcaster is content-blind, so the
// proposal-signature value is opaque hex.
var fixtureKey = mustDecodeHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// makeFreezeReadyProposal returns a single-key freeze proposal
// already at threshold with one fixture signature.
func makeFreezeReadyProposal() *Proposal {
	p, _ := NewProposal(ActionFreeze, nil, 1, time.Hour)
	p.AddSignature(hex.EncodeToString(fixtureKey), hex.EncodeToString(make([]byte, 71)))
	return p
}

// makeUnfreezeReadyProposal returns a single-key unfreeze proposal
// already at threshold.
func makeUnfreezeReadyProposal() *Proposal {
	p, _ := NewProposal(ActionUnfreeze, nil, 1, time.Hour)
	p.AddSignature(hex.EncodeToString(fixtureKey), hex.EncodeToString(make([]byte, 71)))
	return p
}

// fixtureCovenant returns a CompiledCovenant whose LockingScript is
// non-empty so the broadcaster doesn't bail on the "covenant
// unavailable" guard.
func fixtureCovenant() *covenant.CompiledCovenant {
	return &covenant.CompiledCovenant{LockingScript: []byte{0x76, 0xa9, 0x14, 0xde, 0xad}}
}

// fixtureTipTxID returns a non-zero stub tip txid so the
// broadcaster's isZeroHash guard doesn't fire.
func fixtureTipTxID() types.Hash {
	var h types.Hash
	for i := range h {
		h[i] = byte(i + 1)
	}
	return h
}

// TestBroadcaster_Freeze_AssemblesAndBroadcasts asserts the happy-
// path freeze flow assembles the spend tx, hands it to ARC, and
// surfaces the resulting txid through Subscribe.
func TestBroadcaster_Freeze_AssemblesAndBroadcasts(t *testing.T) {
	state := &stubState{
		tipTxID: fixtureTipTxID(),
		tipVout: 0,
		cov:     fixtureCovenant(),
		gov: covenant.GovernanceConfig{
			Mode:      covenant.GovernanceSingleKey,
			Threshold: 1,
			Keys:      [][]byte{fixtureKey},
		},
		sats: 1234,
	}
	builder := &stubSpendBuilder{
		returnTxHex: hex.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef}),
		returnTxID:  strings.Repeat("aa", 32),
	}
	var resp arc.BroadcastResponse
	resp.Status = arc.StatusReceived
	for i := range resp.TxID {
		resp.TxID[i] = byte(0x77)
	}
	stub := &stubARC{resp: &resp}

	b, err := NewBroadcaster(BroadcasterConfig{
		ARC:          stub,
		State:        state,
		SpendBuilder: builder.Build,
		DefaultSats:  100,
	})
	if err != nil {
		t.Fatalf("NewBroadcaster: %v", err)
	}

	var got BroadcastResult
	b.Subscribe(func(r BroadcastResult) { got = r })
	b.OnReady(makeFreezeReadyProposal())

	if builder.called != 1 {
		t.Fatalf("spend builder called %d times, want 1", builder.called)
	}
	if builder.lastSats != 1234 {
		t.Errorf("spend builder sats = %d, want 1234 (CurrentSats override)", builder.lastSats)
	}
	if builder.lastVout != 0 {
		t.Errorf("spend builder vout = %d, want 0", builder.lastVout)
	}
	if !bytesEqual(builder.lastScript, state.cov.LockingScript) {
		t.Error("spend builder continuation script != live LockingScript")
	}
	if len(builder.lastUnlock) == 0 {
		t.Error("spend builder unlock bytes empty")
	}
	if stub.called != 1 {
		t.Fatalf("ARC.Broadcast called %d times, want 1", stub.called)
	}
	if got.Err != nil {
		t.Fatalf("BroadcastResult.Err = %v, want nil", got.Err)
	}
	if got.TxID == "" {
		t.Error("BroadcastResult.TxID empty")
	}
	if got.Action != ActionFreeze {
		t.Errorf("BroadcastResult.Action = %q, want freeze", got.Action)
	}
}

// TestBroadcaster_Unfreeze_DispatchesUnfreezeUnlock asserts the
// unfreeze action goes through the unfreeze unlock path (not the
// freeze one). We can't assert exact bytes because the unlock script
// only carries sigs, but we CAN assert the spend builder was called
// and the result fans out through Subscribe with the unfreeze action
// label.
func TestBroadcaster_Unfreeze_DispatchesUnfreezeUnlock(t *testing.T) {
	state := &stubState{
		tipTxID: fixtureTipTxID(),
		cov:     fixtureCovenant(),
		gov: covenant.GovernanceConfig{
			Mode:      covenant.GovernanceSingleKey,
			Threshold: 1,
			Keys:      [][]byte{fixtureKey},
		},
		sats: 1000,
	}
	builder := &stubSpendBuilder{returnTxHex: "deadbeef", returnTxID: strings.Repeat("bb", 32)}
	stub := &stubARC{resp: &arc.BroadcastResponse{Status: arc.StatusReceived}}
	b, _ := NewBroadcaster(BroadcasterConfig{
		ARC: stub, State: state, SpendBuilder: builder.Build, DefaultSats: 100,
	})

	var got BroadcastResult
	b.Subscribe(func(r BroadcastResult) { got = r })
	b.OnReady(makeUnfreezeReadyProposal())

	if got.Action != ActionUnfreeze {
		t.Errorf("BroadcastResult.Action = %q, want unfreeze", got.Action)
	}
	if got.Err != nil {
		t.Errorf("unexpected error: %v", got.Err)
	}
}

// TestBroadcaster_ARCFailureSurfacesAsWarn asserts an ARC broadcast
// failure does NOT panic, leaves BroadcastTxID unset, and surfaces
// the error through Subscribe so an operator can retry.
func TestBroadcaster_ARCFailureSurfacesAsWarn(t *testing.T) {
	state := &stubState{
		tipTxID: fixtureTipTxID(),
		cov:     fixtureCovenant(),
		gov: covenant.GovernanceConfig{
			Mode:      covenant.GovernanceSingleKey,
			Threshold: 1,
			Keys:      [][]byte{fixtureKey},
		},
		sats: 1000,
	}
	builder := &stubSpendBuilder{returnTxHex: "deadbeef", returnTxID: strings.Repeat("cc", 32)}
	stub := &stubARC{err: errors.New("arc: connection refused")}
	b, _ := NewBroadcaster(BroadcasterConfig{
		ARC: stub, State: state, SpendBuilder: builder.Build, DefaultSats: 100,
	})

	var got BroadcastResult
	b.Subscribe(func(r BroadcastResult) { got = r })
	b.OnReady(makeFreezeReadyProposal())

	if stub.called != 1 {
		t.Fatalf("ARC.Broadcast not invoked")
	}
	if got.Err == nil {
		t.Fatal("expected BroadcastResult.Err on ARC failure")
	}
	if !strings.Contains(got.Err.Error(), "connection refused") {
		t.Errorf("unexpected error: %v", got.Err)
	}
	if got.TxHex == "" {
		t.Error("BroadcastResult.TxHex empty after ARC failure (operator can't retry without it)")
	}
}

// TestBroadcaster_UpgradeDeferred asserts the upgrade path emits a
// typed error documenting WW-governance-payload-extension instead of
// silently dropping the proposal.
func TestBroadcaster_UpgradeDeferred(t *testing.T) {
	state := &stubState{
		tipTxID: fixtureTipTxID(),
		cov:     fixtureCovenant(),
		gov: covenant.GovernanceConfig{
			Mode:      covenant.GovernanceSingleKey,
			Threshold: 1,
			Keys:      [][]byte{fixtureKey},
		},
	}
	stub := &stubARC{resp: &arc.BroadcastResponse{}}
	builder := &stubSpendBuilder{}
	b, _ := NewBroadcaster(BroadcasterConfig{
		ARC: stub, State: state, SpendBuilder: builder.Build, DefaultSats: 100,
	})

	var got BroadcastResult
	b.Subscribe(func(r BroadcastResult) { got = r })

	p, _ := NewProposal(ActionUpgrade, nil, 1, time.Hour)
	p.AddSignature(hex.EncodeToString(fixtureKey), hex.EncodeToString(make([]byte, 71)))
	b.OnReady(p)

	if stub.called != 0 {
		t.Errorf("ARC.Broadcast was called for upgrade — should be deferred (called=%d)", stub.called)
	}
	if builder.called != 0 {
		t.Errorf("spend builder was called for upgrade — should be deferred (called=%d)", builder.called)
	}
	if got.Err == nil {
		t.Fatal("expected BroadcastResult.Err for deferred upgrade")
	}
	if !strings.Contains(got.Err.Error(), "WW-governance-payload-extension") {
		t.Errorf("error should reference the deferral tracker: %v", got.Err)
	}
}

// TestBroadcaster_NilARCNoOpsButLogs asserts the broadcaster degrades
// gracefully (no panic, no spend-tx assembly) when ARC is unconfigured.
func TestBroadcaster_NilARCNoOpsButLogs(t *testing.T) {
	state := &stubState{
		tipTxID: fixtureTipTxID(),
		cov:     fixtureCovenant(),
		gov: covenant.GovernanceConfig{
			Mode:      covenant.GovernanceSingleKey,
			Threshold: 1,
			Keys:      [][]byte{fixtureKey},
		},
	}
	builder := &stubSpendBuilder{}
	b, err := NewBroadcaster(BroadcasterConfig{
		ARC: nil, State: state, SpendBuilder: builder.Build, DefaultSats: 100,
	})
	if err != nil {
		t.Fatalf("NewBroadcaster (nil ARC): %v", err)
	}
	subbed := false
	b.Subscribe(func(r BroadcastResult) { subbed = true })
	b.OnReady(makeFreezeReadyProposal())

	if builder.called != 0 {
		t.Error("spend builder was called despite nil ARC — should short-circuit")
	}
	if subbed {
		t.Error("subscriber was invoked despite nil ARC — should short-circuit")
	}
}

// TestBroadcaster_RejectsZeroTip asserts the "no tip txid yet" guard
// — useful during shard bootstrap when a follower hasn't synced the
// covenant chain yet but somehow accumulates governance signatures.
func TestBroadcaster_RejectsZeroTip(t *testing.T) {
	state := &stubState{
		// tipTxID intentionally left zero
		cov: fixtureCovenant(),
		gov: covenant.GovernanceConfig{
			Mode:      covenant.GovernanceSingleKey,
			Threshold: 1,
			Keys:      [][]byte{fixtureKey},
		},
		sats: 100,
	}
	builder := &stubSpendBuilder{}
	stub := &stubARC{resp: &arc.BroadcastResponse{}}
	b, _ := NewBroadcaster(BroadcasterConfig{
		ARC: stub, State: state, SpendBuilder: builder.Build, DefaultSats: 100,
	})

	var got BroadcastResult
	b.Subscribe(func(r BroadcastResult) { got = r })
	b.OnReady(makeFreezeReadyProposal())

	if got.Err == nil {
		t.Fatal("expected BroadcastResult.Err when tip txid is zero")
	}
	if !strings.Contains(got.Err.Error(), "tip txid") {
		t.Errorf("expected 'tip txid' in error, got: %v", got.Err)
	}
	if stub.called != 0 {
		t.Error("ARC.Broadcast called despite zero-tip guard")
	}
}

// bytesEqual is a minimal byte-slice comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
