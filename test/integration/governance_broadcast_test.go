// governance_broadcast_test.go — validation harness for the
// at-threshold governance broadcaster wired into cmd/bsvm/main.go's
// OnReady callback.
//
// The pure-Go layer is exercised here without contacting any BSV
// node or ARC instance. The flow under test:
//
//   - Build a covenant.CovenantManager + a governance.Broadcaster
//     wired through deploy/covenant.BuildUpgradeSpendTx (the same
//     spend-tx builder cmd/bsvm/governance_broadcast.go uses).
//   - Aim the broadcaster at a non-routable ARC URL so Broadcast
//     errors out reliably (mirrors rotate_vk_test.go's
//     FullSigsAssemblesTx pattern).
//   - Construct a freeze proposal at threshold and dispatch via
//     OnReady.
//   - Assert the broadcaster reached the ARC.Broadcast call (proven
//     by the published BroadcastResult containing a non-empty
//     TxHex), and that the result fans out through Subscribe.
//
// This is the closest integration coverage we get without a live
// BSV node: it asserts the assembly path produced a complete tx
// AND that a real ARC client was dialled. Together with the unit
// tests in pkg/governance/broadcaster_test.go (which exercise stub
// ARC + stub spend builder for fast feedback), it locks down the
// "OnReady actually broadcasts" behaviour the spec mandates.
package integration

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/governance"
	"github.com/icellan/bsvm/pkg/types"

	covenantdeploy "github.com/icellan/bsvm/deploy/covenant"
)

// fixtureGovernanceTipTxID returns a deterministic non-zero tip
// txid used for the integration fixture.
func fixtureGovernanceTipTxID(t *testing.T) types.Hash {
	t.Helper()
	var h types.Hash
	for i := range h {
		h[i] = byte(0x33)
	}
	return h
}

// integrationCovenantState is the minimal CovenantStateReader the
// integration test needs. It is NOT the production
// covenantStateAdapter (that lives in cmd/bsvm) — the integration
// tests live in package integration and can't import main, so we
// inline a tiny mirror here. The shape MUST match the production
// adapter; if either drifts, the broadcaster wiring breaks.
type integrationCovenantState struct {
	tipTxID types.Hash
	tipVout uint32
	cov     *covenant.CompiledCovenant
	gov     covenant.GovernanceConfig
	sats    uint64
}

func (s *integrationCovenantState) CurrentTxID() types.Hash               { return s.tipTxID }
func (s *integrationCovenantState) CurrentVout() uint32                   { return s.tipVout }
func (s *integrationCovenantState) Covenant() *covenant.CompiledCovenant  { return s.cov }
func (s *integrationCovenantState) GovernanceConfig() covenant.GovernanceConfig {
	return s.gov
}
func (s *integrationCovenantState) CurrentSats() uint64 { return s.sats }

// integrationSpendBuilder is the production wiring path —
// deploy/covenant.BuildUpgradeSpendTx. Mirrors cmd/bsvm/governance_broadcast.go's
// governanceSpendBuilder verbatim so the integration test exercises
// the same code the daemon does.
func integrationSpendBuilder(
	covenantTxID string,
	covenantVout uint32,
	covenantSatsLive uint64,
	continuationLockingScript []byte,
	unlockBytes []byte,
) (string, string, error) {
	tx, err := covenantdeploy.BuildUpgradeSpendTx(
		covenantTxID,
		covenantVout,
		covenantSatsLive,
		continuationLockingScript,
		unlockBytes,
	)
	if err != nil {
		return "", "", err
	}
	return tx.Hex(), tx.TxID().String(), nil
}

// TestGovernanceBroadcast_FreezeReachesARC asserts the broadcaster
// assembles a real spend tx and dispatches it to the configured
// ARC endpoint. The endpoint is unreachable so the broadcast fails
// — the test asserts the failure surfaces through Subscribe AND that
// a non-empty TxHex was assembled before the network failure.
func TestGovernanceBroadcast_FreezeReachesARC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping governance broadcast assembly in short mode")
	}

	gov := covenant.GovernanceConfig{
		Mode:      covenant.GovernanceSingleKey,
		Threshold: 1,
		Keys:      [][]byte{mustDecodeHexInt(fixtureSinglekeyPubKeyHex)},
	}
	state := &integrationCovenantState{
		tipTxID: fixtureGovernanceTipTxID(t),
		tipVout: 0,
		cov:     &covenant.CompiledCovenant{LockingScript: []byte{0x76, 0xa9, 0x14, 0xab, 0xcd}},
		gov:     gov,
		sats:    covenant.DefaultCovenantSats,
	}

	// 127.0.0.1:1 — guaranteed-unreachable endpoint mirrored from
	// rotate_vk_test.go's FullSigsAssemblesTx. ARC.Broadcast will
	// return an ARCBroadcastError whose Underlying captures the
	// dial-refused failure.
	arcClient, err := arc.NewClient(arc.Config{URL: "http://127.0.0.1:1", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("arc.NewClient: %v", err)
	}

	b, err := governance.NewBroadcaster(governance.BroadcasterConfig{
		ARC:              arcClient,
		State:            state,
		SpendBuilder:     integrationSpendBuilder,
		DefaultSats:      covenant.DefaultCovenantSats,
		BroadcastTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBroadcaster: %v", err)
	}

	var (
		mu  sync.Mutex
		got governance.BroadcastResult
	)
	b.Subscribe(func(r governance.BroadcastResult) {
		mu.Lock()
		got = r
		mu.Unlock()
	})

	// Build a freeze proposal at threshold: single-key governance,
	// one signature already collected against the fixture pubkey.
	p, err := governance.NewProposal(governance.ActionFreeze, nil, 1, time.Hour)
	if err != nil {
		t.Fatalf("NewProposal: %v", err)
	}
	p.AddSignature(hex.EncodeToString(state.gov.Keys[0]),
		hex.EncodeToString(make([]byte, 71)))

	b.OnReady(p)

	mu.Lock()
	defer mu.Unlock()
	if got.Action != governance.ActionFreeze {
		t.Errorf("BroadcastResult.Action = %q, want freeze", got.Action)
	}
	if got.Err == nil {
		t.Fatal("expected ARC.Broadcast error against 127.0.0.1:1, got nil — was the broadcast attempted?")
	}
	// The assembly must have produced a non-empty tx hex BEFORE the
	// network call — otherwise we never reached ARC.Broadcast at all.
	if got.TxHex == "" {
		t.Fatal("BroadcastResult.TxHex empty — assembly did not produce a tx before ARC failure")
	}
	if _, decErr := hex.DecodeString(got.TxHex); decErr != nil {
		t.Errorf("TxHex is not valid hex: %v", decErr)
	}
	// Predicted TxID populated even on ARC failure so an operator
	// can identify which tx they need to retry.
	if got.TxID == "" {
		t.Error("BroadcastResult.TxID empty after ARC failure — operator can't identify the tx")
	}
}

// TestGovernanceBroadcast_UpgradeIsDeferred asserts the upgrade path
// emits the WW-governance-payload-extension typed error — proving
// the broadcaster does NOT silently drop upgrade proposals at
// threshold even though it can't yet broadcast them.
func TestGovernanceBroadcast_UpgradeIsDeferred(t *testing.T) {
	gov := covenant.GovernanceConfig{
		Mode:      covenant.GovernanceSingleKey,
		Threshold: 1,
		Keys:      [][]byte{mustDecodeHexInt(fixtureSinglekeyPubKeyHex)},
	}
	state := &integrationCovenantState{
		tipTxID: fixtureGovernanceTipTxID(t),
		cov:     &covenant.CompiledCovenant{LockingScript: []byte{0x76, 0xa9}},
		gov:     gov,
		sats:    covenant.DefaultCovenantSats,
	}
	arcClient, err := arc.NewClient(arc.Config{URL: "http://127.0.0.1:1", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("arc.NewClient: %v", err)
	}

	b, err := governance.NewBroadcaster(governance.BroadcasterConfig{
		ARC:          arcClient,
		State:        state,
		SpendBuilder: integrationSpendBuilder,
		DefaultSats:  covenant.DefaultCovenantSats,
	})
	if err != nil {
		t.Fatalf("NewBroadcaster: %v", err)
	}

	var (
		mu  sync.Mutex
		got governance.BroadcastResult
	)
	b.Subscribe(func(r governance.BroadcastResult) {
		mu.Lock()
		got = r
		mu.Unlock()
	})

	p, _ := governance.NewProposal(governance.ActionUpgrade, nil, 1, time.Hour)
	p.AddSignature(hex.EncodeToString(state.gov.Keys[0]),
		hex.EncodeToString(make([]byte, 71)))
	b.OnReady(p)

	mu.Lock()
	defer mu.Unlock()
	if got.Err == nil {
		t.Fatal("expected upgrade-deferred error, got nil — was the path silently dropped?")
	}
	if !strings.Contains(got.Err.Error(), "WW-governance-payload-extension") {
		t.Errorf("expected WW-governance-payload-extension marker in error, got: %v", got.Err)
	}
}

// mustDecodeHexInt is a local helper (the integration test package
// already has a mustDecodeHex in fixtures.go's neighbours, but this
// avoids any naming collision).
func mustDecodeHexInt(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
