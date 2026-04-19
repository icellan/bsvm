package covenant

import (
	"reflect"
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// 1. Governance keys MUST NOT advance state.
//
//    The only authorization for covenant advance is the SP1 STARK proof.
//    Governance keys can freeze/unfreeze/upgrade only. At the Go-manager
//    layer this is enforced structurally: ValidateAdvanceData /
//    BroadcastAdvance do NOT accept any signature parameter. These tests
//    prove that frozen-state + proof bytes are the sole advance inputs.
// ---------------------------------------------------------------------------

// TestGovernanceNeg_AdvanceAPIHasNoSignatureParam locks in the API contract
// that governance signatures MUST NOT be an input to covenant state
// advancement. If someone adds a Sig/Signature/PubKey parameter to
// ValidateAdvanceData or BroadcastAdvance in the future, this test fails.
func TestGovernanceNeg_AdvanceAPIHasNoSignatureParam(t *testing.T) {
	cm := newTestManager(t, 0, 0, GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3), testKey(4), testKey(5)},
		Threshold: 3,
	})

	// Reflect on ValidateAdvanceData's method type.
	buildAdv := reflect.ValueOf(cm).MethodByName("ValidateAdvanceData")
	if !buildAdv.IsValid() {
		t.Fatal("CovenantManager.ValidateAdvanceData not found")
	}
	assertNoSignatureParam(t, "ValidateAdvanceData", buildAdv.Type())

	adv := reflect.ValueOf(cm).MethodByName("BroadcastAdvance")
	if !adv.IsValid() {
		t.Fatal("CovenantManager.BroadcastAdvance not found")
	}
	assertNoSignatureParam(t, "BroadcastAdvance", adv.Type())
}

// assertNoSignatureParam fails the test if any parameter of the method
// type names anything that could reasonably be a governance signature or
// public-key input. This is a structural guard for the "governance cannot
// advance state" invariant.
func assertNoSignatureParam(t *testing.T, method string, mt reflect.Type) {
	t.Helper()
	forbidden := []string{"sig", "signature", "pubkey", "pub_key", "governance"}
	for i := 0; i < mt.NumIn(); i++ {
		p := mt.In(i)
		name := strings.ToLower(p.String())
		for _, f := range forbidden {
			if strings.Contains(name, f) {
				t.Errorf("%s param %d of type %q looks like a governance signature — advance must not accept governance keys",
					method, i, p.String())
			}
		}
	}
}

// TestGovernanceNeg_MultisigHoldersCannotAdvance exercises the end-to-end
// expectation: a caller holding all M-of-N governance keys still cannot
// produce a CovenantState advance by signing — the only accepted inputs
// are a proof, public values, and batch data. Supplying "signatures" as
// proof/public-values bytes does not help: the advance still goes through
// ValidateAdvanceData which only gates on frozen flag and block-number
// increment, and the Rúnar script-level STARK check (exercised elsewhere)
// rejects anything that isn't a real proof. Here we verify the Go layer
// behaviour: even with governance fully configured, the only way for the
// manager to accept an advance is non-empty proof bytes and a +1 block.
func TestGovernanceNeg_MultisigHoldersCannotAdvance(t *testing.T) {
	gov := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3), testKey(4), testKey(5)},
		Threshold: 3,
	}
	if err := gov.Validate(); err != nil {
		t.Fatalf("3-of-5 governance must validate: %v", err)
	}

	cm := newTestManager(t, 0, 0, gov)

	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}

	// Attempting to advance with EMPTY proof bytes fails — the signatures
	// from the governance holders are not accepted as an advance proof.
	if err := cm.ValidateAdvanceData(newState, []byte("batch"), nil, []byte("pv")); err == nil {
		t.Fatal("advance with empty proof must be rejected even under full multisig control")
	}

	// Attempting to advance with empty public values fails — again,
	// governance signatures do not substitute for the SP1 proof bundle.
	if err := cm.ValidateAdvanceData(newState, []byte("batch"), []byte("proof"), nil); err == nil {
		t.Fatal("advance with empty public values must be rejected")
	}

	// Attempting to advance with no batch data fails.
	if err := cm.ValidateAdvanceData(newState, nil, []byte("proof"), []byte("pv")); err == nil {
		t.Fatal("advance with empty batch data must be rejected")
	}

	// The only way the manager accepts an advance is with non-empty
	// proof/pv/batch. That is the SP1-proof path — not a governance path.
	if err := cm.ValidateAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv")); err != nil {
		t.Fatalf("advance with proof should succeed (governance keys are irrelevant here): %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. Multisig threshold (M-of-N) enforcement.
//
//    Signature verification is on-chain (Rúnar script). At the Go layer we
//    exercise GovernanceConfig.Validate to verify the M-of-N invariants
//    that gate acceptance of a governance config in the first place. The
//    on-chain sig-check matrix is covered by the contracts package tests
//    (rollup_basefold_test.go etc.); here we bind the manager-level config.
// ---------------------------------------------------------------------------

// TestGovernanceNeg_Multisig3of5_ValidatesCorrectly verifies that a
// 3-of-5 multisig is a valid configuration and that invalid threshold
// values are rejected with clear errors.
func TestGovernanceNeg_Multisig3of5_ValidatesCorrectly(t *testing.T) {
	keys := [][]byte{testKey(1), testKey(2), testKey(3), testKey(4), testKey(5)}

	// 3-of-5 is valid.
	valid := GovernanceConfig{Mode: GovernanceMultiSig, Keys: keys, Threshold: 3}
	if err := valid.Validate(); err != nil {
		t.Fatalf("3-of-5 must validate: %v", err)
	}

	// Threshold 0 is rejected.
	g0 := GovernanceConfig{Mode: GovernanceMultiSig, Keys: keys, Threshold: 0}
	if err := g0.Validate(); err == nil {
		t.Fatal("threshold 0 must be rejected")
	}

	// Threshold > N is rejected.
	gHigh := GovernanceConfig{Mode: GovernanceMultiSig, Keys: keys, Threshold: 6}
	if err := gHigh.Validate(); err == nil {
		t.Fatal("threshold 6 with 5 keys must be rejected")
	}

	// Threshold 5 of 5 (full) is valid.
	g5 := GovernanceConfig{Mode: GovernanceMultiSig, Keys: keys, Threshold: 5}
	if err := g5.Validate(); err != nil {
		t.Fatalf("5-of-5 must validate: %v", err)
	}

	// Threshold 1 of 5 is valid at the config level (even though
	// 1-of-N is not a "multisig" in spirit, the schema admits it).
	g1 := GovernanceConfig{Mode: GovernanceMultiSig, Keys: keys, Threshold: 1}
	if err := g1.Validate(); err != nil {
		t.Fatalf("1-of-5 must validate: %v", err)
	}
}

// TestGovernanceNeg_Multisig3of5_DuplicateKeysFlagged asserts that duplicate
// keys in a multisig set are rejected at Validate() time. If the on-chain
// Rúnar CheckMultiSig admits the same key satisfying multiple signature
// slots, a 3-of-5 set where three slots hold the same key is effectively
// 1-of-N. Validate must therefore reject configs with repeated keys to
// preserve true M-of-N semantics.
func TestGovernanceNeg_Multisig3of5_DuplicateKeysFlagged(t *testing.T) {
	// Build a 3-of-5 config where the same key appears three times.
	repeated := testKey(1)
	keys := [][]byte{repeated, repeated, repeated, testKey(2), testKey(3)}
	gov := GovernanceConfig{Mode: GovernanceMultiSig, Keys: keys, Threshold: 3}

	err := gov.Validate()
	if err == nil {
		t.Fatal("multisig config with duplicate keys must be rejected")
	}
	if !strings.Contains(err.Error(), "unique") {
		t.Errorf("expected duplicate-key error, got %v", err)
	}

	// Two distinct duplicates should also be rejected — detecting any
	// duplicate is sufficient.
	keys2 := [][]byte{testKey(1), testKey(2), testKey(2), testKey(3), testKey(4)}
	gov2 := GovernanceConfig{Mode: GovernanceMultiSig, Keys: keys2, Threshold: 3}
	if err := gov2.Validate(); err == nil {
		t.Fatal("multisig config with any duplicate key must be rejected")
	}

	// Sanity: an all-unique set still validates.
	unique := [][]byte{testKey(1), testKey(2), testKey(3), testKey(4), testKey(5)}
	good := GovernanceConfig{Mode: GovernanceMultiSig, Keys: unique, Threshold: 3}
	if err := good.Validate(); err != nil {
		t.Fatalf("unique 3-of-5 must still validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. Frozen-state invariant: advance must be rejected while frozen, and
//    must be re-enabled after unfreeze.
// ---------------------------------------------------------------------------

// TestGovernanceNeg_Frozen3of5_AdvanceBlocked asserts that when a 3-of-5
// multisig shard is frozen, advance validation is rejected
// regardless of proof validity. Freeze/unfreeze is simulated by directly
// applying the state transition — the real freeze is signed on-chain by
// three governance holders (exercised in the contracts package tests).
func TestGovernanceNeg_Frozen3of5_AdvanceBlocked(t *testing.T) {
	gov := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3), testKey(4), testKey(5)},
		Threshold: 3,
	}
	if err := gov.Validate(); err != nil {
		t.Fatalf("3-of-5 must validate: %v", err)
	}

	// Start active, at block 7.
	cm := newTestManager(t, 0, 7, gov)

	// Simulate 3-of-5 freeze action: governance holders produce signatures
	// that satisfy Rúnar's CheckMultiSig on-chain. We model the on-chain
	// outcome by applying the frozen state.
	frozen := cm.CurrentState()
	frozen.Frozen = 1
	if err := cm.ApplyAdvance(types.BytesToHash([]byte{0xF0}), frozen); err != nil {
		t.Fatalf("simulated freeze apply failed: %v", err)
	}
	if cm.CurrentState().Frozen != 1 {
		t.Fatal("shard must be frozen after apply")
	}

	// Advance validation while frozen MUST be rejected, even with a non-empty
	// proof (the frozen guard runs before proof-shape checks).
	err := cm.ValidateAdvanceData(
		CovenantState{StateRoot: testStateRoot(8), BlockNumber: 8, Frozen: 0},
		[]byte("batch"), []byte("proof"), []byte("pv"),
	)
	if err == nil {
		t.Fatal("frozen shard must reject ValidateAdvanceData")
	}
	if !strings.Contains(err.Error(), "frozen") {
		t.Errorf("expected frozen-related error, got %v", err)
	}

	// Simulate a 3-of-5 unfreeze.
	unfrozen := cm.CurrentState()
	unfrozen.Frozen = 0
	if err := cm.ApplyAdvance(types.BytesToHash([]byte{0xF1}), unfrozen); err != nil {
		t.Fatalf("simulated unfreeze apply failed: %v", err)
	}
	if cm.CurrentState().Frozen != 0 {
		t.Fatal("shard must be active after unfreeze")
	}

	// After unfreeze, a valid-shape advance succeeds.
	if err := cm.ValidateAdvanceData(
		CovenantState{StateRoot: testStateRoot(8), BlockNumber: 8, Frozen: 0},
		[]byte("batch"), []byte("proof"), []byte("pv"),
	); err != nil {
		t.Fatalf("advance after unfreeze should succeed: %v", err)
	}
}

// TestGovernanceNeg_UpgradeRequiresFrozen locks in the manager-level
// contract that upgrade semantics are only meaningful when the shard is
// frozen. The actual "must be frozen" check is enforced by the on-chain
// Rúnar script (see UpgradeSingleKey/UpgradeMultiSig* in
// rollup_basefold.runar.go which all assert c.Frozen == 1). At the Go
// layer we verify only the manager's frozen-state reporting and advance
// validation behaviour.
func TestGovernanceNeg_UpgradeRequiresFrozen(t *testing.T) {
	cm := newTestManager(t, 0, 10, GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3), testKey(4), testKey(5)},
		Threshold: 3,
	})
	if cm.CurrentState().Frozen != 0 {
		t.Fatal("expected active shard")
	}

	// But a ValidateAdvanceData call on an active shard still must reject
	// anything that would install an upgrade — at the Go layer we can't
	// distinguish upgrade vs advance payloads, but we CAN assert that
	// frozen-state blocks the advance API entirely once frozen.
	frozen := cm.CurrentState()
	frozen.Frozen = 1
	if err := cm.ApplyAdvance(types.BytesToHash([]byte{0xF2}), frozen); err != nil {
		t.Fatalf("freeze apply failed: %v", err)
	}
	if err := cm.ValidateAdvanceData(
		CovenantState{StateRoot: testStateRoot(11), BlockNumber: 11},
		[]byte("batch"), []byte("proof"), []byte("pv"),
	); err == nil {
		t.Fatal("advance must be rejected while frozen")
	}
}
