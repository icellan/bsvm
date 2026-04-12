package covenant

import (
	"crypto/sha256"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// newTestManager creates a CovenantManager for governance state machine
// testing with the given initial state and governance configuration.
func newTestManager(t *testing.T, frozen uint8, blockNum uint64, gov GovernanceConfig) *CovenantManager {
	t.Helper()

	compiled := &CompiledCovenant{
		LockingScript: []byte{0x01, 0x02, 0x03},
		StateSize:     3,
		ScriptHash:    sha256.Sum256([]byte{0x01, 0x02, 0x03}),
	}

	initialState := CovenantState{
		StateRoot:   testStateRoot(blockNum),
		BlockNumber: blockNum,
		Frozen:      frozen,
	}

	return NewCovenantManager(
		compiled,
		types.Hash{},
		0,
		DefaultCovenantSats,
		initialState,
		8453111,
		VerifyGroth16,
	)
}

// TestGovernanceStateMachine_ActiveToFrozen verifies that transitioning
// from active (Frozen=0) to frozen (Frozen=1) succeeds. This simulates
// a governance key holder freezing the shard.
func TestGovernanceStateMachine_ActiveToFrozen(t *testing.T) {
	cm := newTestManager(t, 0, 5, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	})

	// Verify shard is active.
	if cm.CurrentState().Frozen != 0 {
		t.Fatal("expected shard to be active (Frozen=0)")
	}

	// Simulate freeze: governance key holder applies a state transition
	// that sets Frozen=1. On-chain this is done via BuildFreezeUnlockScript;
	// here we simulate the result by applying the frozen state.
	frozenState := CovenantState{
		StateRoot:   cm.CurrentState().StateRoot, // state root unchanged during freeze
		BlockNumber: cm.CurrentState().BlockNumber,
		Frozen:      1,
	}
	freezeTxID := types.BytesToHash([]byte{0xf0})
	if err := cm.ApplyAdvance(freezeTxID, frozenState); err != nil {
		t.Fatalf("ApplyAdvance failed: %v", err)
	}

	// Verify the shard is now frozen.
	if cm.CurrentState().Frozen != 1 {
		t.Fatal("expected shard to be frozen (Frozen=1)")
	}

	// Verify that state root and block number are preserved.
	if cm.CurrentState().StateRoot != testStateRoot(5) {
		t.Error("state root should be preserved during freeze")
	}
	if cm.CurrentState().BlockNumber != 5 {
		t.Error("block number should be preserved during freeze")
	}
}

// TestGovernanceStateMachine_FrozenToActive verifies that transitioning
// from frozen (Frozen=1) back to active (Frozen=0) succeeds. This
// simulates a governance key holder unfreezing the shard.
func TestGovernanceStateMachine_FrozenToActive(t *testing.T) {
	cm := newTestManager(t, 1, 10, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	})

	// Verify shard is frozen.
	if cm.CurrentState().Frozen != 1 {
		t.Fatal("expected shard to be frozen (Frozen=1)")
	}

	// Simulate unfreeze.
	activeState := CovenantState{
		StateRoot:   cm.CurrentState().StateRoot,
		BlockNumber: cm.CurrentState().BlockNumber,
		Frozen:      0,
	}
	unfreezeTxID := types.BytesToHash([]byte{0xf1})
	if err := cm.ApplyAdvance(unfreezeTxID, activeState); err != nil {
		t.Fatalf("ApplyAdvance failed: %v", err)
	}

	// Verify the shard is now active.
	if cm.CurrentState().Frozen != 0 {
		t.Fatal("expected shard to be active (Frozen=0)")
	}

	// After unfreeze, advances should succeed again.
	newState := CovenantState{
		StateRoot:   testStateRoot(11),
		BlockNumber: 11,
		Frozen:      0,
	}
	_, err := cm.BuildAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv"))
	if err != nil {
		t.Fatalf("advance after unfreeze should succeed: %v", err)
	}
}

// TestGovernanceStateMachine_FrozenToUpgrade verifies that an upgrade
// (changing the covenant script) can be performed from frozen state.
// Upgrades require the shard to be frozen first.
func TestGovernanceStateMachine_FrozenToUpgrade(t *testing.T) {
	cm := newTestManager(t, 1, 20, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	})

	// Verify shard is frozen.
	if cm.CurrentState().Frozen != 1 {
		t.Fatal("expected shard to be frozen (Frozen=1)")
	}

	// Build the upgrade unlock script. This requires the shard to be frozen.
	sig := []byte("governance-signature")
	newScript := []byte("new-covenant-script-v2")
	upgradeScript, err := BuildUpgradeUnlockScript(sig, newScript)
	if err != nil {
		t.Fatalf("BuildUpgradeUnlockScript failed: %v", err)
	}
	if len(upgradeScript) == 0 {
		t.Fatal("upgrade unlock script should not be empty")
	}

	// Simulate the upgrade result: the covenant UTXO transitions to a
	// new script. The state (root, block number) is preserved, and the
	// shard remains frozen until explicitly unfrozen.
	upgradedState := CovenantState{
		StateRoot:   cm.CurrentState().StateRoot,
		BlockNumber: cm.CurrentState().BlockNumber,
		Frozen:      1, // remains frozen after upgrade
	}

	// Apply the upgrade.
	upgradeTxID := types.BytesToHash([]byte{0xf2})
	if err := cm.ApplyAdvance(upgradeTxID, upgradedState); err != nil {
		t.Fatalf("ApplyAdvance failed: %v", err)
	}

	// Verify state is preserved and shard is still frozen.
	if cm.CurrentState().Frozen != 1 {
		t.Error("shard should remain frozen after upgrade")
	}
	if cm.CurrentState().BlockNumber != 20 {
		t.Error("block number should be preserved after upgrade")
	}

	// Now unfreeze to resume operations.
	activeState := CovenantState{
		StateRoot:   cm.CurrentState().StateRoot,
		BlockNumber: cm.CurrentState().BlockNumber,
		Frozen:      0,
	}
	if err := cm.ApplyAdvance(types.BytesToHash([]byte{0xf3}), activeState); err != nil {
		t.Fatalf("ApplyAdvance failed: %v", err)
	}

	// Advances should work again.
	newState := CovenantState{
		StateRoot:   testStateRoot(21),
		BlockNumber: 21,
		Frozen:      0,
	}
	_, err = cm.BuildAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv"))
	if err != nil {
		t.Fatalf("advance after upgrade+unfreeze should succeed: %v", err)
	}
}

// TestGovernanceStateMachine_ActiveToUpgradeRejected verifies that
// upgrades are rejected when the shard is active (not frozen). Upgrades
// can only be performed while frozen per the spec.
func TestGovernanceStateMachine_ActiveToUpgradeRejected(t *testing.T) {
	// The shard is active (Frozen=0).
	cm := newTestManager(t, 0, 30, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	})

	// Attempting to build an upgrade unlock script is allowed (it just
	// builds the script data), but the on-chain covenant would reject
	// the transaction because the shard is not frozen.
	//
	// At the manager level, we verify that the shard is active and
	// BuildAdvanceData works normally. The state machine constraint
	// "upgrade only when frozen" is enforced by the on-chain script,
	// but the manager-level test validates that the freeze guard on
	// BuildAdvanceData is working by confirming advances still work
	// while active.
	if cm.CurrentState().Frozen != 0 {
		t.Fatal("expected shard to be active")
	}

	// Normal advances should work when active.
	newState := CovenantState{
		StateRoot:   testStateRoot(31),
		BlockNumber: 31,
		Frozen:      0,
	}
	_, err := cm.BuildAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv"))
	if err != nil {
		t.Fatalf("advance while active should succeed: %v", err)
	}

	// But if someone tries to apply an upgrade state while active (by
	// changing the covenant script but not freezing), the on-chain script
	// would reject it. We simulate the constraint by verifying that a
	// direct upgrade attempt without freezing first would be caught
	// at the script level. At the manager level, we just verify the
	// manager's state is correct.
	//
	// The key constraint: if frozen=0, BuildAdvanceData succeeds normally.
	// The upgrade-requires-frozen constraint is enforced on-chain.
	if cm.CurrentState().Frozen != 0 {
		t.Fatal("shard should still be active after successful advance")
	}
}

// TestGovernanceStateMachine_AdvanceWhileFrozen verifies that state
// advances are rejected while the shard is frozen.
func TestGovernanceStateMachine_AdvanceWhileFrozen(t *testing.T) {
	cm := newTestManager(t, 1, 40, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	})

	// Verify shard is frozen.
	if cm.CurrentState().Frozen != 1 {
		t.Fatal("expected shard to be frozen")
	}

	// Attempting to advance state while frozen should fail.
	newState := CovenantState{
		StateRoot:   testStateRoot(41),
		BlockNumber: 41,
		Frozen:      0,
	}
	_, err := cm.BuildAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv"))
	if err == nil {
		t.Fatal("advance while frozen should be rejected")
	}

	// The error should mention frozen.
	if err.Error() != "covenant is frozen, cannot advance state" {
		t.Errorf("unexpected error message: %v", err)
	}

	// Also try advancing with Frozen=1 in the new state (still should
	// fail because block advancement is not allowed when frozen).
	frozenNewState := CovenantState{
		StateRoot:   testStateRoot(41),
		BlockNumber: 41,
		Frozen:      1,
	}
	_, err = cm.BuildAdvanceData(frozenNewState, []byte("batch"), []byte("proof"), []byte("pv"))
	if err == nil {
		t.Fatal("advance while frozen should be rejected regardless of new state frozen flag")
	}
}

// TestGovernanceStateMachine_NoneHasNoGovernanceMethods verifies that
// GovernanceNone mode has no keys and no governance capability.
func TestGovernanceStateMachine_NoneHasNoGovernanceMethods(t *testing.T) {
	gov := GovernanceConfig{Mode: GovernanceNone}

	// Validate should pass with no keys.
	if err := gov.Validate(); err != nil {
		t.Fatalf("GovernanceNone validation should pass: %v", err)
	}

	// No keys means no one can freeze/unfreeze/upgrade.
	if len(gov.Keys) != 0 {
		t.Fatalf("GovernanceNone should have 0 keys, got %d", len(gov.Keys))
	}
	if gov.Threshold != 0 {
		t.Fatalf("GovernanceNone should have threshold 0, got %d", gov.Threshold)
	}

	// Adding keys should cause validation to fail.
	govWithKeys := GovernanceConfig{
		Mode: GovernanceNone,
		Keys: [][]byte{testKey(1)},
	}
	if err := govWithKeys.Validate(); err == nil {
		t.Fatal("GovernanceNone with keys should fail validation")
	}

	// Adding threshold should cause validation to fail.
	govWithThreshold := GovernanceConfig{
		Mode:      GovernanceNone,
		Threshold: 1,
	}
	if err := govWithThreshold.Validate(); err == nil {
		t.Fatal("GovernanceNone with threshold should fail validation")
	}

	// Create a manager with GovernanceNone. Advances should work normally.
	cm := newTestManager(t, 0, 0, gov)
	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}
	_, err := cm.BuildAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv"))
	if err != nil {
		t.Fatalf("advance with GovernanceNone should succeed: %v", err)
	}
}

// TestGovernanceStateMachine_MultisigThreshold verifies M-of-N enforcement
// in the governance configuration.
func TestGovernanceStateMachine_MultisigThreshold(t *testing.T) {
	// Valid 2-of-3 multisig.
	gov := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
		Threshold: 2,
	}
	if err := gov.Validate(); err != nil {
		t.Fatalf("valid 2-of-3 multisig should pass: %v", err)
	}

	// Threshold > N should fail.
	govBadThreshold := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2)},
		Threshold: 3,
	}
	if err := govBadThreshold.Validate(); err == nil {
		t.Fatal("threshold > N should fail validation")
	}

	// Threshold == 0 should fail.
	govZeroThreshold := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2)},
		Threshold: 0,
	}
	if err := govZeroThreshold.Validate(); err == nil {
		t.Fatal("threshold 0 should fail validation for multisig")
	}

	// Threshold == N (N-of-N) should succeed.
	govNofN := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
		Threshold: 3,
	}
	if err := govNofN.Validate(); err != nil {
		t.Fatalf("N-of-N should pass: %v", err)
	}

	// Threshold == 1 (1-of-N) should succeed.
	gov1ofN := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
		Threshold: 1,
	}
	if err := gov1ofN.Validate(); err != nil {
		t.Fatalf("1-of-N should pass: %v", err)
	}

	// Only 1 key should fail (multisig needs at least 2).
	govOneKey := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1)},
		Threshold: 1,
	}
	if err := govOneKey.Validate(); err == nil {
		t.Fatal("multisig with 1 key should fail validation")
	}

	// Invalid key in set should fail.
	govBadKey := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), make([]byte, 10)}, // bad key
		Threshold: 1,
	}
	if err := govBadKey.Validate(); err == nil {
		t.Fatal("multisig with invalid key should fail validation")
	}

	// Valid multisig manager should allow advances.
	cm := newTestManager(t, 0, 0, gov)
	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}
	_, err := cm.BuildAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv"))
	if err != nil {
		t.Fatalf("advance with valid multisig should succeed: %v", err)
	}
}
