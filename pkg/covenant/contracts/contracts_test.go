package contracts

import (
	"reflect"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Tests: RollupContract state fields
// ---------------------------------------------------------------------------

func TestRollupContract_StateFields(t *testing.T) {
	rt := reflect.TypeOf(RollupContract{})

	// Mutable state fields (no runar:"readonly" tag).
	mutable := []string{"StateRoot", "BlockNumber", "Frozen"}
	for _, name := range mutable {
		f, ok := rt.FieldByName(name)
		if !ok {
			t.Errorf("RollupContract missing mutable state field %s", name)
			continue
		}
		tag := f.Tag.Get("runar")
		if tag == "readonly" {
			t.Errorf("state field %s should be mutable, but has runar:\"readonly\" tag", name)
		}
	}

	// Readonly fields (must have runar:"readonly" tag).
	readonly := []string{
		"VerifyingKeyHash", "ChainId", "VerificationMode",
		"GovernanceMode", "GovernanceThreshold",
		"GovernanceKey", "GovernanceKey2", "GovernanceKey3",
		"AlphaG1",
		"BetaG2X0", "BetaG2X1", "BetaG2Y0", "BetaG2Y1",
		"GammaG2X0", "GammaG2X1", "GammaG2Y0", "GammaG2Y1",
		"DeltaG2X0", "DeltaG2X1", "DeltaG2Y0", "DeltaG2Y1",
		"IC0", "IC1", "IC2", "IC3", "IC4", "IC5",
	}
	for _, name := range readonly {
		f, ok := rt.FieldByName(name)
		if !ok {
			t.Errorf("RollupContract missing readonly field %s", name)
			continue
		}
		tag := f.Tag.Get("runar")
		if tag != "readonly" {
			t.Errorf("field %s should have runar:\"readonly\" tag, got %q", name, tag)
		}
	}
}

// TestRollupContract_AdvancesSinceInbox removed — inbox tracking moved to
// overlay node layer (pkg/overlay/inbox_monitor.go).

// ---------------------------------------------------------------------------
// Tests: Unified AdvanceState handles inbox (C5)
// ---------------------------------------------------------------------------

func TestRollupContract_AdvanceStateParamCount(t *testing.T) {
	// Verify the unified AdvanceState method exists and has the correct
	// parameter count (receiver + 22 args = 23 total).
	// The 22 args are: newStateRoot, newBlockNumber, publicValues, batchData,
	// proofBlob, proofFieldA/B/C, merkleLeaf, merkleProof, merkleIndex,
	// proofA, proofBX0/X1/Y0/Y1, proofC, g16Input0..g16Input4.
	rt := reflect.TypeOf(&RollupContract{})
	m, ok := rt.MethodByName("AdvanceState")
	if !ok {
		t.Fatal("RollupContract missing method AdvanceState")
	}

	if got := m.Type.NumIn(); got != 23 {
		t.Errorf("AdvanceState: expected 23 params (incl receiver), got %d", got)
	}

	// Verify AdvanceStateWithInbox does NOT exist (unified into AdvanceState).
	_, exists := rt.MethodByName("AdvanceStateWithInbox")
	if exists {
		t.Error("AdvanceStateWithInbox should not exist — it was unified into AdvanceState (C5)")
	}
}

// ---------------------------------------------------------------------------
// Tests: Migrate method
// ---------------------------------------------------------------------------

func TestRollupContract_UpgradeMethod(t *testing.T) {
	// Verify the Upgrade method exists via reflection.
	rt := reflect.TypeOf(&RollupContract{})
	m, ok := rt.MethodByName("Upgrade")
	if !ok {
		t.Fatal("RollupContract missing method Upgrade")
	}

	// Method should have 26 parameters (receiver + 25 args):
	// sig1, sig2, sig3, newCovenantScript, publicValues, batchData, proofBlob,
	// proofFieldA/B/C, merkleLeaf, merkleProof, merkleIndex,
	// proofA, proofBX0/X1/Y0/Y1, proofC, g16Input0..g16Input4,
	// newBlockNumber.
	if got := m.Type.NumIn(); got != 26 {
		t.Errorf("Upgrade: expected 26 params (incl receiver), got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Tests: InboxContract Submit
// ---------------------------------------------------------------------------

func TestInboxContract_Submit(t *testing.T) {
	c := &InboxContract{
		TxQueueHash: runar.Hash256(runar.Num2Bin(0, 32)),
		TxCount:     0,
	}

	// Submit a transaction and verify state updates.
	c.Submit(runar.ByteString("tx-data-one-padding-to-32-bytes!"))
	if c.TxCount != 1 {
		t.Errorf("expected TxCount=1 after submit, got %d", c.TxCount)
	}

	// Submit another and verify count increments.
	c.Submit(runar.ByteString("tx-data-two-padding-to-32-bytes!"))
	if c.TxCount != 2 {
		t.Errorf("expected TxCount=2 after second submit, got %d", c.TxCount)
	}

	// Hash should not be the initial zero hash anymore.
	emptyHash := runar.Hash256(runar.Num2Bin(0, 32))
	if c.TxQueueHash == emptyHash {
		t.Error("TxQueueHash should change after submitting transactions")
	}
}

// NOTE: Drain tests removed per spec 10 -- inbox drain is handled through
// the state covenant's STARK public values, not as a separate inbox method.
