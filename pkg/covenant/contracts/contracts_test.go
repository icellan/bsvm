package contracts

import (
	"reflect"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Tests: FRIRollupContract state fields
// ---------------------------------------------------------------------------

// sharedRollupMutableFields lists the state fields that BOTH rollup contract
// variants must expose. These are the tips of the covenant state chain.
var sharedRollupMutableFields = []string{"StateRoot", "BlockNumber", "Frozen"}

// sharedRollupReadonlyFields lists the readonly properties that BOTH rollup
// contract variants must expose (the Groth16 variant layers additional VK
// readonly fields on top — see groth16ExtraReadonlyFields).
var sharedRollupReadonlyFields = []string{
	"SP1VerifyingKeyHash", "ChainId",
	"GovernanceMode", "GovernanceThreshold",
	"GovernanceKey", "GovernanceKey2", "GovernanceKey3",
}

// groth16ExtraReadonlyFields lists the Groth16-only readonly VK components.
var groth16ExtraReadonlyFields = []string{
	"AlphaG1",
	"BetaG2X0", "BetaG2X1", "BetaG2Y0", "BetaG2Y1",
	"GammaG2X0", "GammaG2X1", "GammaG2Y0", "GammaG2Y1",
	"DeltaG2X0", "DeltaG2X1", "DeltaG2Y0", "DeltaG2Y1",
	"IC0", "IC1", "IC2", "IC3", "IC4", "IC5",
}

func assertFieldsHaveTag(t *testing.T, rt reflect.Type, names []string, want string) {
	t.Helper()
	for _, name := range names {
		f, ok := rt.FieldByName(name)
		if !ok {
			t.Errorf("%s: missing field %s", rt.Name(), name)
			continue
		}
		tag := f.Tag.Get("runar")
		if want == "" {
			if tag == "readonly" {
				t.Errorf("%s: field %s should be mutable, but has runar:\"readonly\" tag", rt.Name(), name)
			}
		} else if tag != want {
			t.Errorf("%s: field %s should have runar:%q tag, got %q", rt.Name(), name, want, tag)
		}
	}
}

func TestFRIRollupContract_StateFields(t *testing.T) {
	rt := reflect.TypeOf(FRIRollupContract{})
	assertFieldsHaveTag(t, rt, sharedRollupMutableFields, "")
	assertFieldsHaveTag(t, rt, sharedRollupReadonlyFields, "readonly")

	// Mode 1 must NOT carry any Groth16 VK readonly fields.
	for _, name := range groth16ExtraReadonlyFields {
		if _, ok := rt.FieldByName(name); ok {
			t.Errorf("FRIRollupContract should not carry Groth16 VK field %s", name)
		}
	}
}

func TestGroth16RollupContract_StateFields(t *testing.T) {
	rt := reflect.TypeOf(Groth16RollupContract{})
	assertFieldsHaveTag(t, rt, sharedRollupMutableFields, "")
	assertFieldsHaveTag(t, rt, sharedRollupReadonlyFields, "readonly")
	assertFieldsHaveTag(t, rt, groth16ExtraReadonlyFields, "readonly")
}

func TestDevKeyRollupContract_StateFields(t *testing.T) {
	rt := reflect.TypeOf(DevKeyRollupContract{})
	assertFieldsHaveTag(t, rt, sharedRollupMutableFields, "")
	assertFieldsHaveTag(t, rt, sharedRollupReadonlyFields, "readonly")

	// DevKey contract must NOT carry any Groth16 VK readonly fields —
	// it reuses the shared governance readonly layout without Groth16
	// additions.
	for _, name := range groth16ExtraReadonlyFields {
		if _, ok := rt.FieldByName(name); ok {
			t.Errorf("DevKeyRollupContract should not carry Groth16 VK field %s", name)
		}
	}
}

func TestDevKeyRollupContract_AdvanceStateParamCount(t *testing.T) {
	// Receiver + 6 args: sig, newStateRoot, newBlockNumber, publicValues,
	// batchData, proofBlob. One more than FRI's AdvanceState because the
	// devnet variant adds the leading CheckSig signature param.
	rt := reflect.TypeOf(&DevKeyRollupContract{})
	m, ok := rt.MethodByName("AdvanceState")
	if !ok {
		t.Fatal("DevKeyRollupContract missing method AdvanceState")
	}
	if got := m.Type.NumIn(); got != 7 {
		t.Errorf("DevKeyRollupContract.AdvanceState: expected 7 params (incl receiver), got %d", got)
	}
}

func TestDevKeyRollupContract_FreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&DevKeyRollupContract{})
	requireMethodArity(t, rt, "FreezeSingleKey", 2)
	requireMethodArity(t, rt, "FreezeMultiSig2", 3)
	requireMethodArity(t, rt, "FreezeMultiSig3", 4)
}

func TestDevKeyRollupContract_UnfreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&DevKeyRollupContract{})
	requireMethodArity(t, rt, "UnfreezeSingleKey", 2)
	requireMethodArity(t, rt, "UnfreezeMultiSig2", 3)
	requireMethodArity(t, rt, "UnfreezeMultiSig3", 4)
}

func TestDevKeyRollupContract_UpgradeMethods(t *testing.T) {
	rt := reflect.TypeOf(&DevKeyRollupContract{})
	requireMethodArity(t, rt, "UpgradeSingleKey", 1+1+5)
	requireMethodArity(t, rt, "UpgradeMultiSig2", 1+2+5)
	requireMethodArity(t, rt, "UpgradeMultiSig3", 1+3+5)
}

func TestGroth16WARollupContract_StateFields(t *testing.T) {
	rt := reflect.TypeOf(Groth16WARollupContract{})
	assertFieldsHaveTag(t, rt, sharedRollupMutableFields, "")
	assertFieldsHaveTag(t, rt, sharedRollupReadonlyFields, "readonly")

	// Mode 3 does NOT carry any Groth16 VK readonly fields — the VK is baked
	// by the witness-assisted preamble emitter, not as readonly args.
	for _, name := range groth16ExtraReadonlyFields {
		if _, ok := rt.FieldByName(name); ok {
			t.Errorf("Groth16WARollupContract should not carry Groth16 VK field %s", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: rollup variants expose AdvanceState with the correct arity
// ---------------------------------------------------------------------------

func TestFRIRollupContract_AdvanceStateParamCount(t *testing.T) {
	// Receiver + 5 args: newStateRoot, newBlockNumber, publicValues,
	// batchData, proofBlob. Mode 1 does NOT verify the FRI proof
	// on-chain (trust-minimized bridge) so it carries no proof-field /
	// Merkle-path positional args. Total = 6.
	rt := reflect.TypeOf(&FRIRollupContract{})
	m, ok := rt.MethodByName("AdvanceState")
	if !ok {
		t.Fatal("FRIRollupContract missing method AdvanceState")
	}
	if got := m.Type.NumIn(); got != 6 {
		t.Errorf("FRIRollupContract.AdvanceState: expected 6 params (incl receiver), got %d", got)
	}
}

func TestGroth16RollupContract_AdvanceStateParamCount(t *testing.T) {
	// Receiver + 16 args: newStateRoot, newBlockNumber, publicValues,
	// batchData, proofBlob, proofA, proofBX0/X1/Y0/Y1, proofC, g16Input0..4.
	// Total = 17.
	rt := reflect.TypeOf(&Groth16RollupContract{})
	m, ok := rt.MethodByName("AdvanceState")
	if !ok {
		t.Fatal("Groth16RollupContract missing method AdvanceState")
	}
	if got := m.Type.NumIn(); got != 17 {
		t.Errorf("Groth16RollupContract.AdvanceState: expected 17 params (incl receiver), got %d", got)
	}
}

func TestGroth16WARollupContract_AdvanceStateParamCount(t *testing.T) {
	// Receiver + 5 args: newStateRoot, newBlockNumber, publicValues,
	// batchData, proofBlob. The witness-assisted preamble consumes its
	// bundle from the top of the stack (pushed via CallOptions), so no
	// additional positional proof args. Total = 6.
	rt := reflect.TypeOf(&Groth16WARollupContract{})
	m, ok := rt.MethodByName("AdvanceState")
	if !ok {
		t.Fatal("Groth16WARollupContract missing method AdvanceState")
	}
	if got := m.Type.NumIn(); got != 6 {
		t.Errorf("Groth16WARollupContract.AdvanceState: expected 6 params (incl receiver), got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance method arities on each variant
// ---------------------------------------------------------------------------
//
// The Rúnar affine value checker rejects a single Freeze/Unfreeze/Upgrade
// method that branches on c.GovernanceMode and reuses sig1 across
// mutually-exclusive arms. Each governance action is therefore split into
// three entry points — SingleKey, MultiSig2, MultiSig3 — that take only the
// signatures they need. The matrix per contract is:
//
//   - FreezeSingleKey    / UnfreezeSingleKey    / UpgradeSingleKey   (mode 1)
//   - FreezeMultiSig2    / UnfreezeMultiSig2    / UpgradeMultiSig2   (mode 2, M=2)
//   - FreezeMultiSig3    / UnfreezeMultiSig3    / UpgradeMultiSig3   (mode 2, M=3)

// requireMethodArity asserts that the named method on rt exists and takes
// exactly wantParams parameters (including the receiver).
func requireMethodArity(t *testing.T, rt reflect.Type, name string, wantParams int) {
	t.Helper()
	m, ok := rt.MethodByName(name)
	if !ok {
		t.Fatalf("%s: missing method %s", rt.Elem().Name(), name)
	}
	if got := m.Type.NumIn(); got != wantParams {
		t.Errorf("%s.%s: expected %d params (incl receiver), got %d",
			rt.Elem().Name(), name, wantParams, got)
	}
}

func TestFRIRollupContract_FreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&FRIRollupContract{})
	// FreezeSingleKey: receiver + sig                   = 2
	// FreezeMultiSig2: receiver + sig1, sig2            = 3
	// FreezeMultiSig3: receiver + sig1, sig2, sig3      = 4
	requireMethodArity(t, rt, "FreezeSingleKey", 2)
	requireMethodArity(t, rt, "FreezeMultiSig2", 3)
	requireMethodArity(t, rt, "FreezeMultiSig3", 4)
}

func TestFRIRollupContract_UnfreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&FRIRollupContract{})
	requireMethodArity(t, rt, "UnfreezeSingleKey", 2)
	requireMethodArity(t, rt, "UnfreezeMultiSig2", 3)
	requireMethodArity(t, rt, "UnfreezeMultiSig3", 4)
}

func TestFRIRollupContract_UpgradeMethods(t *testing.T) {
	// Mode 1 Upgrade does NOT carry an on-chain proof check (same trust
	// model as AdvanceState). Common upgrade payload (excluding sigs) is
	// 5 args: newCovenantScript, publicValues, batchData, proofBlob,
	// newBlockNumber.
	rt := reflect.TypeOf(&FRIRollupContract{})
	requireMethodArity(t, rt, "UpgradeSingleKey", 1+1+5) // receiver + sig + 5 payload
	requireMethodArity(t, rt, "UpgradeMultiSig2", 1+2+5) // receiver + 2 sigs + 5 payload
	requireMethodArity(t, rt, "UpgradeMultiSig3", 1+3+5) // receiver + 3 sigs + 5 payload
}

func TestGroth16RollupContract_FreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&Groth16RollupContract{})
	requireMethodArity(t, rt, "FreezeSingleKey", 2)
	requireMethodArity(t, rt, "FreezeMultiSig2", 3)
	requireMethodArity(t, rt, "FreezeMultiSig3", 4)
}

func TestGroth16RollupContract_UnfreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&Groth16RollupContract{})
	requireMethodArity(t, rt, "UnfreezeSingleKey", 2)
	requireMethodArity(t, rt, "UnfreezeMultiSig2", 3)
	requireMethodArity(t, rt, "UnfreezeMultiSig3", 4)
}

func TestGroth16RollupContract_UpgradeMethods(t *testing.T) {
	// Common upgrade payload (excluding sigs) for Groth16 is 16 args:
	// newCovenantScript, publicValues, batchData, proofBlob,
	// proofA, proofBX0/X1/Y0/Y1, proofC, g16Input0..4, newBlockNumber.
	rt := reflect.TypeOf(&Groth16RollupContract{})
	requireMethodArity(t, rt, "UpgradeSingleKey", 1+1+16) // receiver + sig + 16 payload
	requireMethodArity(t, rt, "UpgradeMultiSig2", 1+2+16)
	requireMethodArity(t, rt, "UpgradeMultiSig3", 1+3+16)
}

func TestGroth16WARollupContract_FreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&Groth16WARollupContract{})
	requireMethodArity(t, rt, "FreezeSingleKey", 2)
	requireMethodArity(t, rt, "FreezeMultiSig2", 3)
	requireMethodArity(t, rt, "FreezeMultiSig3", 4)
}

func TestGroth16WARollupContract_UnfreezeMethods(t *testing.T) {
	rt := reflect.TypeOf(&Groth16WARollupContract{})
	requireMethodArity(t, rt, "UnfreezeSingleKey", 2)
	requireMethodArity(t, rt, "UnfreezeMultiSig2", 3)
	requireMethodArity(t, rt, "UnfreezeMultiSig3", 4)
}

func TestGroth16WARollupContract_UpgradeMethods(t *testing.T) {
	// Mode 3 Upgrade does NOT re-verify a proof (the witness preamble can
	// only be used by a single method, and that method is AdvanceState),
	// so the governance signatures are the sole authorization. Common
	// upgrade payload is 2 args: newCovenantScript, newBlockNumber.
	rt := reflect.TypeOf(&Groth16WARollupContract{})
	// F05: Mode 3 Upgrade* payload is 3 args — newCovenantScript,
	// migrationHash, newBlockNumber — with migrationHash asserted equal
	// to Hash256(newCovenantScript) on chain.
	requireMethodArity(t, rt, "UpgradeSingleKey", 1+1+3) // receiver + sig + 3 payload
	requireMethodArity(t, rt, "UpgradeMultiSig2", 1+2+3)
	requireMethodArity(t, rt, "UpgradeMultiSig3", 1+3+3)
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
