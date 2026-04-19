package contracts

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// The witness-assisted Groth16 preamble is a compile-time codegen
// concern: runar.AssertGroth16WitnessAssistedWithMSM() is a no-op on the
// Go side (same strategy as CheckSig and the rest of the BN254 mocks),
// AND runar.Groth16PublicInput(i) always returns 0 in the Go mock (it
// reads real stack slots only in the compiled Script). The F01 bindings
// therefore look like `0 == X` under the mock; for happy-path coverage
// this file pins X = 0 via testSP1ProgramVkHashScalarWA = 0 and
// testBn254ScalarMaskWA = 1 (any value mod 1 = 0). Adversarial F01
// tests live in rollup_groth16_fixes_test.go and exercise the
// assertion by flipping the pinned value away from 0 and verifying the
// mock-produced Groth16PublicInput(0)=0 no longer matches.
//
// The compiled Bitcoin Script uses the real witness-assisted MSM-binding
// BN254 codegen when deployed via CompileGroth16WARollup.

// testSP1ProgramVkHashScalarWA is the Mode 3 counterpart to
// testSP1ProgramVkHashScalar — set to 0 so the F01 assertion
// `runar.Groth16PublicInput(0) == c.SP1ProgramVkHashScalar` holds under
// the Go-mock where Groth16PublicInput always returns 0. Real
// deployments compute the non-zero scalar via
// ReduceSP1ProgramVkHashScalar.
const testSP1ProgramVkHashScalarWA = int64(0)

// testBn254ScalarMaskWA is a mock-friendly mask: every integer mod 1
// is 0, so `runar.Groth16PublicInput(1) == reducePublicValuesToScalarWA(...)`
// holds regardless of the publicValues bytes. Real deployments bake
// 2^253 via SP1Bn254ScalarMask.
const testBn254ScalarMaskWA = int64(1)

// testBn254ScalarOrderWA is the Mode 3 Go-mock scalar-order stand-in.
// Mode 3 still uses int64 Bigint for scalar fields (the Groth16
// witness-assisted path reads inputs via runar.Groth16PublicInput(i),
// which returns int64 in the Go-mock). Mode 2's BigintBig migration
// under R4c does NOT apply here: migrating Mode 3 would require a
// `Groth16PublicInputBig` intrinsic upstream, which does not exist.
const testBn254ScalarOrderWA = int64(1 << 40)

// ---------------------------------------------------------------------------
// Groth16WA contract constructors
// ---------------------------------------------------------------------------

func newGroth16WARollup(stateRoot string, blockNumber, frozen int64) *Groth16WARollupContract {
	return &Groth16WARollupContract{
		StateRoot:              runar.ByteString(stateRoot),
		BlockNumber:            blockNumber,
		Frozen:                 frozen,
		SP1VerifyingKeyHash:    runar.ByteString(testVKHash),
		ChainId:                chainId,
		Bn254ScalarOrder:       testBn254ScalarOrderWA,
		SP1ProgramVkHashScalar: testSP1ProgramVkHashScalarWA,
		Bn254ScalarMask:        testBn254ScalarMaskWA,
		GovernanceMode:         1, // single_key
		GovernanceThreshold:    1,
		GovernanceKey:          runar.Alice.PubKey,
	}
}

func newGroth16WARollupNoGov(stateRoot string, blockNumber, frozen int64) *Groth16WARollupContract {
	c := newGroth16WARollup(stateRoot, blockNumber, frozen)
	c.GovernanceMode = 0
	c.GovernanceThreshold = 0
	c.GovernanceKey = runar.ByteString("")
	return c
}

func newGroth16WARollupMultiSig(stateRoot string, blockNumber, frozen int64, keys []runar.TestKeyPair, threshold int64) *Groth16WARollupContract {
	c := newGroth16WARollup(stateRoot, blockNumber, frozen)
	c.GovernanceMode = 2
	c.GovernanceThreshold = threshold
	if len(keys) > 0 {
		c.GovernanceKey = keys[0].PubKey
	}
	if len(keys) > 1 {
		c.GovernanceKey2 = keys[1].PubKey
	}
	if len(keys) > 2 {
		c.GovernanceKey3 = keys[2].PubKey
	}
	return c
}

// ---------------------------------------------------------------------------
// AdvanceState argument bundle — Mode 3 has only 5 core args
// ---------------------------------------------------------------------------

type groth16WAAdvArgs struct {
	newStateRoot runar.ByteString
	newBlockNum  runar.Bigint
	publicValues runar.ByteString
	batchData    runar.ByteString
	proofBlob    runar.ByteString
}

func buildGroth16WAArgs(preStateRoot string, newBlockNumber int64) groth16WAAdvArgs {
	newStateRoot := stateRootForBlock(int(newBlockNumber))
	batchData := generateBatchData(preStateRoot, newStateRoot, testBatchDataSize)
	proofBlob := generateProofBlob(byte(newBlockNumber), testProofBlobSize)
	pv := buildPublicValues(preStateRoot, newStateRoot, batchData, proofBlob, chainId)

	return groth16WAAdvArgs{
		newStateRoot: runar.ByteString(newStateRoot),
		newBlockNum:  newBlockNumber,
		publicValues: runar.ByteString(pv),
		batchData:    runar.ByteString(batchData),
		proofBlob:    runar.ByteString(proofBlob),
	}
}

func callGroth16WAAdvance(c *Groth16WARollupContract, a groth16WAAdvArgs) {
	c.AdvanceState(
		a.newStateRoot, a.newBlockNum, a.publicValues, a.batchData, a.proofBlob,
	)
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState happy paths
// ---------------------------------------------------------------------------

func TestGroth16WARollup_InitialState(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	if c.BlockNumber != 0 {
		t.Errorf("expected block 0, got %d", c.BlockNumber)
	}
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestGroth16WARollup_AdvanceState(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
	if string(c.StateRoot) != stateRootForBlock(1) {
		t.Error("state root not updated")
	}
}

func TestGroth16WARollup_ChainAdvances(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	pre := zeros32()
	for i := int64(1); i <= 3; i++ {
		args := buildGroth16WAArgs(pre, i)
		callGroth16WAAdvance(c, args)
		pre = stateRootForBlock(int(i))
	}
	if c.BlockNumber != 3 {
		t.Errorf("expected block 3, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState rejection paths
// ---------------------------------------------------------------------------

func TestGroth16WARollup_RejectWhenFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when frozen")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 1) // frozen
	callGroth16WAAdvance(c, buildGroth16WAArgs(zeros32(), 1))
}

func TestGroth16WARollup_RejectWrongPreStateRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(rawSha256("not-zero"), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)
}

func TestGroth16WARollup_RejectBlockNumberSkipping(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 2) // skip block 1
	callGroth16WAAdvance(c, args)
}

func TestGroth16WARollup_RejectWrongBatchDataHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	args.batchData = runar.ByteString(string(make([]byte, testBatchDataSize)))
	callGroth16WAAdvance(c, args)
}

func TestGroth16WARollup_RejectWrongChainId(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	newStateRoot := stateRootForBlock(1)
	badPV := buildPublicValues(zeros32(), newStateRoot,
		string(args.batchData), string(args.proofBlob), 999)
	args.publicValues = runar.ByteString(badPV)
	callGroth16WAAdvance(c, args)
}

func TestGroth16WARollup_RejectPostStateRootMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	args.newStateRoot = runar.ByteString(rawSha256("garbage"))
	callGroth16WAAdvance(c, args)
}

// TestGroth16WARollup_ProofBlobNotBoundToCovenant pins the F04 fix in
// Mode 3: the tautological pvProofHash check was removed, so a swapped
// proofBlob is now ACCEPTED (the witness-preamble verifier is responsible
// for proof validity; the proofBlob byte argument only preserves the
// unlock layout).
func TestGroth16WARollup_ProofBlobNotBoundToCovenant(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callGroth16WAAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1 after F04-allowed advance, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance — single_key
// ---------------------------------------------------------------------------

func TestGroth16WARollup_Freeze(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 1 {
		t.Errorf("expected frozen=1, got %d", c.Frozen)
	}
}

func TestGroth16WARollup_Unfreeze(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 1)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestGroth16WARollup_FreezeRejectsAlreadyFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 1)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestGroth16WARollup_Upgrade(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	newScript := runar.ByteString("new_script")
	migHash := runar.ByteString(rawHash256(string(newScript)))
	c.UpgradeSingleKey(sig, newScript, migHash, 1)
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0 after upgrade, got %d", c.Frozen)
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestGroth16WARollup_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	newScript := runar.ByteString("new_script")
	migHash := runar.ByteString(rawHash256(string(newScript)))
	c.UpgradeSingleKey(sig, newScript, migHash, 1)
}

// ---------------------------------------------------------------------------
// Tests: governance — none (mode 0)
// ---------------------------------------------------------------------------

func TestGroth16WARollup_GovernanceNone_FreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollupNoGov(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestGroth16WARollup_GovernanceNone_AdvanceStillWorks(t *testing.T) {
	c := newGroth16WARollupNoGov(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance — multisig (2-of-2)
// ---------------------------------------------------------------------------

func TestGroth16WARollup_MultiSig_FreezeAndUnfreeze(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16WARollupMultiSig(zeros32(), 0, 0, keys, 2)

	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	c.FreezeMultiSig2(sigA, sigB)
	if c.Frozen != 1 {
		t.Errorf("expected frozen=1, got %d", c.Frozen)
	}

	c.UnfreezeMultiSig2(sigA, sigB)
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestGroth16WARollup_MultiSig_AdvanceStillWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16WARollupMultiSig(zeros32(), 0, 0, keys, 2)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}
