package contracts

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// The witness-assisted Groth16 preamble is a compile-time codegen concern:
// runar.AssertGroth16WitnessAssisted() is a no-op on the Go side (same
// strategy as CheckSig and the rest of the BN254 mocks), so the Go tests
// below exercise the same non-preamble invariants — frozen check, block
// number monotonicity, public-values binding — that the two other rollup
// variants exercise. The compiled Bitcoin Script uses the real witness-
// assisted BN254 codegen when deployed via CompileGroth16WARollup.

// ---------------------------------------------------------------------------
// Groth16WA contract constructors
// ---------------------------------------------------------------------------

func newGroth16WARollup(stateRoot string, blockNumber, frozen int64) *Groth16WARollupContract {
	return &Groth16WARollupContract{
		StateRoot:           runar.ByteString(stateRoot),
		BlockNumber:         blockNumber,
		Frozen:              frozen,
		SP1VerifyingKeyHash: runar.ByteString(testMerkleRoot),
		ChainId:             chainId,
		GovernanceMode:      1, // single_key
		GovernanceThreshold: 1,
		GovernanceKey:       runar.Alice.PubKey,
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

func TestGroth16WARollup_RejectBadProofBlobHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callGroth16WAAdvance(c, args)
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
	c.UpgradeSingleKey(sig, runar.ByteString("new_script"), 1)
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
	c.UpgradeSingleKey(sig, runar.ByteString("new_script"), 1)
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
