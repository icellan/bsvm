package contracts

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// The Groth16 BN254 primitives in runar-go are mock implementations for the
// Go test harness: Bn254MultiPairing4 always returns true, and the G1 curve
// check accepts the identity point (0,0) — so a fully zero proof / VK tuple
// satisfies every BN254 assertion inside AdvanceState. That lets these tests
// exercise the non-pairing invariants (frozen, block number, public values
// binding, hash checks) without constructing real elliptic-curve data.
// The compiled Bitcoin Script uses the real 254-bit BN254 codegen.

// ---------------------------------------------------------------------------
// Groth16 contract constructors
// ---------------------------------------------------------------------------

func newGroth16Rollup(stateRoot string, blockNumber, frozen int64) *Groth16RollupContract {
	return &Groth16RollupContract{
		StateRoot:           runar.ByteString(stateRoot),
		BlockNumber:         blockNumber,
		Frozen:              frozen,
		SP1VerifyingKeyHash: runar.ByteString(testMerkleRoot),
		ChainId:             chainId,
		GovernanceMode:      1, // single_key
		GovernanceThreshold: 1,
		GovernanceKey:       runar.Alice.PubKey,
		// VK components default to their zero values — runar-go's BN254 mock
		// accepts the identity point on the curve check and MultiPairing4
		// always returns true.
	}
}

func newGroth16RollupNoGov(stateRoot string, blockNumber, frozen int64) *Groth16RollupContract {
	c := newGroth16Rollup(stateRoot, blockNumber, frozen)
	c.GovernanceMode = 0
	c.GovernanceThreshold = 0
	c.GovernanceKey = runar.ByteString("")
	return c
}

func newGroth16RollupMultiSig(stateRoot string, blockNumber, frozen int64, keys []runar.TestKeyPair, threshold int64) *Groth16RollupContract {
	c := newGroth16Rollup(stateRoot, blockNumber, frozen)
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
// AdvanceState argument bundle (groth16-only)
// ---------------------------------------------------------------------------

type groth16AdvArgs struct {
	newStateRoot runar.ByteString
	newBlockNum  runar.Bigint
	publicValues runar.ByteString
	batchData    runar.ByteString
	proofBlob    runar.ByteString

	proofA    runar.Point
	proofBX0  runar.Bigint
	proofBX1  runar.Bigint
	proofBY0  runar.Bigint
	proofBY1  runar.Bigint
	proofC    runar.Point
	g16Input0 runar.Bigint
	g16Input1 runar.Bigint
	g16Input2 runar.Bigint
	g16Input3 runar.Bigint
	g16Input4 runar.Bigint
}

// zeroG1 is a 64-byte all-zero Rúnar Point (the identity point). runar-go's
// Bn254G1OnCurve accepts it as on-curve, so it's a convenient test placeholder.
func zeroG1() runar.Point { return runar.Point(string(make([]byte, 64))) }

func buildGroth16Args(preStateRoot string, newBlockNumber int64) groth16AdvArgs {
	newStateRoot := stateRootForBlock(int(newBlockNumber))
	batchData := generateBatchData(preStateRoot, newStateRoot, testBatchDataSize)
	proofBlob := generateProofBlob(byte(newBlockNumber), testProofBlobSize)
	pv := buildPublicValues(preStateRoot, newStateRoot, batchData, proofBlob, chainId)

	return groth16AdvArgs{
		newStateRoot: runar.ByteString(newStateRoot),
		newBlockNum:  newBlockNumber,
		publicValues: runar.ByteString(pv),
		batchData:    runar.ByteString(batchData),
		proofBlob:    runar.ByteString(proofBlob),
		proofA:       zeroG1(),
		proofC:       zeroG1(),
		// Bigint inputs default to zero.
	}
}

func callGroth16Advance(c *Groth16RollupContract, a groth16AdvArgs) {
	c.AdvanceState(
		a.newStateRoot, a.newBlockNum, a.publicValues, a.batchData, a.proofBlob,
		a.proofA, a.proofBX0, a.proofBX1, a.proofBY0, a.proofBY1, a.proofC,
		a.g16Input0, a.g16Input1, a.g16Input2, a.g16Input3, a.g16Input4,
	)
}

// buildGroth16UpgradeArgs builds a valid proof bundle for the next block and
// splices the migration hash into pv[240..272].
func buildGroth16UpgradeArgs(c *Groth16RollupContract, newScript runar.ByteString) groth16AdvArgs {
	preStateRoot := string(c.StateRoot)
	newBlockNumber := int64(c.BlockNumber) + 1
	args := buildGroth16Args(preStateRoot, newBlockNumber)

	pv := []byte(args.publicValues)
	migHash := rawHash256(string(newScript))
	copy(pv[240:272], []byte(migHash))
	args.publicValues = runar.ByteString(string(pv))
	return args
}

// callGroth16UpgradeSingleKey invokes UpgradeSingleKey with a freshly built
// proof bundle. Used by the single-key governance tests.
func callGroth16UpgradeSingleKey(c *Groth16RollupContract, sig runar.Sig, newScript runar.ByteString) {
	args := buildGroth16UpgradeArgs(c, newScript)
	c.UpgradeSingleKey(
		sig, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.proofA, args.proofBX0, args.proofBX1, args.proofBY0, args.proofBY1, args.proofC,
		args.g16Input0, args.g16Input1, args.g16Input2, args.g16Input3, args.g16Input4,
		args.newBlockNum,
	)
}

// callGroth16UpgradeMultiSig2 invokes UpgradeMultiSig2 with a freshly built
// proof bundle. Used by the 2-of-3 multisig governance tests.
func callGroth16UpgradeMultiSig2(c *Groth16RollupContract, sig1, sig2 runar.Sig, newScript runar.ByteString) {
	args := buildGroth16UpgradeArgs(c, newScript)
	c.UpgradeMultiSig2(
		sig1, sig2, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.proofA, args.proofBX0, args.proofBX1, args.proofBY0, args.proofBY1, args.proofC,
		args.g16Input0, args.g16Input1, args.g16Input2, args.g16Input3, args.g16Input4,
		args.newBlockNum,
	)
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState happy paths
// ---------------------------------------------------------------------------

func TestGroth16Rollup_InitialState(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	if c.BlockNumber != 0 {
		t.Errorf("expected block 0, got %d", c.BlockNumber)
	}
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestGroth16Rollup_AdvanceState(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
	if string(c.StateRoot) != stateRootForBlock(1) {
		t.Error("state root not updated")
	}
}

func TestGroth16Rollup_ChainAdvances(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	pre := zeros32()
	for i := int64(1); i <= 3; i++ {
		args := buildGroth16Args(pre, i)
		callGroth16Advance(c, args)
		pre = stateRootForBlock(int(i))
	}
	if c.BlockNumber != 3 {
		t.Errorf("expected block 3, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState rejection paths
// ---------------------------------------------------------------------------

func TestGroth16Rollup_RejectWhenFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when frozen")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 1) // frozen
	callGroth16Advance(c, buildGroth16Args(zeros32(), 1))
}

func TestGroth16Rollup_RejectWrongPreStateRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(rawSha256("not-zero"), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)
}

func TestGroth16Rollup_RejectBlockNumberGoingBackward(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 5, 0)
	args := buildGroth16Args(zeros32(), 3)
	callGroth16Advance(c, args)
}

func TestGroth16Rollup_RejectBlockNumberSkipping(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 2)
	callGroth16Advance(c, args)
}

func TestGroth16Rollup_RejectWrongBatchDataHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.batchData = runar.ByteString(string(make([]byte, testBatchDataSize)))
	callGroth16Advance(c, args)
}

func TestGroth16Rollup_RejectWrongChainId(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	newStateRoot := stateRootForBlock(1)
	badPV := buildPublicValues(zeros32(), newStateRoot,
		string(args.batchData), string(args.proofBlob), 999)
	args.publicValues = runar.ByteString(badPV)
	callGroth16Advance(c, args)
}

func TestGroth16Rollup_RejectPostStateRootMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.newStateRoot = runar.ByteString(rawSha256("garbage"))
	callGroth16Advance(c, args)
}

func TestGroth16Rollup_RejectBadProofBlobHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callGroth16Advance(c, args)
}

// ---------------------------------------------------------------------------
// Tests: governance — single_key
// ---------------------------------------------------------------------------

func TestGroth16Rollup_Freeze(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 1 {
		t.Errorf("expected frozen=1, got %d", c.Frozen)
	}
}

func TestGroth16Rollup_FreezeRejectsAlreadyFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 1)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestGroth16Rollup_Unfreeze(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 1)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestGroth16Rollup_UnfreezeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestGroth16Rollup_FreezeThenAdvanceRejectedThenUnfreezeThenAdvanceSucceeds(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)

	c.FreezeSingleKey(sig)
	if c.Frozen != 1 {
		t.Fatal("not frozen")
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected advance to fail when frozen")
			}
		}()
		callGroth16Advance(c, buildGroth16Args(zeros32(), 1))
	}()

	c.UnfreezeSingleKey(sig)
	if c.Frozen != 0 {
		t.Fatal("not unfrozen")
	}

	callGroth16Advance(c, buildGroth16Args(zeros32(), 1))
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestGroth16Rollup_Upgrade(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callGroth16UpgradeSingleKey(c, sig, runar.ByteString("new_script"))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0 after upgrade, got %d", c.Frozen)
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestGroth16Rollup_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callGroth16UpgradeSingleKey(c, sig, runar.ByteString("new_script"))
}

// ---------------------------------------------------------------------------
// Tests: governance — none (mode 0)
// ---------------------------------------------------------------------------

func TestGroth16Rollup_GovernanceNone_FreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Freeze")
		}
	}()
	c := newGroth16RollupNoGov(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestGroth16Rollup_GovernanceNone_UnfreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Unfreeze")
		}
	}()
	c := newGroth16RollupNoGov(zeros32(), 0, 1)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestGroth16Rollup_GovernanceNone_UpgradeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Upgrade")
		}
	}()
	c := newGroth16RollupNoGov(zeros32(), 0, 1)
	callGroth16UpgradeSingleKey(c, runar.SignTestMessage(runar.Alice.PrivKey), runar.ByteString("new_script"))
}

func TestGroth16Rollup_GovernanceNone_AdvanceStillWorks(t *testing.T) {
	c := newGroth16RollupNoGov(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance — multisig (2-of-2)
// ---------------------------------------------------------------------------

func TestGroth16Rollup_MultiSig_FreezeAndUnfreeze(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16RollupMultiSig(zeros32(), 0, 0, keys, 2)

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

func TestGroth16Rollup_MultiSig_FreezeRejectsInsufficientSigs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: insufficient signatures for 2-of-2")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16RollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	c.FreezeMultiSig2(sigA, runar.Sig(""))
}

func TestGroth16Rollup_MultiSig_UpgradeWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16RollupMultiSig(zeros32(), 0, 1, keys, 2)

	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callGroth16UpgradeMultiSig2(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestGroth16Rollup_MultiSig_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: must be frozen to upgrade")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16RollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callGroth16UpgradeMultiSig2(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestGroth16Rollup_MultiSig_AdvanceStillWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16RollupMultiSig(zeros32(), 0, 0, keys, 2)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}
