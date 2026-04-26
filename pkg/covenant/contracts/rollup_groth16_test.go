package contracts

import (
	"math/big"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// The Groth16 BN254 primitives in runar-go split into a lossy int64 family
// (Bn254MultiPairing4 returns true; Bn254G1ScalarMulP truncates to int64)
// and a full-range *big.Int family (Bn254MultiPairing4Big runs real gnark
// pairing; Bn254G1ScalarMulBigP handles 254-bit scalars). The contract now
// uses the *Big scalar-mul variant and BigintBig-typed g16Inputs / scalar
// fields, so the Go-mock F01 / F08 assertions run over real 254-bit values
// — but the pairing itself still goes through the int64 Bn254MultiPairing4
// (which returns true unconditionally) since every happy-path Advance test
// would otherwise need a real SP1 Groth16 proof fixture. Pairing fidelity
// is covered by groth16_real_pairing_test.go's standalone gnark path; the
// contract-level Go-mock verifies that F01 / F08 reject bogus scalars
// before the pairing and accepts only a correctly-bound proof payload.
// The compiled Bitcoin Script uses the real 254-bit BN254 codegen.

// ---------------------------------------------------------------------------
// Groth16 contract constructors
// ---------------------------------------------------------------------------

// R4c: the scalar-domain constants are *big.Int (BigintBig) to match the
// contract field types. They can now carry the real BN254 scalar-field
// values in the Go-mock without int64 truncation. The values chosen here
// are still small enough to make F08 boundary tests cheap (set
// g16Input_i = testBn254ScalarOrder to exercise the == r rejection) while
// living in a domain where testSP1ProgramVkHashScalar (a small constant)
// is a valid pinned scalar.

// testBn254ScalarOrder is the Go-mock stand-in for BN254 scalar field
// order r. Kept at 1<<40 so F08 negative tests can set g16Input_i
// exactly equal to the order. The on-chain contract bakes the real r =
// 21888242871839275222246405745257275088548364400416034343698204186575808495617
// via compile.go.
var testBn254ScalarOrder = big.NewInt(1 << 40)

// testBn254ScalarMask stands in for F01's on-chain 2^253 reduction modulus.
// Must be < testBn254ScalarOrder so reducePublicValuesToScalar's output
// is always in range.
var testBn254ScalarMask = big.NewInt(1 << 20)

// testSP1ProgramVkHashScalar is the F01 pinned vkey scalar the contract
// asserts against g16Input0 on every advance. Any *big.Int value that is
// both < testBn254ScalarMask (so it can be the output of the reducer, in
// the degenerate test where we force g16Input1 to match) and <
// testBn254ScalarOrder works for the mock.
var testSP1ProgramVkHashScalar = big.NewInt(4242)

// testBn254Zero is the pinned zero RHS used by the F01 g16Input2 /
// g16Input4 equality assertions. Must be a distinct *big.Int instance
// because the contract's BigintBigEqual is value-equality via
// big.Int.Cmp — pointer identity is irrelevant.
var testBn254Zero = big.NewInt(0)

func newGroth16Rollup(stateRoot string, blockNumber, frozen int64) *Groth16RollupContract {
	return &Groth16RollupContract{
		StateRoot:              runar.ByteString(stateRoot),
		BlockNumber:            blockNumber,
		Frozen:                 frozen,
		SP1VerifyingKeyHash:    runar.ByteString(testVKHash),
		ChainId:                chainId,
		Bn254ScalarOrder:       testBn254ScalarOrder,
		SP1ProgramVkHashScalar: testSP1ProgramVkHashScalar,
		Bn254ScalarMask:        testBn254ScalarMask,
		Bn254Zero:              testBn254Zero,
		GovernanceMode:         1, // single_key
		GovernanceThreshold:    1,
		GovernanceKey:          runar.Alice.PubKey,
		// IC points seeded to the BN254 generator (1, 2) so the on-chain
		// MSM — preparedInputs = IC0 + Σ g16Input_i · IC[i+1] — produces
		// on-curve intermediates under the Go-mock EC routines. Post-R6
		// runar rejects the identity point in OnCurve, so the previous
		// all-zero VK placeholders no longer pass. Bn254MultiPairing4
		// still returns true in the mock regardless.
		AlphaG1: genG1(),
		IC0:     genG1(),
		IC1:     genG1(),
		IC2:     genG1(),
		IC3:     genG1(),
		IC4:     genG1(),
		IC5:     genG1(),
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

	proofA   runar.Point
	proofBX0 runar.Bigint
	proofBX1 runar.Bigint
	proofBY0 runar.Bigint
	proofBY1 runar.Bigint
	proofC   runar.Point
	// R4c: scalar public inputs are BigintBig to run F01 / F08 over the
	// real 254-bit domain in the Go-mock. Default-zero-value *big.Int is
	// nil; buildGroth16Args must initialise g16Input2 / g16Input3 /
	// g16Input4 to distinct big.NewInt(0) instances.
	g16Input0 runar.BigintBig
	g16Input1 runar.BigintBig
	g16Input2 runar.BigintBig
	g16Input3 runar.BigintBig
	g16Input4 runar.BigintBig
}

// genG1 is the BN254 G1 generator (1, 2) encoded as 64-byte big-endian
// x || y. Rúnar's Bn254G1OnCurve (post-R6) rejects the identity point
// (0, 0), so tests that need a trivially-valid proof placeholder use the
// generator instead. y² = 4 = 1 + 3 = x³ + 3, so (1, 2) is on-curve.
func genG1() runar.Point {
	buf := make([]byte, 64)
	buf[31] = 1 // x = 1 (big-endian)
	buf[63] = 2 // y = 2 (big-endian)
	return runar.Point(string(buf))
}

// expectedG16Input1 mirrors the contract's reducePublicValuesToScalar
// computation. Post-R3 + R4c, runar.Sha256(x) is a real Go function and
// the reducer uses Bin2NumBig + BigintBigMod so the Go-mock produces the
// full 253-bit digest instead of truncating at int64. Tests constructing
// the expected scalar must follow the same wide path or the F01
// g16Input1 binding will silently mismatch.
func expectedG16Input1(publicValues string) runar.BigintBig {
	pv := runar.ByteString(publicValues)
	hashBE := runar.Sha256(pv)
	hashLE := runar.ReverseBytes(hashBE)
	padded := runar.Cat(hashLE, runar.Num2Bin(0, 1))
	return runar.BigintBigMod(runar.Bin2NumBig(padded), testBn254ScalarMask)
}

func buildGroth16Args(preStateRoot string, newBlockNumber int64) groth16AdvArgs {
	newStateRoot := stateRootForBlock(int(newBlockNumber))
	batchData := generateBatchData(preStateRoot, newStateRoot, testBatchDataSize)
	proofBlob := generateProofBlob(byte(newBlockNumber), testProofBlobSize)
	pv := buildPublicValues(preStateRoot, newStateRoot, batchData, proofBlob, chainId, newBlockNumber)

	return groth16AdvArgs{
		newStateRoot: runar.ByteString(newStateRoot),
		newBlockNum:  newBlockNumber,
		publicValues: runar.ByteString(pv),
		batchData:    runar.ByteString(batchData),
		proofBlob:    runar.ByteString(proofBlob),
		proofA:       genG1(),
		proofC:       genG1(),
		// F01: bind g16Input0 to pinned vkey scalar, g16Input1 to the
		// reduced publicValues digest. g16Input2 / g16Input3 / g16Input4
		// get fresh big.NewInt(0) instances so BigintBigEqual against
		// c.Bn254Zero evaluates value-equal (not pointer-equal) and
		// BigintBigLess against c.Bn254ScalarOrder treats the default as
		// 0 rather than nil-then-crash downstream in scalar-mul.
		g16Input0: testSP1ProgramVkHashScalar,
		g16Input1: expectedG16Input1(pv),
		g16Input2: big.NewInt(0),
		g16Input3: big.NewInt(0),
		g16Input4: big.NewInt(0),
	}
}

func callGroth16Advance(c *Groth16RollupContract, a groth16AdvArgs) {
	c.AdvanceState(
		a.newStateRoot, a.newBlockNum, a.publicValues, a.batchData, a.proofBlob,
		a.proofA, a.proofBX0, a.proofBX1, a.proofBY0, a.proofBY1, a.proofC,
		a.g16Input0, a.g16Input1, a.g16Input2, a.g16Input3, a.g16Input4,
	)
}

// buildGroth16UpgradeArgs builds a valid proof bundle for the next block,
// splices the migration hash into pv[240..272], and re-reduces g16Input1
// so the F01 publicValues-digest binding still matches after the splice.
func buildGroth16UpgradeArgs(c *Groth16RollupContract, newScript runar.ByteString) groth16AdvArgs {
	preStateRoot := string(c.StateRoot)
	newBlockNumber := int64(c.BlockNumber) + 1
	args := buildGroth16Args(preStateRoot, newBlockNumber)

	pv := []byte(args.publicValues)
	migHash := rawHash256(string(newScript))
	copy(pv[240:272], []byte(migHash))
	args.publicValues = runar.ByteString(string(pv))
	args.g16Input1 = expectedG16Input1(string(pv))
	return args
}

// callGroth16UpgradeSingleKey invokes UpgradeSingleKey with a freshly built
// proof bundle. Used by the single-key governance tests.
func callGroth16UpgradeSingleKey(c *Groth16RollupContract, sig runar.Sig, newScript runar.ByteString) {
	args := buildGroth16UpgradeArgs(c, newScript)
	c.UpgradeSingleKey(
		sig, newScript, fakeAnfHash(newScript),
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
		sig1, sig2, newScript, fakeAnfHash(newScript),
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
		string(args.batchData), string(args.proofBlob), 999, 1)
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

// TestGroth16Rollup_RejectBlockNumberMismatch pins the C4 binding:
// pv[272..280) must equal num2binLE(newBlockNumber). Mismatched proof
// block number rejects.
func TestGroth16Rollup_RejectBlockNumberMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	pv := []byte(args.publicValues)
	copy(pv[272:280], []byte(num2binLE(2)))
	args.publicValues = runar.ByteString(string(pv))
	// g16Input1 binds to sha256(pv) mod r, so reducing the mutated pv
	// needs a fresh scalar — otherwise the F01 binding assertion fires
	// before the block-number assertion and masks the regression.
	args.g16Input1 = expectedG16Input1(string(pv))
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_ProofBlobNotBoundToCovenant pins the F04 fix: the
// tautological pvProofHash check was removed, so a swapped proofBlob is
// now ACCEPTED (proof integrity is carried by the Groth16 pairing over
// (A, B, C); the proofBlob byte argument only preserves the unlock-script
// positional layout).
func TestGroth16Rollup_ProofBlobNotBoundToCovenant(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callGroth16Advance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1 after F04-allowed advance, got %d", c.BlockNumber)
	}
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
