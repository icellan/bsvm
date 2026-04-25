package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Helpers (shared across fri / groth16 / groth16-wa test files)
// ---------------------------------------------------------------------------

func rawSha256(data string) string {
	h := sha256.Sum256([]byte(data))
	return string(h[:])
}

func rawHash256(data string) string { return rawSha256(rawSha256(data)) }

func stateRootForBlock(n int) string { return rawSha256(fmt.Sprintf("%d", n)) }

func zeros32() string { return string(make([]byte, 32)) }

func num2binLE(v int64) string {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(v))
	return string(buf)
}

// ---------------------------------------------------------------------------
// Proof blob and batch data generators (shared)
// ---------------------------------------------------------------------------

const (
	testProofBlobSize = 165_000
	testBatchDataSize = 20_000
	chainId           = int64(8453111)
)

// testVKHash is a deterministic 32-byte value used as the SP1VerifyingKeyHash
// readonly property across all rollup-test fixtures. The on-chain Mode 1
// script does not consult this value (no FRI verifier), and the Groth16 /
// Groth16-WA scripts only use it as a readonly binding for public-values
// cross-referencing, so any stable 32-byte blob is sufficient.
var testVKHash = rawSha256("bsvm-test-sp1-vk-hash-fixture")

func generateProofBlob(seed byte, size int) string {
	data := make([]byte, size)
	h := sha256.Sum256([]byte{seed})
	for i := 0; i < size; i += 32 {
		end := i + 32
		if end > size {
			end = size
		}
		copy(data[i:end], h[:end-i])
		h = sha256.Sum256(h[:])
	}
	return string(data)
}

func generateBatchData(preStateRoot, newStateRoot string, size int) string {
	base := preStateRoot + newStateRoot
	data := make([]byte, size)
	copy(data, []byte(base))
	h := sha256.Sum256([]byte(base))
	for i := len(base); i < size; i += 32 {
		end := i + 32
		if end > size {
			end = size
		}
		copy(data[i:end], h[:end-i])
		h = sha256.Sum256(h[:])
	}
	return string(data)
}

// buildPublicValues constructs a 280-byte public values blob matching the
// spec 12 layout. Offset [64..96] is reserved for receiptsHash per spec
// 12 (unused by Mode 1; the Groth16 rollups don't consult it either).
// blockNumber is serialised into [272..280) as 8 little-endian bytes to
// match runar.Num2Bin(newBlockNumber, 8) on the covenant side.
func buildPublicValues(preStateRoot, postStateRoot, batchData, proofBlob string, cid, blockNumber int64) string {
	z32 := zeros32()
	z8 := string(make([]byte, 8))
	proofHash := rawHash256(proofBlob) // occupies the reserved [64..96] slot
	batchDataHash := rawHash256(batchData)
	chainIdBytes := num2binLE(cid)
	blockNumberBytes := num2binLE(blockNumber)

	return preStateRoot + postStateRoot + proofHash + z8 +
		batchDataHash + chainIdBytes +
		z32 + z32 + z32 + z32 +
		blockNumberBytes
}

// ---------------------------------------------------------------------------
// FRIRollupContract constructors
// ---------------------------------------------------------------------------

// newFRIRollup builds a FRIRollupContract with single-key governance
// (Alice). Used for the bulk of state-transition and governance tests.
func newFRIRollup(stateRoot string, blockNumber, frozen int64) *FRIRollupContract {
	return &FRIRollupContract{
		StateRoot:           runar.ByteString(stateRoot),
		BlockNumber:         blockNumber,
		Frozen:              frozen,
		SP1VerifyingKeyHash: runar.ByteString(testVKHash),
		ChainId:             chainId,
		GovernanceMode:      1, // single_key
		GovernanceThreshold: 1,
		GovernanceKey:       runar.Alice.PubKey,
	}
}

// newFRIRollupNoGov builds a contract with GovernanceMode=0 (no governance).
// Freeze/Unfreeze/Upgrade always fail because GovernanceKey is empty and
// CheckSig against an empty key always returns false.
func newFRIRollupNoGov(stateRoot string, blockNumber, frozen int64) *FRIRollupContract {
	c := newFRIRollup(stateRoot, blockNumber, frozen)
	c.GovernanceMode = 0
	c.GovernanceThreshold = 0
	c.GovernanceKey = runar.ByteString("")
	return c
}

// newFRIRollupMultiSig builds a contract with multisig governance.
// keys is the list of M-of-N pubkeys (max 3); threshold is M.
func newFRIRollupMultiSig(stateRoot string, blockNumber, frozen int64, keys []runar.TestKeyPair, threshold int64) *FRIRollupContract {
	c := newFRIRollup(stateRoot, blockNumber, frozen)
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
// AdvanceState argument bundle
// ---------------------------------------------------------------------------

type friAdvArgs struct {
	newStateRoot runar.ByteString
	newBlockNum  runar.Bigint
	publicValues runar.ByteString
	batchData    runar.ByteString
	proofBlob    runar.ByteString
}

func buildFRIArgs(preStateRoot string, newBlockNumber int64) friAdvArgs {
	newStateRoot := stateRootForBlock(int(newBlockNumber))
	batchData := generateBatchData(preStateRoot, newStateRoot, testBatchDataSize)
	proofBlob := generateProofBlob(byte(newBlockNumber), testProofBlobSize)
	pv := buildPublicValues(preStateRoot, newStateRoot, batchData, proofBlob, chainId, newBlockNumber)

	return friAdvArgs{
		newStateRoot: runar.ByteString(newStateRoot),
		newBlockNum:  newBlockNumber,
		publicValues: runar.ByteString(pv),
		batchData:    runar.ByteString(batchData),
		proofBlob:    runar.ByteString(proofBlob),
	}
}

func callFRIAdvance(c *FRIRollupContract, a friAdvArgs) {
	c.AdvanceState(
		a.newStateRoot, a.newBlockNum, a.publicValues, a.batchData, a.proofBlob,
	)
}

// buildFRIUpgradeArgs builds a valid advance args bundle and splices the
// migration hash into pv[240..272] (which Upgrade verifies). The block
// number slot at pv[272..280] was already populated to newBlockNumber by
// buildFRIArgs → buildPublicValues, so Upgrade's pvBlockNumber assertion
// matches without extra splicing.
func buildFRIUpgradeArgs(c *FRIRollupContract, newScript runar.ByteString) friAdvArgs {
	preStateRoot := string(c.StateRoot)
	newBlockNumber := int64(c.BlockNumber) + 1
	args := buildFRIArgs(preStateRoot, newBlockNumber)

	pv := []byte(args.publicValues)
	migHash := rawHash256(string(newScript))
	copy(pv[240:272], []byte(migHash))
	args.publicValues = runar.ByteString(string(pv))
	return args
}

// callFRIUpgradeSingleKey invokes UpgradeSingleKey with a freshly built
// args bundle.
func callFRIUpgradeSingleKey(c *FRIRollupContract, sig runar.Sig, newScript runar.ByteString) {
	args := buildFRIUpgradeArgs(c, newScript)
	c.UpgradeSingleKey(
		sig, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.newBlockNum,
	)
}

// callFRIUpgradeMultiSig2 invokes UpgradeMultiSig2.
func callFRIUpgradeMultiSig2(c *FRIRollupContract, sig1, sig2 runar.Sig, newScript runar.ByteString) {
	args := buildFRIUpgradeArgs(c, newScript)
	c.UpgradeMultiSig2(
		sig1, sig2, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.newBlockNum,
	)
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState happy paths
// ---------------------------------------------------------------------------

func TestFRIRollup_InitialState(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	if c.BlockNumber != 0 {
		t.Errorf("expected block 0, got %d", c.BlockNumber)
	}
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestFRIRollup_AdvanceState(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
	if string(c.StateRoot) != stateRootForBlock(1) {
		t.Error("state root not updated")
	}
}

func TestFRIRollup_ChainAdvances(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	pre := zeros32()
	for i := int64(1); i <= 3; i++ {
		args := buildFRIArgs(pre, i)
		callFRIAdvance(c, args)
		pre = stateRootForBlock(int(i))
	}
	if c.BlockNumber != 3 {
		t.Errorf("expected block 3, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState rejection paths
// ---------------------------------------------------------------------------

func TestFRIRollup_RejectWhenFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when frozen")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 1)
	callFRIAdvance(c, buildFRIArgs(zeros32(), 1))
}

func TestFRIRollup_RejectWrongPreStateRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(rawSha256("not-zero"), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)
}

func TestFRIRollup_RejectBlockNumberGoingBackward(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 5, 0)
	args := buildFRIArgs(zeros32(), 3)
	callFRIAdvance(c, args)
}

func TestFRIRollup_RejectBlockNumberSkipping(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 2)
	callFRIAdvance(c, args)
}

func TestFRIRollup_RejectWrongBatchDataHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	args.batchData = runar.ByteString(string(make([]byte, testBatchDataSize)))
	callFRIAdvance(c, args)
}

func TestFRIRollup_RejectWrongChainId(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	newStateRoot := stateRootForBlock(1)
	badPV := buildPublicValues(zeros32(), newStateRoot,
		string(args.batchData), string(args.proofBlob), 999, 1)
	args.publicValues = runar.ByteString(badPV)
	callFRIAdvance(c, args)
}

func TestFRIRollup_RejectPostStateRootMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	args.newStateRoot = runar.ByteString(rawSha256("garbage"))
	callFRIAdvance(c, args)
}

// TestFRIRollup_RejectBlockNumberMismatch pins the C4 binding: the
// public-values slot at [272..280) must encode the same block number
// the caller supplies in newBlockNumber. A prover that commits a
// different block number in the proof cannot replay it at another
// height.
func TestFRIRollup_RejectBlockNumberMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	// Splice a mismatched block number into pv[272..280): claim block 2
	// in the proof's public values while newBlockNumber = 1 is passed
	// as the method argument. The covenant's pvBlockNumber assertion
	// must reject.
	pv := []byte(args.publicValues)
	copy(pv[272:280], []byte(num2binLE(2)))
	args.publicValues = runar.ByteString(string(pv))
	callFRIAdvance(c, args)
}

// TestFRIRollup_ProofBlobNotBoundToCovenant pins the trust-minimized
// Mode 1 security model: the proofBlob argument is accepted but not
// consumed on-chain. Any proofBlob bytes that parse at the argument
// boundary are acceptable. This is by design — Mode 1 is the FRI
// bridge without an on-chain proof check; off-chain nodes verify.
func TestFRIRollup_ProofBlobNotBoundToCovenant(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callFRIAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1 after proofBlob swap, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance — single_key
// ---------------------------------------------------------------------------

func TestFRIRollup_Freeze(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 1 {
		t.Errorf("expected frozen=1, got %d", c.Frozen)
	}
}

func TestFRIRollup_FreezeRejectsAlreadyFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 1)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestFRIRollup_Unfreeze(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 1)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestFRIRollup_UnfreezeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestFRIRollup_FreezeThenAdvanceRejectedThenUnfreezeThenAdvanceSucceeds(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
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
		callFRIAdvance(c, buildFRIArgs(zeros32(), 1))
	}()

	c.UnfreezeSingleKey(sig)
	if c.Frozen != 0 {
		t.Fatal("not unfrozen")
	}

	callFRIAdvance(c, buildFRIArgs(zeros32(), 1))
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestFRIRollup_Upgrade(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callFRIUpgradeSingleKey(c, sig, runar.ByteString("new_script"))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0 after upgrade, got %d", c.Frozen)
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestFRIRollup_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callFRIUpgradeSingleKey(c, sig, runar.ByteString("new_script"))
}

// ---------------------------------------------------------------------------
// Tests: governance — none (mode 0)
// ---------------------------------------------------------------------------

func TestFRIRollup_GovernanceNone_FreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Freeze")
		}
	}()
	c := newFRIRollupNoGov(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestFRIRollup_GovernanceNone_UnfreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Unfreeze")
		}
	}()
	c := newFRIRollupNoGov(zeros32(), 0, 1)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestFRIRollup_GovernanceNone_UpgradeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Upgrade")
		}
	}()
	c := newFRIRollupNoGov(zeros32(), 0, 1)
	callFRIUpgradeSingleKey(c, runar.SignTestMessage(runar.Alice.PrivKey), runar.ByteString("new_script"))
}

func TestFRIRollup_GovernanceNone_AdvanceStillWorks(t *testing.T) {
	c := newFRIRollupNoGov(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance — multisig (2-of-2)
// ---------------------------------------------------------------------------

func TestFRIRollup_MultiSig_FreezeAndUnfreeze(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newFRIRollupMultiSig(zeros32(), 0, 0, keys, 2)

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

func TestFRIRollup_MultiSig_FreezeRejectsInsufficientSigs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: insufficient signatures for 2-of-2")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newFRIRollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	c.FreezeMultiSig2(sigA, runar.Sig(""))
}

func TestFRIRollup_MultiSig_UpgradeWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newFRIRollupMultiSig(zeros32(), 0, 1, keys, 2)

	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callFRIUpgradeMultiSig2(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestFRIRollup_MultiSig_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: must be frozen to upgrade")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newFRIRollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callFRIUpgradeMultiSig2(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestFRIRollup_MultiSig_AdvanceStillWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newFRIRollupMultiSig(zeros32(), 0, 0, keys, 2)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}
