package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const kbP = 2_130_706_433 // KoalaBear field prime (p = 2^31 - 2^24 + 1)

func kbMul(a, b int64) int64 { return (a * b) % kbP }

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
// Depth-20 Merkle tree (sparse — builds proof without full 2^20 leaf tree)
// ---------------------------------------------------------------------------

func buildDepth20Proof(leaf string, index int) (proof, root string) {
	var siblings []string
	current := leaf
	idx := index
	for d := 0; d < 20; d++ {
		sibling := rawSha256(fmt.Sprintf("sib-%d-%d", d, idx^1))
		siblings = append(siblings, sibling)
		if idx&1 == 0 {
			current = rawSha256(current + sibling)
		} else {
			current = rawSha256(sibling + current)
		}
		idx >>= 1
	}
	p := ""
	for _, s := range siblings {
		p += s
	}
	return p, current
}

// ---------------------------------------------------------------------------
// Proof blob and batch data generators
// ---------------------------------------------------------------------------

const (
	testProofBlobSize = 165_000
	testBatchDataSize = 20_000
	chainId           = int64(8453111)
	leafIdx           = 7
)

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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

var testMerkleLeaf string
var testMerkleProof string
var testMerkleRoot string

func init() {
	testMerkleLeaf = rawSha256("test-leaf")
	testMerkleProof, testMerkleRoot = buildDepth20Proof(testMerkleLeaf, leafIdx)
}

// buildPublicValues constructs a 272-byte public values blob matching the
// spec 12 layout. Offset [64..96] is proofBlobHash (hash256 of proof blob).
func buildPublicValues(preStateRoot, postStateRoot, batchData, proofBlob string, cid int64) string {
	z32 := zeros32()
	z8 := string(make([]byte, 8))
	proofHash := rawHash256(proofBlob)
	batchDataHash := rawHash256(batchData)
	chainIdBytes := num2binLE(cid)

	return preStateRoot + postStateRoot + proofHash + z8 +
		batchDataHash + chainIdBytes +
		z32 + z32 + z32 + z32
}

// ---------------------------------------------------------------------------
// Contract constructors
// ---------------------------------------------------------------------------

// newRollup builds a Basefold-mode RollupContract with single-key governance
// (Alice). Used for the bulk of state-transition and governance tests.
func newRollup(stateRoot string, blockNumber, frozen int64) *RollupContract {
	return &RollupContract{
		StateRoot:           runar.ByteString(stateRoot),
		BlockNumber:         blockNumber,
		Frozen:              frozen,
		VerifyingKeyHash:    runar.ByteString(testMerkleRoot),
		ChainId:             chainId,
		VerificationMode:    0, // Basefold
		GovernanceMode:      1, // single_key
		GovernanceThreshold: 1,
		GovernanceKey:       runar.Alice.PubKey,
	}
}

// newRollupNoGov builds a contract with GovernanceMode=0 (no governance).
// Freeze/Unfreeze/Upgrade always fail because GovernanceKey is empty and
// CheckSig against an empty key always returns false.
func newRollupNoGov(stateRoot string, blockNumber, frozen int64) *RollupContract {
	c := newRollup(stateRoot, blockNumber, frozen)
	c.GovernanceMode = 0
	c.GovernanceThreshold = 0
	c.GovernanceKey = runar.ByteString("")
	return c
}

// newRollupMultiSig builds a contract with multisig governance.
// keys is the list of M-of-N pubkeys (max 3); threshold is M.
func newRollupMultiSig(stateRoot string, blockNumber, frozen int64, keys []runar.TestKeyPair, threshold int64) *RollupContract {
	c := newRollup(stateRoot, blockNumber, frozen)
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

// newRollupWithMode is currently unused but kept for future Groth16 tests
// that need to construct a contract in mode 1.
func newRollupWithMode(stateRoot string, blockNumber, frozen, mode int64) *RollupContract {
	c := newRollup(stateRoot, blockNumber, frozen)
	c.VerificationMode = mode
	return c
}

// _ keeps newRollupWithMode reachable for future test additions without
// triggering an unused-function lint warning.
var _ = newRollupWithMode

// ---------------------------------------------------------------------------
// AdvanceState argument bundle
// ---------------------------------------------------------------------------

type advArgs struct {
	newStateRoot runar.ByteString
	newBlockNum  runar.Bigint
	publicValues runar.ByteString
	batchData    runar.ByteString
	proofBlob    runar.ByteString

	// Basefold proof elements
	proofFieldA runar.Bigint
	proofFieldB runar.Bigint
	proofFieldC runar.Bigint
	merkleLeaf  runar.ByteString
	merkleProof runar.ByteString
	merkleIndex runar.Bigint

	// Groth16 proof elements (zero placeholders for Basefold tests)
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

func buildArgs(preStateRoot string, newBlockNumber int64) advArgs {
	newStateRoot := stateRootForBlock(int(newBlockNumber))
	batchData := generateBatchData(preStateRoot, newStateRoot, testBatchDataSize)
	proofBlob := generateProofBlob(byte(newBlockNumber), testProofBlobSize)
	pv := buildPublicValues(preStateRoot, newStateRoot, batchData, proofBlob, chainId)

	return advArgs{
		newStateRoot: runar.ByteString(newStateRoot),
		newBlockNum:  newBlockNumber,
		publicValues: runar.ByteString(pv),
		batchData:    runar.ByteString(batchData),
		proofBlob:    runar.ByteString(proofBlob),
		proofFieldA:  1_000_000,
		proofFieldB:  2_000_000,
		proofFieldC:  kbMul(1_000_000, 2_000_000),
		merkleLeaf:   runar.ByteString(testMerkleLeaf),
		merkleProof:  runar.ByteString(testMerkleProof),
		merkleIndex:  int64(leafIdx),
	}
}

func callAdvance(c *RollupContract, a advArgs) {
	c.AdvanceState(
		a.newStateRoot, a.newBlockNum, a.publicValues, a.batchData, a.proofBlob,
		a.proofFieldA, a.proofFieldB, a.proofFieldC,
		a.merkleLeaf, a.merkleProof, a.merkleIndex,
		a.proofA, a.proofBX0, a.proofBX1, a.proofBY0, a.proofBY1, a.proofC,
		a.g16Input0, a.g16Input1, a.g16Input2, a.g16Input3, a.g16Input4,
	)
}

// callUpgradeFull is the underlying helper used by callUpgrade and
// callUpgradeMultiSig. It builds a valid proof bundle for the next block,
// splices the migration hash into pv[240..272] (which Upgrade verifies),
// and invokes the contract.
func callUpgradeFull(c *RollupContract, sig1, sig2, sig3 runar.Sig, newScript runar.ByteString) {
	preStateRoot := string(c.StateRoot)
	newBlockNumber := int64(c.BlockNumber) + 1
	args := buildArgs(preStateRoot, newBlockNumber)

	// Splice the migration hash into pv[240..272] so Upgrade's hash check passes.
	pv := []byte(args.publicValues)
	migHash := rawHash256(string(newScript))
	copy(pv[240:272], []byte(migHash))
	args.publicValues = runar.ByteString(string(pv))

	c.Upgrade(
		sig1, sig2, sig3, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.proofFieldA, args.proofFieldB, args.proofFieldC,
		args.merkleLeaf, args.merkleProof, args.merkleIndex,
		args.proofA, args.proofBX0, args.proofBX1, args.proofBY0, args.proofBY1, args.proofC,
		args.g16Input0, args.g16Input1, args.g16Input2, args.g16Input3, args.g16Input4,
		args.newBlockNum,
	)
}

func callUpgrade(c *RollupContract, sig runar.Sig, newScript runar.ByteString) {
	callUpgradeFull(c, sig, runar.Sig(""), runar.Sig(""), newScript)
}

func callUpgradeMultiSig(c *RollupContract, sig1, sig2 runar.Sig, newScript runar.ByteString) {
	callUpgradeFull(c, sig1, sig2, runar.Sig(""), newScript)
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState happy paths
// ---------------------------------------------------------------------------

func TestRollup_InitialState(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	if c.BlockNumber != 0 {
		t.Errorf("expected block 0, got %d", c.BlockNumber)
	}
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestRollup_AdvanceState(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	callAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
	if string(c.StateRoot) != stateRootForBlock(1) {
		t.Error("state root not updated")
	}
}

func TestRollup_ChainAdvances(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	pre := zeros32()
	for i := int64(1); i <= 3; i++ {
		args := buildArgs(pre, i)
		callAdvance(c, args)
		pre = stateRootForBlock(int(i))
	}
	if c.BlockNumber != 3 {
		t.Errorf("expected block 3, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState rejection paths
// ---------------------------------------------------------------------------

func TestRollup_RejectWhenFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when frozen")
		}
	}()
	c := newRollup(zeros32(), 0, 1) // frozen
	callAdvance(c, buildArgs(zeros32(), 1))
}

func TestRollup_RejectWrongPreStateRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(rawSha256("not-zero"), 0, 0) // pre-state != args.preStateRoot
	args := buildArgs(zeros32(), 1)              // args were built assuming pre = zeros
	callAdvance(c, args)
}

func TestRollup_RejectBlockNumberGoingBackward(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 5, 0)
	args := buildArgs(zeros32(), 3) // newBlockNumber=3, expected 6
	callAdvance(c, args)
}

func TestRollup_RejectBlockNumberSkipping(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 2) // skip block 1
	callAdvance(c, args)
}

func TestRollup_RejectInvalidKoalaBearProof(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	args.proofFieldC = 99_999 // wrong product
	callAdvance(c, args)
}

func TestRollup_RejectInvalidMerkleProof(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	args.merkleLeaf = runar.ByteString(rawSha256("wrong-leaf"))
	callAdvance(c, args)
}

func TestRollup_RejectWrongBatchDataHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	// Replace batchData with garbage so Hash256(batchData) won't match pv[104..136].
	args.batchData = runar.ByteString(string(make([]byte, testBatchDataSize)))
	callAdvance(c, args)
}

func TestRollup_RejectWrongChainId(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	// Rebuild pv with chainId=999 — all other fields valid.
	newStateRoot := stateRootForBlock(1)
	badPV := buildPublicValues(zeros32(), newStateRoot,
		string(args.batchData), string(args.proofBlob), 999)
	args.publicValues = runar.ByteString(badPV)
	callAdvance(c, args)
}

func TestRollup_RejectPostStateRootMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	// Replace newStateRoot with garbage; pv still has the correct postStateRoot.
	args.newStateRoot = runar.ByteString(rawSha256("garbage"))
	callAdvance(c, args)
}

func TestRollup_RejectBadProofBlobHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	// Replace proofBlob — pv[64..96] no longer matches.
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callAdvance(c, args)
}

// ---------------------------------------------------------------------------
// Tests: governance — single_key
// ---------------------------------------------------------------------------

func TestRollup_Freeze(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	c.Freeze(runar.SignTestMessage(runar.Alice.PrivKey), "", "")
	if c.Frozen != 1 {
		t.Errorf("expected frozen=1, got %d", c.Frozen)
	}
}

func TestRollup_FreezeRejectsAlreadyFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 1)
	c.Freeze(runar.SignTestMessage(runar.Alice.PrivKey), "", "")
}

func TestRollup_Unfreeze(t *testing.T) {
	c := newRollup(zeros32(), 0, 1)
	c.Unfreeze(runar.SignTestMessage(runar.Alice.PrivKey), "", "")
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestRollup_UnfreezeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	c.Unfreeze(runar.SignTestMessage(runar.Alice.PrivKey), "", "")
}

func TestRollup_FreezeThenAdvanceRejectedThenUnfreezeThenAdvanceSucceeds(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)

	c.Freeze(sig, "", "")
	if c.Frozen != 1 {
		t.Fatal("not frozen")
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected advance to fail when frozen")
			}
		}()
		callAdvance(c, buildArgs(zeros32(), 1))
	}()

	c.Unfreeze(sig, "", "")
	if c.Frozen != 0 {
		t.Fatal("not unfrozen")
	}

	callAdvance(c, buildArgs(zeros32(), 1))
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestRollup_Upgrade(t *testing.T) {
	c := newRollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callUpgrade(c, sig, runar.ByteString("new_script"))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0 after upgrade, got %d", c.Frozen)
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestRollup_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callUpgrade(c, sig, runar.ByteString("new_script"))
}

// ---------------------------------------------------------------------------
// Tests: governance — none (mode 0)
// ---------------------------------------------------------------------------

func TestRollup_GovernanceNone_FreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Freeze")
		}
	}()
	c := newRollupNoGov(zeros32(), 0, 0)
	c.Freeze(runar.SignTestMessage(runar.Alice.PrivKey), "", "")
}

func TestRollup_GovernanceNone_UnfreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Unfreeze")
		}
	}()
	c := newRollupNoGov(zeros32(), 0, 1)
	c.Unfreeze(runar.SignTestMessage(runar.Alice.PrivKey), "", "")
}

func TestRollup_GovernanceNone_UpgradeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Upgrade")
		}
	}()
	c := newRollupNoGov(zeros32(), 0, 1)
	callUpgrade(c, runar.SignTestMessage(runar.Alice.PrivKey), runar.ByteString("new_script"))
}

func TestRollup_GovernanceNone_AdvanceStillWorks(t *testing.T) {
	c := newRollupNoGov(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	callAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance — multisig (2-of-2)
// ---------------------------------------------------------------------------

func TestRollup_MultiSig_FreezeAndUnfreeze(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newRollupMultiSig(zeros32(), 0, 0, keys, 2)

	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	c.Freeze(sigA, sigB, "")
	if c.Frozen != 1 {
		t.Errorf("expected frozen=1, got %d", c.Frozen)
	}

	c.Unfreeze(sigA, sigB, "")
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestRollup_MultiSig_FreezeRejectsInsufficientSigs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: insufficient signatures for 2-of-2")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newRollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	c.Freeze(sigA, "", "") // only 1 of 2 sigs
}

func TestRollup_MultiSig_UpgradeWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newRollupMultiSig(zeros32(), 0, 1, keys, 2) // already frozen

	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callUpgradeMultiSig(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestRollup_MultiSig_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: must be frozen to upgrade")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newRollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callUpgradeMultiSig(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestRollup_MultiSig_AdvanceStillWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newRollupMultiSig(zeros32(), 0, 0, keys, 2)
	args := buildArgs(zeros32(), 1)
	callAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}
