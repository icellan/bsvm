package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Helpers (shared between basefold and groth16 test files)
// ---------------------------------------------------------------------------

const kbP = 2_130_706_433 // KoalaBear field prime

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
// Proof blob and batch data generators (shared)
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
// Fixtures
// ---------------------------------------------------------------------------

var testMerkleLeaf string
var testMerkleProof string
var testMerkleRoot string

func init() {
	testMerkleLeaf = rawSha256("test-leaf")
	testMerkleProof, testMerkleRoot = buildDepth20Proof(testMerkleLeaf, leafIdx)
}

// ---------------------------------------------------------------------------
// Basefold contract constructors
// ---------------------------------------------------------------------------

// newBasefoldRollup builds a BasefoldRollupContract with single-key governance
// (Alice). Used for the bulk of state-transition and governance tests.
func newBasefoldRollup(stateRoot string, blockNumber, frozen int64) *BasefoldRollupContract {
	return &BasefoldRollupContract{
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

// newBasefoldRollupNoGov builds a contract with GovernanceMode=0 (no governance).
// Freeze/Unfreeze/Upgrade always fail because GovernanceKey is empty and
// CheckSig against an empty key always returns false.
func newBasefoldRollupNoGov(stateRoot string, blockNumber, frozen int64) *BasefoldRollupContract {
	c := newBasefoldRollup(stateRoot, blockNumber, frozen)
	c.GovernanceMode = 0
	c.GovernanceThreshold = 0
	c.GovernanceKey = runar.ByteString("")
	return c
}

// newBasefoldRollupMultiSig builds a contract with multisig governance.
// keys is the list of M-of-N pubkeys (max 3); threshold is M.
func newBasefoldRollupMultiSig(stateRoot string, blockNumber, frozen int64, keys []runar.TestKeyPair, threshold int64) *BasefoldRollupContract {
	c := newBasefoldRollup(stateRoot, blockNumber, frozen)
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
// AdvanceState argument bundle (basefold-only)
// ---------------------------------------------------------------------------

type basefoldAdvArgs struct {
	newStateRoot runar.ByteString
	newBlockNum  runar.Bigint
	publicValues runar.ByteString
	batchData    runar.ByteString
	proofBlob    runar.ByteString

	proofFieldA runar.Bigint
	proofFieldB runar.Bigint
	proofFieldC runar.Bigint
	merkleLeaf  runar.ByteString
	merkleProof runar.ByteString
	merkleIndex runar.Bigint
}

func buildBasefoldArgs(preStateRoot string, newBlockNumber int64) basefoldAdvArgs {
	newStateRoot := stateRootForBlock(int(newBlockNumber))
	batchData := generateBatchData(preStateRoot, newStateRoot, testBatchDataSize)
	proofBlob := generateProofBlob(byte(newBlockNumber), testProofBlobSize)
	pv := buildPublicValues(preStateRoot, newStateRoot, batchData, proofBlob, chainId)

	return basefoldAdvArgs{
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

func callBasefoldAdvance(c *BasefoldRollupContract, a basefoldAdvArgs) {
	c.AdvanceState(
		a.newStateRoot, a.newBlockNum, a.publicValues, a.batchData, a.proofBlob,
		a.proofFieldA, a.proofFieldB, a.proofFieldC,
		a.merkleLeaf, a.merkleProof, a.merkleIndex,
	)
}

// buildBasefoldUpgradeArgs builds a valid proof bundle for the next block and
// splices the migration hash into pv[240..272] (which Upgrade verifies).
func buildBasefoldUpgradeArgs(c *BasefoldRollupContract, newScript runar.ByteString) basefoldAdvArgs {
	preStateRoot := string(c.StateRoot)
	newBlockNumber := int64(c.BlockNumber) + 1
	args := buildBasefoldArgs(preStateRoot, newBlockNumber)

	// Splice the migration hash into pv[240..272] so Upgrade's hash check passes.
	pv := []byte(args.publicValues)
	migHash := rawHash256(string(newScript))
	copy(pv[240:272], []byte(migHash))
	args.publicValues = runar.ByteString(string(pv))
	return args
}

// callBasefoldUpgradeSingleKey invokes UpgradeSingleKey with a freshly built
// proof bundle. Used by the single-key governance tests.
func callBasefoldUpgradeSingleKey(c *BasefoldRollupContract, sig runar.Sig, newScript runar.ByteString) {
	args := buildBasefoldUpgradeArgs(c, newScript)
	c.UpgradeSingleKey(
		sig, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.proofFieldA, args.proofFieldB, args.proofFieldC,
		args.merkleLeaf, args.merkleProof, args.merkleIndex,
		args.newBlockNum,
	)
}

// callBasefoldUpgradeMultiSig2 invokes UpgradeMultiSig2 with a freshly built
// proof bundle. Used by the 2-of-3 multisig governance tests.
func callBasefoldUpgradeMultiSig2(c *BasefoldRollupContract, sig1, sig2 runar.Sig, newScript runar.ByteString) {
	args := buildBasefoldUpgradeArgs(c, newScript)
	c.UpgradeMultiSig2(
		sig1, sig2, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.proofFieldA, args.proofFieldB, args.proofFieldC,
		args.merkleLeaf, args.merkleProof, args.merkleIndex,
		args.newBlockNum,
	)
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState happy paths
// ---------------------------------------------------------------------------

func TestBasefoldRollup_InitialState(t *testing.T) {
	c := newBasefoldRollup(zeros32(), 0, 0)
	if c.BlockNumber != 0 {
		t.Errorf("expected block 0, got %d", c.BlockNumber)
	}
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestBasefoldRollup_AdvanceState(t *testing.T) {
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	callBasefoldAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
	if string(c.StateRoot) != stateRootForBlock(1) {
		t.Error("state root not updated")
	}
}

func TestBasefoldRollup_ChainAdvances(t *testing.T) {
	c := newBasefoldRollup(zeros32(), 0, 0)
	pre := zeros32()
	for i := int64(1); i <= 3; i++ {
		args := buildBasefoldArgs(pre, i)
		callBasefoldAdvance(c, args)
		pre = stateRootForBlock(int(i))
	}
	if c.BlockNumber != 3 {
		t.Errorf("expected block 3, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: AdvanceState rejection paths
// ---------------------------------------------------------------------------

func TestBasefoldRollup_RejectWhenFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when frozen")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 1) // frozen
	callBasefoldAdvance(c, buildBasefoldArgs(zeros32(), 1))
}

func TestBasefoldRollup_RejectWrongPreStateRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(rawSha256("not-zero"), 0, 0) // pre-state != args.preStateRoot
	args := buildBasefoldArgs(zeros32(), 1)             // args built assuming pre = zeros
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectBlockNumberGoingBackward(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 5, 0)
	args := buildBasefoldArgs(zeros32(), 3) // newBlockNumber=3, expected 6
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectBlockNumberSkipping(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 2) // skip block 1
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectInvalidKoalaBearProof(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	args.proofFieldC = 99_999 // wrong product
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectInvalidMerkleProof(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	args.merkleLeaf = runar.ByteString(rawSha256("wrong-leaf"))
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectWrongBatchDataHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	// Replace batchData with garbage so Hash256(batchData) won't match pv[104..136].
	args.batchData = runar.ByteString(string(make([]byte, testBatchDataSize)))
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectWrongChainId(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	// Rebuild pv with chainId=999 — all other fields valid.
	newStateRoot := stateRootForBlock(1)
	badPV := buildPublicValues(zeros32(), newStateRoot,
		string(args.batchData), string(args.proofBlob), 999)
	args.publicValues = runar.ByteString(badPV)
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectPostStateRootMismatch(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	// Replace newStateRoot with garbage; pv still has the correct postStateRoot.
	args.newStateRoot = runar.ByteString(rawSha256("garbage"))
	callBasefoldAdvance(c, args)
}

func TestBasefoldRollup_RejectBadProofBlobHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	// Replace proofBlob — pv[64..96] no longer matches.
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callBasefoldAdvance(c, args)
}

// ---------------------------------------------------------------------------
// Tests: governance — single_key
// ---------------------------------------------------------------------------

func TestBasefoldRollup_Freeze(t *testing.T) {
	c := newBasefoldRollup(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 1 {
		t.Errorf("expected frozen=1, got %d", c.Frozen)
	}
}

func TestBasefoldRollup_FreezeRejectsAlreadyFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 1)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestBasefoldRollup_Unfreeze(t *testing.T) {
	c := newBasefoldRollup(zeros32(), 0, 1)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0, got %d", c.Frozen)
	}
}

func TestBasefoldRollup_UnfreezeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestBasefoldRollup_FreezeThenAdvanceRejectedThenUnfreezeThenAdvanceSucceeds(t *testing.T) {
	c := newBasefoldRollup(zeros32(), 0, 0)
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
		callBasefoldAdvance(c, buildBasefoldArgs(zeros32(), 1))
	}()

	c.UnfreezeSingleKey(sig)
	if c.Frozen != 0 {
		t.Fatal("not unfrozen")
	}

	callBasefoldAdvance(c, buildBasefoldArgs(zeros32(), 1))
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestBasefoldRollup_Upgrade(t *testing.T) {
	c := newBasefoldRollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callBasefoldUpgradeSingleKey(c, sig, runar.ByteString("new_script"))
	if c.Frozen != 0 {
		t.Errorf("expected frozen=0 after upgrade, got %d", c.Frozen)
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestBasefoldRollup_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newBasefoldRollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	callBasefoldUpgradeSingleKey(c, sig, runar.ByteString("new_script"))
}

// ---------------------------------------------------------------------------
// Tests: governance — none (mode 0)
// ---------------------------------------------------------------------------

func TestBasefoldRollup_GovernanceNone_FreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Freeze")
		}
	}()
	// In mode 0, the single-key entry point must reject because the
	// GovernanceMode == 1 assertion fails before any signature check.
	c := newBasefoldRollupNoGov(zeros32(), 0, 0)
	c.FreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestBasefoldRollup_GovernanceNone_UnfreezeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Unfreeze")
		}
	}()
	c := newBasefoldRollupNoGov(zeros32(), 0, 1)
	c.UnfreezeSingleKey(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestBasefoldRollup_GovernanceNone_UpgradeRejects(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: GovernanceNone should reject Upgrade")
		}
	}()
	c := newBasefoldRollupNoGov(zeros32(), 0, 1)
	callBasefoldUpgradeSingleKey(c, runar.SignTestMessage(runar.Alice.PrivKey), runar.ByteString("new_script"))
}

func TestBasefoldRollup_GovernanceNone_AdvanceStillWorks(t *testing.T) {
	c := newBasefoldRollupNoGov(zeros32(), 0, 0)
	args := buildBasefoldArgs(zeros32(), 1)
	callBasefoldAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// Tests: governance — multisig (2-of-2)
// ---------------------------------------------------------------------------

func TestBasefoldRollup_MultiSig_FreezeAndUnfreeze(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newBasefoldRollupMultiSig(zeros32(), 0, 0, keys, 2)

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

func TestBasefoldRollup_MultiSig_FreezeRejectsInsufficientSigs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: insufficient signatures for 2-of-2")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newBasefoldRollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	// Pass an empty second sig — CheckMultiSig must reject 1-of-2 as insufficient.
	c.FreezeMultiSig2(sigA, runar.Sig(""))
}

func TestBasefoldRollup_MultiSig_UpgradeWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newBasefoldRollupMultiSig(zeros32(), 0, 1, keys, 2) // already frozen

	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callBasefoldUpgradeMultiSig2(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestBasefoldRollup_MultiSig_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure: must be frozen to upgrade")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newBasefoldRollupMultiSig(zeros32(), 0, 0, keys, 2)
	sigA := runar.SignTestMessage(runar.Alice.PrivKey)
	sigB := runar.SignTestMessage(runar.Bob.PrivKey)
	callBasefoldUpgradeMultiSig2(c, sigA, sigB, runar.ByteString("new_script"))
}

func TestBasefoldRollup_MultiSig_AdvanceStillWorks(t *testing.T) {
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newBasefoldRollupMultiSig(zeros32(), 0, 0, keys, 2)
	args := buildBasefoldArgs(zeros32(), 1)
	callBasefoldAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}
