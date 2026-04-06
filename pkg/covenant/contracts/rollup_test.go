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

const bbP = 2013265921

func bbMul(a, b int64) int64 { return (a * b) % bbP }

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

func newRollup(stateRoot string, blockNumber, frozen int64) *RollupContract {
	return &RollupContract{
		StateRoot:        runar.ByteString(stateRoot),
		BlockNumber:      blockNumber,
		Frozen:           frozen,
		VerifyingKeyHash: runar.ByteString(testMerkleRoot),
		ChainId:          chainId,
		GovernanceKey:    runar.Alice.PubKey,
	}
}

type advArgs struct {
	newStateRoot runar.ByteString
	newBlockNum  runar.Bigint
	publicValues runar.ByteString
	batchData    runar.ByteString
	proofBlob    runar.ByteString
	proofFieldA  runar.Bigint
	proofFieldB  runar.Bigint
	proofFieldC  runar.Bigint
	merkleLeaf   runar.ByteString
	merkleProof  runar.ByteString
	merkleIndex  runar.Bigint
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
		proofFieldA:  1000000,
		proofFieldB:  2000000,
		proofFieldC:  bbMul(1000000, 2000000),
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
	)
}

// ---------------------------------------------------------------------------
// Tests: advanceState
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
	if string(c.StateRoot) != string(args.newStateRoot) {
		t.Error("state root not updated")
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", c.BlockNumber)
	}
}

func TestRollup_ChainAdvances(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	pre := zeros32()
	for block := int64(1); block <= 3; block++ {
		args := buildArgs(pre, block)
		callAdvance(c, args)
		if c.BlockNumber != block {
			t.Errorf("expected block %d, got %d", block, c.BlockNumber)
		}
		pre = string(args.newStateRoot)
	}
}

func TestRollup_RejectWhenFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when frozen")
		}
	}()
	c := newRollup(zeros32(), 0, 1)
	callAdvance(c, buildArgs(zeros32(), 1))
}

func TestRollup_RejectWrongPreStateRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	bad := make([]byte, 32)
	bad[0] = 0xff
	args.publicValues = runar.ByteString(string(bad)) + args.publicValues[32:]
	callAdvance(c, args)
}

func TestRollup_RejectBlockNumberGoingBackward(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 5, 0)
	callAdvance(c, buildArgs(zeros32(), 3))
}

func TestRollup_RejectBlockNumberSkipping(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for skipped block number")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 2) // skip block 1, go straight to 2
	callAdvance(c, args)
}

func TestRollup_RejectInvalidBabyBearProof(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	args.proofFieldC = 99999
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
	bad := make([]byte, 32)
	bad[0] = 0xaa
	args.merkleLeaf = runar.ByteString(bad)
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
	newStateRoot := stateRootForBlock(1)
	batchData := generateBatchData(zeros32(), newStateRoot, testBatchDataSize)
	proofBlob := generateProofBlob(1, testProofBlobSize)
	badPV := buildPublicValues(zeros32(), newStateRoot, batchData, proofBlob, 999)
	args := buildArgs(zeros32(), 1)
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
	bad := make([]byte, 32)
	bad[0] = 0xdd
	args.newStateRoot = runar.ByteString(bad)
	callAdvance(c, args)
}

func TestRollup_RejectBadProofBlob(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	args := buildArgs(zeros32(), 1)
	args.proofBlob = runar.ByteString(generateProofBlob(99, testProofBlobSize))
	callAdvance(c, args)
}

// ---------------------------------------------------------------------------
// Tests: governance
// ---------------------------------------------------------------------------

func TestRollup_Freeze(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	c.Freeze(runar.SignTestMessage(runar.Alice.PrivKey))
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
	c.Freeze(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestRollup_Unfreeze(t *testing.T) {
	c := newRollup(zeros32(), 0, 1)
	c.Unfreeze(runar.SignTestMessage(runar.Alice.PrivKey))
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
	c.Unfreeze(runar.SignTestMessage(runar.Alice.PrivKey))
}

func TestRollup_FreezeThenAdvanceRejectedThenUnfreezeThenAdvanceSucceeds(t *testing.T) {
	c := newRollup(zeros32(), 0, 0)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)

	c.Freeze(sig)
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

	c.Unfreeze(sig)
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
	c.Upgrade(runar.SignTestMessage(runar.Alice.PrivKey), runar.ByteString("new_script"))
}

func TestRollup_UpgradeRejectsNotFrozen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newRollup(zeros32(), 0, 0)
	c.Upgrade(runar.SignTestMessage(runar.Alice.PrivKey), runar.ByteString("new_script"))
}

func TestRollup_Compile(t *testing.T) {
	if err := runar.CompileCheck("rollup.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
