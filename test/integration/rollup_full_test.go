//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Full-sized data generators
// ---------------------------------------------------------------------------

const (
	rollupContractPath = "pkg/covenant/contracts/rollup.runar.go"
	proofBlobSize      = 165_000 // ~165 KB SP1 STARK proof
	batchDataSize      = 20_000 // ~20 KB compressed batch
	merkleDepth        = 20     // FRI query depth
	merkleLeafIndex    = 7
)

func hexGenProofBlob(seed byte, size int) string {
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
	return hex.EncodeToString(data)
}

func hexGenBatchData(preStateRoot, newStateRoot string, size int) string {
	base, _ := hex.DecodeString(preStateRoot + newStateRoot)
	data := make([]byte, size)
	copy(data, base)
	h := sha256.Sum256(base)
	for i := len(base); i < size; i += 32 {
		end := i + 32
		if end > size {
			end = size
		}
		copy(data[i:end], h[:end-i])
		h = sha256.Sum256(h[:])
	}
	return hex.EncodeToString(data)
}

// buildHexDepth20Proof constructs a valid depth-20 Merkle proof without
// building the full 2^20 leaf tree — picks deterministic siblings.
func buildHexDepth20Proof(leafHex string, index int) (proofHex, rootHex string) {
	var siblings []string
	current := leafHex
	idx := index
	for d := 0; d < merkleDepth; d++ {
		sibling := hexSha256(hex.EncodeToString([]byte{byte(d), byte(idx ^ 1)}))
		siblings = append(siblings, sibling)
		if idx&1 == 0 {
			current = hexSha256(current + sibling)
		} else {
			current = hexSha256(sibling + current)
		}
		idx >>= 1
	}
	p := ""
	for _, s := range siblings {
		p += s
	}
	return p, current
}

func fullPVNum2binHexLE(v int64, size int) string {
	buf := make([]byte, size)
	binary.LittleEndian.PutUint64(buf, uint64(v))
	return hex.EncodeToString(buf[:size])
}

func buildFullPV(preStateRoot, postStateRoot, batchDataHex, proofBlobHex string, cid int64) string {
	z32 := hexZeros32()
	z8 := "0000000000000000"
	proofHash := hexHash256(proofBlobHex)
	batchDataHash := hexHash256(batchDataHex)
	chainIdBytes := fullPVNum2binHexLE(cid, 8)

	return preStateRoot + postStateRoot + proofHash + z8 +
		batchDataHash + chainIdBytes + z32 + z32 + z32 + z32
}

// Fixed Merkle root for the test (computed once from leaf at index 7)
var fullMerkleLeafHex string
var fullMerkleProofHex string
var fullMerkleRootHex string

func init() {
	fullMerkleLeafHex = hexSha256("00")
	fullMerkleProofHex, fullMerkleRootHex = buildHexDepth20Proof(fullMerkleLeafHex, merkleLeafIndex)
}

func buildFullArgs(preStateRoot string, newBlockNumber int64) []interface{} {
	newStateRoot := hexStateRoot(int(newBlockNumber))
	batchDataHex := hexGenBatchData(preStateRoot, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(byte(newBlockNumber), proofBlobSize)
	publicValues := buildFullPV(preStateRoot, newStateRoot, batchDataHex, proofBlobHex, chainID)

	proofA := int64(1000000)
	proofB := int64(2000000)
	proofC := bbMul(proofA, proofB)

	return []interface{}{
		newStateRoot,
		int64(newBlockNumber),
		publicValues,
		batchDataHex,
		proofBlobHex,
		proofA,
		proofB,
		proofC,
		fullMerkleLeafHex,
		fullMerkleProofHex,
		int64(merkleLeafIndex),
	}
}

func fullGetTxSize(t *testing.T, txid string) int {
	t.Helper()
	result, rpcErr := helpers.RPCCall("getrawtransaction", txid)
	if rpcErr != nil {
		t.Logf("warning: RPC error for %s: %v", txid, rpcErr)
		return 0
	}
	var h string
	if err := json.Unmarshal(result, &h); err != nil {
		t.Logf("warning: unmarshal error for %s: %v", txid, err)
		return 0
	}
	return len(h) / 2
}

func deployFullRollup(t *testing.T) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet) {
	t.Helper()

	artifact, err := compileContract(rollupContractPath)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("COMPILE: locking script = %d bytes", len(artifact.Script)/2)

	z32 := hexZeros32()

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false) //nolint:errcheck
	_, err = helpers.FundWallet(wallet, 5.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// Constructor: (stateRoot, blockNumber, frozen, verifyingKeyHash, chainId, governanceKey)
	contract := runar.NewRunarContract(artifact, []interface{}{
		z32,                    // genesis state root
		int64(0),               // block number
		int64(0),               // not frozen
		fullMerkleRootHex,      // verifying key hash = depth-20 Merkle root
		chainID,                // chain ID
		wallet.PubKeyHex(),     // governance key
	})

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	t.Logf("DEPLOY:  txid=%s", txid)

	return contract, provider, signer, wallet
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestRollupIntegration_FullLifecycle deploys the covenant and chains 10
// state advances with realistic-sized data (~165 KB proof, ~20 KB batch,
// depth-20 Merkle proofs). Measures TX sizes and timing.
func TestRollupIntegration_FullLifecycle(t *testing.T) {
	totalStart := time.Now()
	contract, provider, signer, _ := deployFullRollup(t)

	deployTxid := contract.GetCurrentUtxo().Txid
	deploySize := fullGetTxSize(t, deployTxid)
	t.Logf("DEPLOY:  size=%d bytes (%d KB)", deploySize, deploySize/1024)

	z32 := hexZeros32()
	pre := z32
	const numAdvances = 10
	var sizes []int
	var times []time.Duration

	for block := int64(1); block <= numAdvances; block++ {
		args := buildFullArgs(pre, block)
		start := time.Now()
		txid, _, err := contract.Call("advanceState", args, provider, signer, nil)
		dur := time.Since(start)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		txSize := fullGetTxSize(t, txid)
		sizes = append(sizes, txSize)
		times = append(times, dur)
		t.Logf("ADVANCE: block=%d  size=%d bytes (%d KB)  time=%s", block, txSize, txSize/1024, dur)
		pre = hexStateRoot(int(block))
	}

	totalDur := time.Since(totalStart)
	var totalSize int
	var totalTime time.Duration
	minS, maxS := sizes[0], sizes[0]
	for i, s := range sizes {
		totalSize += s
		totalTime += times[i]
		if s < minS {
			minS = s
		}
		if s > maxS {
			maxS = s
		}
	}

	t.Logf("")
	t.Logf("================================================================")
	t.Logf("FULL INTEGRATION RESULTS")
	t.Logf("================================================================")
	t.Logf("Proof blob:         %d KB", proofBlobSize/1024)
	t.Logf("Batch data:         %d KB", batchDataSize/1024)
	t.Logf("Merkle depth:       %d", merkleDepth)
	t.Logf("Deploy TX:          %d bytes", deploySize)
	t.Logf("Advances:           %d", numAdvances)
	t.Logf("Advance TX size:    avg=%d KB  min=%d KB  max=%d KB", totalSize/numAdvances/1024, minS/1024, maxS/1024)
	t.Logf("Advance time:       avg=%s  total=%s", totalTime/time.Duration(numAdvances), totalTime)
	t.Logf("Total time:         %s", totalDur)
	t.Logf("================================================================")
}

// TestRollupIntegration_RejectWrongPreStateRoot verifies on-chain rejection.
func TestRollupIntegration_RejectWrongPreStateRoot(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	args := buildFullArgs(z32, 1)
	pv := args[2].(string)
	args[2] = "ff" + pv[2:]
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupIntegration_RejectInvalidBabyBearProof verifies BB check on-chain.
func TestRollupIntegration_RejectInvalidBabyBearProof(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	args := buildFullArgs(z32, 1)
	args[7] = int64(99999) // wrong proofFieldC
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupIntegration_RejectSkippedBlockNumber verifies strict +1 on-chain.
func TestRollupIntegration_RejectSkippedBlockNumber(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	args := buildFullArgs(z32, 2) // skip block 1, go straight to 2
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for skipped block number")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupIntegration_RejectBadProofBlob verifies proof blob integrity on-chain.
func TestRollupIntegration_RejectBadProofBlob(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	args := buildFullArgs(z32, 1)
	args[4] = hexGenProofBlob(99, proofBlobSize) // wrong blob
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupIntegration_RejectWrongBatchData verifies batch data binding on-chain.
func TestRollupIntegration_RejectWrongBatchData(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	args := buildFullArgs(z32, 1)
	args[3] = hexGenBatchData("ff"+z32[2:], hexStateRoot(1), batchDataSize) // wrong data
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupIntegration_RejectWrongChainId verifies chain ID check on-chain.
func TestRollupIntegration_RejectWrongChainId(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	newStateRoot := hexStateRoot(1)
	batchDataHex := hexGenBatchData(z32, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(1, proofBlobSize)
	badPV := buildFullPV(z32, newStateRoot, batchDataHex, proofBlobHex, 999)
	args := buildFullArgs(z32, 1)
	args[2] = badPV
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupIntegration_LongChain runs 25 full-sized advances.
func TestRollupIntegration_LongChain(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	pre := z32
	const chainLen = 25

	start := time.Now()
	for block := int64(1); block <= chainLen; block++ {
		args := buildFullArgs(pre, block)
		_, _, err := contract.Call("advanceState", args, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		pre = hexStateRoot(int(block))
	}
	dur := time.Since(start)
	t.Logf("LONG CHAIN: %d full-sized advances in %s (avg %s/advance)", chainLen, dur, dur/time.Duration(chainLen))
}

// TestRollupIntegration_AdvanceAndRejectCycle alternates valid advances with
// invalid attempts to verify the covenant stays consistent.
func TestRollupIntegration_AdvanceAndRejectCycle(t *testing.T) {
	contract, provider, signer, _ := deployFullRollup(t)
	z32 := hexZeros32()
	pre := z32

	for block := int64(1); block <= 5; block++ {
		// Valid advance
		args := buildFullArgs(pre, block)
		txid, _, err := contract.Call("advanceState", args, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		t.Logf("block %d OK: %s (%d KB)", block, txid, fullGetTxSize(t, txid)/1024)
		pre = hexStateRoot(int(block))

		// Invalid: bad Baby Bear proof
		badArgs := buildFullArgs(pre, block+1)
		badArgs[7] = int64(12345)
		_, _, err = contract.Call("advanceState", badArgs, provider, signer, nil)
		if err == nil {
			t.Fatalf("block %d: expected rejection for bad proof", block+1)
		}

		// Invalid: bad proof blob
		badArgs2 := buildFullArgs(pre, block+1)
		badArgs2[4] = hexGenProofBlob(99, proofBlobSize)
		_, _, err = contract.Call("advanceState", badArgs2, provider, signer, nil)
		if err == nil {
			t.Fatalf("block %d: expected rejection for bad proof blob", block+1)
		}
	}
	t.Log("5 full-sized advances with 10 interleaved rejections: all correct")
}

// TestRollupIntegration_ScriptMetrics reports contract metrics.
func TestRollupIntegration_ScriptMetrics(t *testing.T) {
	artifact, err := compileContract(rollupContractPath)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	scriptBytes := len(artifact.Script) / 2
	asmOps := 1
	for _, ch := range artifact.ASM {
		if ch == ' ' {
			asmOps++
		}
	}

	t.Logf("Contract:           %s", artifact.ContractName)
	t.Logf("Locking script:     %d bytes", scriptBytes)
	t.Logf("ASM opcodes:        ~%d", asmOps)
	t.Logf("Methods:            %d public", len(artifact.ABI.Methods))
	for _, m := range artifact.ABI.Methods {
		if m.IsPublic {
			t.Logf("  %s(%d params)", m.Name, len(m.Params))
		}
	}
	t.Logf("State fields:       %d", len(artifact.StateFields))
	t.Logf("")
	t.Logf("Per-advance data sizes:")
	t.Logf("  Proof blob:       %d KB", proofBlobSize/1024)
	t.Logf("  Batch data:       %d KB", batchDataSize/1024)
	t.Logf("  Merkle proof:     %d bytes (depth %d)", merkleDepth*32, merkleDepth)
	t.Logf("  Public values:    272 bytes")
	t.Logf("  Expected TX:      ~%d KB", (proofBlobSize+batchDataSize+scriptBytes+2000)/1024)
}
