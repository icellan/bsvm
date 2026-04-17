//go:build integration

package integration

import (
	"testing"
	"time"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Basefold rollup covenant regtest tests
// ---------------------------------------------------------------------------
//
// These tests exercise the split Basefold-only rollup contract located at
// pkg/covenant/contracts/rollup_basefold.runar.go against a BSV regtest
// node. The previous dual-mode rollup.runar.go compiled to ~5.8 MB and
// tripped the Rúnar `Invalid OP_SPLIT range` bug on deploy. The new
// Basefold variant compiles to ~2.4 KB (over 2000x smaller), and
// TestRollupBasefold_FullLifecycle is the empirical check for whether the
// OP_SPLIT bug was a function of contract size / dual-mode argument
// complexity. If it passes, the bug is gone for this mode.

// basefoldRollupContractPath points at the split Basefold contract source
// file. Kept separate from rollupContractPath (fixtures.go) so the
// continuous-proving regtest fixture stays decoupled from the Basefold
// per-mode tests.
const basefoldRollupContractPath = "pkg/covenant/contracts/rollup_basefold.runar.go"

// ---------------------------------------------------------------------------
// AdvanceState argument builder
// ---------------------------------------------------------------------------

// buildBasefoldAdvanceArgs produces the 11 positional arguments that the
// Basefold rollup contract's AdvanceState method expects:
//
//  1. newStateRoot    (ByteString, 32 bytes)
//  2. newBlockNumber  (Bigint, int64)
//  3. publicValues    (ByteString, 272 bytes)
//  4. batchData       (ByteString)
//  5. proofBlob       (ByteString)
//  6. proofFieldA     (Bigint, KoalaBear field element)
//  7. proofFieldB     (Bigint, KoalaBear field element)
//  8. proofFieldC     (Bigint, == kbMul(A, B))
//  9. merkleLeaf      (ByteString)
// 10. merkleProof     (ByteString, 20*32 bytes)
// 11. merkleIndex     (Bigint, int64)
//
// The proof field product is evaluated modulo the KoalaBear field prime
// (kbP) to match the runar.KbFieldMul primitive invoked on-chain.
func buildBasefoldAdvanceArgs(preStateRoot string, newBlockNumber int64) []interface{} {
	newStateRoot := hexStateRoot(int(newBlockNumber))
	batchDataHex := hexGenBatchData(preStateRoot, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(byte(newBlockNumber), proofBlobSize)
	publicValues := buildFullPV(preStateRoot, newStateRoot, batchDataHex, proofBlobHex, chainID)

	proofA := int64(1_000_000)
	proofB := int64(2_000_000)
	proofC := kbMul(proofA, proofB)

	return []interface{}{
		newStateRoot,
		newBlockNumber,
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

// ---------------------------------------------------------------------------
// Deploy helper
// ---------------------------------------------------------------------------

// deployBasefoldRollupLifecycle compiles the Basefold-only rollup contract
// via the Rúnar Go pipeline, funds a fresh regtest wallet, and deploys the
// covenant UTXO. Returns the Rúnar contract handle, the SDK provider, the
// SDK signer and the funded wallet.
//
// The helper is deliberately named differently from the stale
// deployBasefoldRollup defined in continuous_proving_regtest_test.go so
// the two files compile side-by-side while the parallel broadcast-client
// rework lands. Once that rework catches up, the stale local helper can
// be removed in favour of this one.
func deployBasefoldRollupLifecycle(t *testing.T) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet) {
	t.Helper()

	artifact, err := compileContract(basefoldRollupContractPath)
	if err != nil {
		t.Fatalf("compile Basefold contract: %v", err)
	}
	t.Logf("COMPILE: %s — locking script = %d bytes (%.1f KB)",
		artifact.ContractName, len(artifact.Script)/2, float64(len(artifact.Script)/2)/1024.0)
	t.Logf("         constructor params = %d", len(artifact.ABI.Constructor.Params))
	t.Logf("         state fields       = %d", len(artifact.StateFields))

	// Fund a fresh wallet for deployment and subsequent contract calls.
	wallet := helpers.NewWallet()
	_, _ = helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 5.0); err != nil {
		t.Fatalf("fund wallet: %v", err)
	}
	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	// BasefoldRollupContract declares 3 mutable state fields plus 7
	// readonly fields (10 constructor args total, in declaration order):
	//   0  stateRoot              (ByteString, 32 bytes)
	//   1  blockNumber            (Bigint)
	//   2  frozen                 (Bigint)
	//   3  sP1VerifyingKeyHash    (ByteString, = Merkle root)
	//   4  chainId                (Bigint)
	//   5  governanceMode         (Bigint, 0=none,1=single_key,2=multisig)
	//   6  governanceThreshold    (Bigint)
	//   7  governanceKey          (PubKey, 33-byte compressed hex)
	//   8  governanceKey2         (PubKey, unused here, 33 zeros)
	//   9  governanceKey3         (PubKey, unused here, 33 zeros)
	z32 := hexZeros32()
	z33 := "000000000000000000000000000000000000000000000000000000000000000000"

	constructorArgs := []interface{}{
		// Mutable state
		z32,      // stateRoot
		int64(0), // blockNumber
		int64(0), // frozen
		// Readonly: shared
		fullMerkleRootHex, // sP1VerifyingKeyHash = depth-20 Merkle root
		chainID,           // chainId
		// Readonly: governance
		int64(1),           // governanceMode = 1 (single_key)
		int64(1),           // governanceThreshold = 1
		wallet.PubKeyHex(), // governanceKey
		z33,                // governanceKey2 (unused)
		z33,                // governanceKey3 (unused)
	}

	contract := runar.NewRunarContract(artifact, constructorArgs)

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100_000})
	if err != nil {
		t.Fatalf("deploy Basefold covenant: %v", err)
	}
	t.Logf("DEPLOY:  txid=%s", txid)

	return contract, provider, signer, wallet
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRollupBasefold_FullLifecycle deploys the Basefold covenant and
// chains 10 state advances with realistic-sized data (~165 KB proof,
// ~20 KB batch, depth-20 Merkle proofs). Measures TX sizes and timing.
//
// This is the empirical test for the OP_SPLIT bug: the old dual-mode
// contract was ~5.8 MB and reliably failed at deploy with
// `Invalid OP_SPLIT range`. If this test passes, the bug is gone for the
// Basefold mode after the contract split.
func TestRollupBasefold_FullLifecycle(t *testing.T) {
	totalStart := time.Now()
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)

	deployTxid := contract.GetCurrentUtxo().Txid
	deploySize := fullGetTxSize(t, deployTxid)
	t.Logf("DEPLOY:  size=%d bytes (%d KB)", deploySize, deploySize/1024)

	z32 := hexZeros32()
	pre := z32
	const numAdvances = 10
	var sizes []int
	var times []time.Duration

	for block := int64(1); block <= numAdvances; block++ {
		args := buildBasefoldAdvanceArgs(pre, block)
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
	t.Logf("BASEFOLD ROLLUP FULL INTEGRATION RESULTS")
	t.Logf("================================================================")
	t.Logf("Proof blob:         %d KB", proofBlobSize/1024)
	t.Logf("Batch data:         %d KB", batchDataSize/1024)
	t.Logf("Merkle depth:       %d", merkleDepth)
	t.Logf("Deploy TX:          %d bytes", deploySize)
	t.Logf("Advances:           %d", numAdvances)
	t.Logf("Advance TX size:    avg=%d KB  min=%d KB  max=%d KB",
		totalSize/numAdvances/1024, minS/1024, maxS/1024)
	t.Logf("Advance time:       avg=%s  total=%s", totalTime/time.Duration(numAdvances), totalTime)
	t.Logf("Total time:         %s", totalDur)
	t.Logf("OP_SPLIT bug:       NOT REPRODUCED — Basefold contract deploys and advances cleanly")
	t.Logf("================================================================")
}

// TestRollupBasefold_RejectWrongPreStateRoot verifies that an advance with
// a tampered pre-state root in the public values blob is rejected
// on-chain.
func TestRollupBasefold_RejectWrongPreStateRoot(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildBasefoldAdvanceArgs(z32, 1)
	pv := args[2].(string)
	args[2] = "ff" + pv[2:] // flip the leading byte of the pre-state root
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong pre-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupBasefold_RejectInvalidProofField verifies that an invalid
// KoalaBear field product is rejected by the on-chain
// runar.KbFieldMul(A, B) == C check.
func TestRollupBasefold_RejectInvalidProofField(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildBasefoldAdvanceArgs(z32, 1)
	// Swap proofFieldC for a value that is NOT kbMul(proofFieldA, proofFieldB).
	args[7] = int64(99_999)
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for invalid KoalaBear field product")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupBasefold_RejectSkippedBlockNumber verifies that advancing the
// block counter by more than +1 is rejected on-chain.
func TestRollupBasefold_RejectSkippedBlockNumber(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildBasefoldAdvanceArgs(z32, 2) // skip block 1, jump to 2
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for skipped block number")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupBasefold_RejectBadProofBlob verifies that a proof blob whose
// hash does not match the public-values proofBlobHash slot is rejected.
func TestRollupBasefold_RejectBadProofBlob(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildBasefoldAdvanceArgs(z32, 1)
	// Replace the proof blob with a blob generated from a different seed
	// so its hash no longer matches the one baked into publicValues.
	args[4] = hexGenProofBlob(99, proofBlobSize)
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for tampered proof blob")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupBasefold_RejectWrongChainID verifies that an advance whose
// public values encode a different chain ID is rejected on-chain.
func TestRollupBasefold_RejectWrongChainID(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	newStateRoot := hexStateRoot(1)
	batchDataHex := hexGenBatchData(z32, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(1, proofBlobSize)
	badPV := buildFullPV(z32, newStateRoot, batchDataHex, proofBlobHex, 999)
	args := buildBasefoldAdvanceArgs(z32, 1)
	args[2] = badPV
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong chain ID")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupBasefold_RejectWrongPostStateRoot verifies that an advance
// whose newStateRoot arg disagrees with the public values post-state root
// (PV[32:64]) is rejected on-chain.
func TestRollupBasefold_RejectWrongPostStateRoot(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildBasefoldAdvanceArgs(z32, 1)
	// Swap newStateRoot (arg 0) so it no longer matches PV[32:64].
	args[0] = "ff" + args[0].(string)[2:]
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong post-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupBasefold_RejectBadBatchData verifies that replacing the batch
// data with a different blob (so hash256(batchData) ≠ PV[104:136]) is
// rejected on-chain.
func TestRollupBasefold_RejectBadBatchData(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildBasefoldAdvanceArgs(z32, 1)
	// Replace batchData (arg 3) with a blob that has a different hash.
	args[3] = hexGenBatchData("ff"+z32[2:], hexStateRoot(99), batchDataSize)
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for bad batch data")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupBasefold_LongChain runs 25 full-sized advances back-to-back
// to prove there is no state drift or stack leak across a long chain of
// Basefold covenant advances.
func TestRollupBasefold_LongChain(t *testing.T) {
	contract, provider, signer, _ := deployBasefoldRollupLifecycle(t)
	z32 := hexZeros32()
	pre := z32
	const chainLen = 25

	start := time.Now()
	for block := int64(1); block <= chainLen; block++ {
		args := buildBasefoldAdvanceArgs(pre, block)
		_, _, err := contract.Call("advanceState", args, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		pre = hexStateRoot(int(block))
	}
	dur := time.Since(start)
	t.Logf("LONG CHAIN: %d full-sized Basefold advances in %s (avg %s/advance)",
		chainLen, dur, dur/time.Duration(chainLen))
}
