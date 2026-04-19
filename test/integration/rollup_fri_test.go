//go:build integration

package integration

import (
	"testing"
	"time"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Mode 1 FRI rollup covenant regtest tests
// ---------------------------------------------------------------------------
//
// These tests exercise the Mode 1 trust-minimized FRI rollup contract at
// pkg/covenant/contracts/rollup_fri.runar.go against a BSV regtest node.
// The Mode 1 covenant does NOT verify the SP1 FRI proof on-chain — see
// rollup_fri.runar.go header and spec 12 "Verification modes" for the
// security model. The 5-arg advanceState ABI is substantially simpler
// than the prior dual-mode design.

// friRollupContractPath points at the Mode 1 FRI contract source file.
// Kept separate from rollupContractPath (fixtures.go) so the continuous-
// proving regtest fixture stays decoupled from the per-mode tests.
const friRollupContractPath = "pkg/covenant/contracts/rollup_fri.runar.go"

// ---------------------------------------------------------------------------
// AdvanceState argument builder
// ---------------------------------------------------------------------------

// buildFRIAdvanceArgs produces the 5 positional arguments that the Mode 1
// FRI rollup contract's AdvanceState method expects:
//
//  1. newStateRoot    (ByteString, 32 bytes)
//  2. newBlockNumber  (Bigint, int64)
//  3. publicValues    (ByteString, 272 bytes)
//  4. batchData       (ByteString)
//  5. proofBlob       (ByteString — not consumed on-chain under Mode 1)
func buildFRIAdvanceArgs(preStateRoot string, newBlockNumber int64) []interface{} {
	newStateRoot := hexStateRoot(int(newBlockNumber))
	batchDataHex := hexGenBatchData(preStateRoot, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(byte(newBlockNumber), proofBlobSize)
	publicValues := buildFullPV(preStateRoot, newStateRoot, batchDataHex, proofBlobHex, chainID)

	return []interface{}{
		newStateRoot,
		newBlockNumber,
		publicValues,
		batchDataHex,
		proofBlobHex,
	}
}

// ---------------------------------------------------------------------------
// Deploy helper
// ---------------------------------------------------------------------------

// deployFRIRollupLifecycle compiles the Mode 1 FRI rollup contract
// via the Rúnar Go pipeline, funds a fresh regtest wallet, and deploys the
// covenant UTXO. Returns the Rúnar contract handle, the SDK provider, the
// SDK signer and the funded wallet.
//
// The helper is deliberately named differently from the stale
// deployFRIRollup defined in continuous_proving_regtest_test.go so
// the two files compile side-by-side while the parallel broadcast-client
// rework lands. Once that rework catches up, the stale local helper can
// be removed in favour of this one.
func deployFRIRollupLifecycle(t *testing.T) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet) {
	t.Helper()

	artifact, err := compileContract(friRollupContractPath)
	if err != nil {
		t.Fatalf("compile Mode 1 FRI contract: %v", err)
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

	// FRIRollupContract declares 3 mutable state fields plus 7
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
		t.Fatalf("deploy FRI covenant: %v", err)
	}
	t.Logf("DEPLOY:  txid=%s", txid)

	return contract, provider, signer, wallet
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRollupFRI_FullLifecycle deploys the FRI covenant and
// chains 10 state advances with realistic-sized data (~165 KB proof,
// ~20 KB batch, depth-20 Merkle proofs). Measures TX sizes and timing.
//
// This is the empirical test for the OP_SPLIT bug: the old dual-mode
// contract was ~5.8 MB and reliably failed at deploy with
// `Invalid OP_SPLIT range`. If this test passes, the bug is gone for the
// Mode 1 (trust-minimized FRI) after the contract split.
func TestRollupFRI_FullLifecycle(t *testing.T) {
	totalStart := time.Now()
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)

	deployTxid := contract.GetCurrentUtxo().Txid
	deploySize := fullGetTxSize(t, deployTxid)
	t.Logf("DEPLOY:  size=%d bytes (%d KB)", deploySize, deploySize/1024)

	z32 := hexZeros32()
	pre := z32
	const numAdvances = 10
	var sizes []int
	var times []time.Duration

	for block := int64(1); block <= numAdvances; block++ {
		args := buildFRIAdvanceArgs(pre, block)
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
	t.Logf("MODE 1 FRI ROLLUP FULL INTEGRATION RESULTS")
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
	t.Logf("OP_SPLIT bug:       NOT REPRODUCED — Mode 1 FRI contract deploys and advances cleanly")
	t.Logf("================================================================")
}

// TestRollupFRI_RejectWrongPreStateRoot verifies that an advance with
// a tampered pre-state root in the public values blob is rejected
// on-chain.
func TestRollupFRI_RejectWrongPreStateRoot(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildFRIAdvanceArgs(z32, 1)
	pv := args[2].(string)
	args[2] = "ff" + pv[2:] // flip the leading byte of the pre-state root
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong pre-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupFRI_RejectSkippedBlockNumber verifies that advancing the
// block counter by more than +1 is rejected on-chain.
func TestRollupFRI_RejectSkippedBlockNumber(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildFRIAdvanceArgs(z32, 2) // skip block 1, jump to 2
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for skipped block number")
	}
	t.Logf("correctly rejected: %v", err)
}

// (Mode 1 does not consume or bind proofBlob on-chain — tampering with
// it is ACCEPTED by the covenant. Off-chain nodes detect the mismatch
// and trigger governance freeze; no on-chain rejection test applies.)

// TestRollupFRI_RejectWrongChainID verifies that an advance whose
// public values encode a different chain ID is rejected on-chain.
func TestRollupFRI_RejectWrongChainID(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	z32 := hexZeros32()
	newStateRoot := hexStateRoot(1)
	batchDataHex := hexGenBatchData(z32, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(1, proofBlobSize)
	badPV := buildFullPV(z32, newStateRoot, batchDataHex, proofBlobHex, 999)
	args := buildFRIAdvanceArgs(z32, 1)
	args[2] = badPV
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong chain ID")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupFRI_RejectWrongPostStateRoot verifies that an advance
// whose newStateRoot arg disagrees with the public values post-state root
// (PV[32:64]) is rejected on-chain.
func TestRollupFRI_RejectWrongPostStateRoot(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildFRIAdvanceArgs(z32, 1)
	// Swap newStateRoot (arg 0) so it no longer matches PV[32:64].
	args[0] = "ff" + args[0].(string)[2:]
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong post-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupFRI_RejectBadBatchData verifies that replacing the batch
// data with a different blob (so hash256(batchData) ≠ PV[104:136]) is
// rejected on-chain.
func TestRollupFRI_RejectBadBatchData(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	z32 := hexZeros32()
	args := buildFRIAdvanceArgs(z32, 1)
	// Replace batchData (arg 3) with a blob that has a different hash.
	args[3] = hexGenBatchData("ff"+z32[2:], hexStateRoot(99), batchDataSize)
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for bad batch data")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupFRI_LongChain runs 25 full-sized advances back-to-back
// to prove there is no state drift or stack leak across a long chain of
// FRI covenant advances.
func TestRollupFRI_LongChain(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	z32 := hexZeros32()
	pre := z32
	const chainLen = 25

	start := time.Now()
	for block := int64(1); block <= chainLen; block++ {
		args := buildFRIAdvanceArgs(pre, block)
		_, _, err := contract.Call("advanceState", args, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		pre = hexStateRoot(int(block))
	}
	dur := time.Since(start)
	t.Logf("LONG CHAIN: %d full-sized Mode 1 advances in %s (avg %s/advance)",
		chainLen, dur, dur/time.Duration(chainLen))
}
