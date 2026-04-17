//go:build integration

package integration

import (
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Mode 3 (witness-assisted Groth16) rollup covenant regtest tests
// ---------------------------------------------------------------------------
//
// These tests exercise the Mode 3 rollup contract located at
// pkg/covenant/contracts/rollup_groth16_wa.runar.go against a BSV regtest
// node. The contract compiles to a ~700 KB locking script (vs 5.6 MB for
// Mode 2) by baking the SP1 Groth16 VK into a witness-assisted verifier
// preamble and shipping the BN254 witness bundle as a spend-time stack
// push via runar.CallOptions.Groth16WAWitness.
//
// Gate 0b's SP1 fixture (tests/sp1/) is reused for the baked-in VK and
// the per-advance witness: the same proof + public inputs are verified
// every block because the mock prover does not regenerate a different
// Groth16 proof per batch. The on-chain verifier only cares that the
// witness bundle is internally consistent with the baked VK.

// groth16WARollupContractPath points at the Mode 3 contract source file
// relative to the BSVM repo root.
const groth16WARollupContractPath = "pkg/covenant/contracts/rollup_groth16_wa.runar.go"

// gate0SP1FixturePath returns the absolute path to a file in tests/sp1/.
// Used to locate the SP1 vk.json / raw proof / public inputs fixtures at
// test time. Mirrors the locator in gate0_groth16_test.go but named to
// avoid colliding with that file.
func gate0SP1FixturePath(name string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "sp1", name)
}

// ---------------------------------------------------------------------------
// Witness cache — load once per package
// ---------------------------------------------------------------------------

var (
	groth16WAWitnessOnce sync.Once
	groth16WAWitness     *bn254witness.Witness
	groth16WAWitnessErr  error
)

// loadGate0Groth16WAWitness loads the canonical Gate 0b SP1 fixture once
// per package run and returns a BN254 witness bundle ready to pass as
// CallOptions.Groth16WAWitness. The witness is reused across every
// advance in a test — the on-chain verifier is stateless about the
// witness identity; it only checks the pairing product equals 1.
func loadGate0Groth16WAWitness(t *testing.T) *bn254witness.Witness {
	t.Helper()
	groth16WAWitnessOnce.Do(func() {
		vkPath := gate0SP1FixturePath("sp1_groth16_vk.json")
		vk, err := bn254witness.LoadSP1VKFromFile(vkPath)
		if err != nil {
			groth16WAWitnessErr = err
			return
		}

		rawProofHex, err := os.ReadFile(gate0SP1FixturePath("groth16_raw_proof.hex"))
		if err != nil {
			groth16WAWitnessErr = err
			return
		}
		proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawProofHex)))
		if err != nil {
			groth16WAWitnessErr = err
			return
		}

		pubInputs, err := bn254witness.LoadSP1PublicInputs(gate0SP1FixturePath("groth16_public_inputs.txt"))
		if err != nil {
			groth16WAWitnessErr = err
			return
		}

		witness, err := bn254witness.GenerateWitness(vk, proof, pubInputs)
		if err != nil {
			groth16WAWitnessErr = err
			return
		}
		groth16WAWitness = witness
	})
	if groth16WAWitnessErr != nil {
		t.Fatalf("loadGate0Groth16WAWitness: %v", groth16WAWitnessErr)
	}
	return groth16WAWitness
}

// ---------------------------------------------------------------------------
// Args builder — Mode 3 only needs 5 positional args
// ---------------------------------------------------------------------------

// buildGroth16WAAdvanceArgs produces the 5 positional arguments that the
// Mode 3 rollup contract's AdvanceState method expects:
//
//  1. newStateRoot    (ByteString, 32 bytes)
//  2. newBlockNumber  (Bigint, int64)
//  3. publicValues    (ByteString, 272 bytes)
//  4. batchData       (ByteString)
//  5. proofBlob       (ByteString)
//
// The witness bundle is NOT a positional argument — it is passed via
// runar.CallOptions.Groth16WAWitness when invoking contract.Call.
func buildGroth16WAAdvanceArgs(preStateRoot string, newBlockNumber int64) []interface{} {
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

// deployGroth16WARollupLifecycle compiles the Mode 3 rollup contract via the
// Rúnar Go pipeline with the Gate 0b SP1 vk.json baked into the witness-
// assisted Groth16 verifier preamble, funds a fresh regtest wallet, and
// deploys the covenant UTXO. Returns the Rúnar contract handle, the SDK
// provider, the SDK signer, and the funded wallet.
func deployGroth16WARollupLifecycle(t *testing.T) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet) {
	t.Helper()

	vkPath := gate0SP1FixturePath("sp1_groth16_vk.json")
	compileStart := time.Now()
	artifact, err := compileContractGroth16WA(groth16WARollupContractPath, vkPath)
	if err != nil {
		t.Fatalf("compile Groth16WA contract: %v", err)
	}
	compileDur := time.Since(compileStart)
	t.Logf("COMPILE: %s — locking script = %d bytes (%.1f KB) in %s",
		artifact.ContractName, len(artifact.Script)/2,
		float64(len(artifact.Script)/2)/1024.0, compileDur)
	t.Logf("         constructor params = %d", len(artifact.ABI.Constructor.Params))
	t.Logf("         state fields       = %d", len(artifact.StateFields))

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

	// The Mode 3 contract declares 3 mutable state fields plus 7 readonly
	// fields (10 constructor args total, in declaration order). No VK
	// readonly fields — the BN254 VK is baked by the preamble emitter.
	z32 := hexZeros32()
	z33 := "000000000000000000000000000000000000000000000000000000000000000000"

	constructorArgs := []interface{}{
		// Mutable state
		z32,      // stateRoot
		int64(0), // blockNumber
		int64(0), // frozen
		// Readonly: shared
		fullMerkleRootHex, // sP1VerifyingKeyHash — bsv-evm tracking hash
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
		t.Fatalf("deploy Groth16WA covenant: %v", err)
	}
	t.Logf("DEPLOY:  txid=%s", txid)

	return contract, provider, signer, wallet
}

// callGroth16WAAdvanceWithWitness invokes the AdvanceState method with
// the supplied args and the Gate 0b witness attached via
// runar.CallOptions.Groth16WAWitness.
func callGroth16WAAdvanceWithWitness(
	t *testing.T,
	contract *runar.RunarContract,
	provider runar.Provider,
	signer runar.Signer,
	args []interface{},
	witness *bn254witness.Witness,
) (string, time.Duration, error) {
	t.Helper()
	start := time.Now()
	txid, _, err := contract.Call("advanceState", args, provider, signer, &runar.CallOptions{
		Groth16WAWitness: witness,
	})
	return txid, time.Since(start), err
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRollupGroth16WA_FullLifecycle deploys the Mode 3 covenant and chains
// 3 state advances with the real Gate 0b SP1 fixture witness. Measures
// script size, deploy TX size, per-advance TX size, and per-advance
// duration. The per-advance should be dominated by the witness pairing
// verification (hundreds of ms vs Basefold's ~50 ms) because the BN254
// pairing check runs on every spend.
func TestRollupGroth16WA_FullLifecycle(t *testing.T) {
	totalStart := time.Now()
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)

	deployTxid := contract.GetCurrentUtxo().Txid
	deploySize := fullGetTxSize(t, deployTxid)
	t.Logf("DEPLOY:  size=%d bytes (%d KB)", deploySize, deploySize/1024)

	witness := loadGate0Groth16WAWitness(t)

	z32 := hexZeros32()
	pre := z32
	const numAdvances = 3
	var sizes []int
	var times []time.Duration

	for block := int64(1); block <= numAdvances; block++ {
		args := buildGroth16WAAdvanceArgs(pre, block)
		txid, dur, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, witness)
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
	t.Logf("MODE 3 (WITNESS-ASSISTED GROTH16) FULL INTEGRATION RESULTS")
	t.Logf("================================================================")
	t.Logf("Deploy TX:          %d bytes (%d KB)", deploySize, deploySize/1024)
	t.Logf("Advances:           %d", numAdvances)
	t.Logf("Advance TX size:    avg=%d KB  min=%d KB  max=%d KB",
		totalSize/numAdvances/1024, minS/1024, maxS/1024)
	t.Logf("Advance time:       avg=%s  total=%s", totalTime/time.Duration(numAdvances), totalTime)
	t.Logf("Total time:         %s", totalDur)
	t.Logf("================================================================")
}

// TestRollupGroth16WA_RejectTamperedWitness tampers with a Miller loop
// gradient on the witness bundle and asserts that the advance fails.
func TestRollupGroth16WA_RejectTamperedWitness(t *testing.T) {
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)

	// Make a SHALLOW copy of the witness and tamper only with a field we
	// own outright. The cached witness must remain pristine for other
	// subtests.
	pristine := loadGate0Groth16WAWitness(t)
	tampered := *pristine
	if len(tampered.MillerGradients) == 0 {
		t.Fatal("cached witness has no Miller gradients")
	}
	tamperedGradients := make([]*big.Int, len(pristine.MillerGradients))
	copy(tamperedGradients, pristine.MillerGradients)
	tamperedGradients[0] = new(big.Int).Add(pristine.MillerGradients[0], big.NewInt(1))
	tampered.MillerGradients = tamperedGradients

	z32 := hexZeros32()
	args := buildGroth16WAAdvanceArgs(z32, 1)
	_, _, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, &tampered)
	if err == nil {
		t.Fatal("SECURITY FAILURE: tampered witness was accepted")
	}
	t.Logf("correctly rejected tampered Miller gradient: %v", err)
}

// TestRollupGroth16WA_RejectWrongPreStateRoot verifies that an advance
// with a tampered pre-state root in the public values blob is rejected.
func TestRollupGroth16WA_RejectWrongPreStateRoot(t *testing.T) {
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)
	witness := loadGate0Groth16WAWitness(t)
	z32 := hexZeros32()
	args := buildGroth16WAAdvanceArgs(z32, 1)
	pv := args[2].(string)
	args[2] = "ff" + pv[2:] // flip leading byte of pre-state root
	_, _, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, witness)
	if err == nil {
		t.Fatal("expected rejection for wrong pre-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16WA_RejectSkippedBlockNumber verifies that advancing
// the block counter by more than +1 is rejected on-chain.
func TestRollupGroth16WA_RejectSkippedBlockNumber(t *testing.T) {
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)
	witness := loadGate0Groth16WAWitness(t)
	z32 := hexZeros32()
	args := buildGroth16WAAdvanceArgs(z32, 2) // skip block 1
	_, _, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, witness)
	if err == nil {
		t.Fatal("expected rejection for skipped block number")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16WA_RejectBadProofBlob verifies that a proof blob whose
// hash does not match the public-values proofBlobHash slot is rejected.
func TestRollupGroth16WA_RejectBadProofBlob(t *testing.T) {
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)
	witness := loadGate0Groth16WAWitness(t)
	z32 := hexZeros32()
	args := buildGroth16WAAdvanceArgs(z32, 1)
	args[4] = hexGenProofBlob(99, proofBlobSize)
	_, _, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, witness)
	if err == nil {
		t.Fatal("expected rejection for tampered proof blob")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16WA_RejectWrongChainID verifies that an advance whose
// public values encode a different chain ID is rejected on-chain.
func TestRollupGroth16WA_RejectWrongChainID(t *testing.T) {
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)
	witness := loadGate0Groth16WAWitness(t)
	z32 := hexZeros32()
	newStateRoot := hexStateRoot(1)
	batchDataHex := hexGenBatchData(z32, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(1, proofBlobSize)
	badPV := buildFullPV(z32, newStateRoot, batchDataHex, proofBlobHex, 999)
	args := buildGroth16WAAdvanceArgs(z32, 1)
	args[2] = badPV
	_, _, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, witness)
	if err == nil {
		t.Fatal("expected rejection for wrong chain ID")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16WA_RejectWrongPostStateRoot verifies that an advance
// whose newStateRoot arg disagrees with the public values post-state root
// is rejected on-chain.
func TestRollupGroth16WA_RejectWrongPostStateRoot(t *testing.T) {
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)
	z32 := hexZeros32()
	args := buildGroth16WAAdvanceArgs(z32, 1)
	args[0] = "ff" + args[0].(string)[2:]
	witness := loadGate0Groth16WAWitness(t)
	_, _, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, witness)
	if err == nil {
		t.Fatal("expected rejection for wrong post-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16WA_RejectBadBatchData verifies that replacing the batch
// data with a different blob is rejected on-chain.
func TestRollupGroth16WA_RejectBadBatchData(t *testing.T) {
	contract, provider, signer, _ := deployGroth16WARollupLifecycle(t)
	z32 := hexZeros32()
	args := buildGroth16WAAdvanceArgs(z32, 1)
	args[3] = hexGenBatchData("ff"+z32[2:], hexStateRoot(99), batchDataSize)
	witness := loadGate0Groth16WAWitness(t)
	_, _, err := callGroth16WAAdvanceWithWitness(t, contract, provider, signer, args, witness)
	if err == nil {
		t.Fatal("expected rejection for bad batch data")
	}
	t.Logf("correctly rejected: %v", err)
}
