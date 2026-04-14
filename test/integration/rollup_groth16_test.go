//go:build integration

package integration

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"runar-integration/helpers"

	"github.com/icellan/bsvm/pkg/covenant"
	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Groth16 rollup covenant regtest tests (Mode 2 — generic BN254 pairing)
// ---------------------------------------------------------------------------
//
// These tests exercise the split Groth16-only rollup contract located at
// pkg/covenant/contracts/rollup_groth16.runar.go against a BSV regtest
// node. The contract compiles to ~5.6 MB (a huge locking script) because
// it bakes in all 19 Groth16 BN254 verification-key components and
// inlines the multi-pairing verifier via the generic Bn254G1*/Bn254Multi*
// primitives.
//
// Unlike Mode 3 (witness-assisted Groth16) the Mode 2 pairing is computed
// entirely on-chain with no prover-supplied gradient witnesses, so the
// contract's OP_VERIFY against Bn254MultiPairing4 only passes when the
// supplied VK components + proof points actually satisfy the Groth16
// equation. The tests therefore deploy the contract with the REAL Gate
// 0b SP1 Groth16 verification key (sign-adjusted for the Mode 2 contract
// convention — see pkg/covenant/LoadSP1Groth16VK) and invoke AdvanceState
// with the REAL SP1 proof points and public inputs.
//
// The public-values blob, batch data and proof blob are still synthetic —
// the contract only binds them via hash256 offsets in the public values,
// which do not affect the pairing check. The first advance starts from
// stateRoot = zero (set at deploy) and increments block-by-block.

// groth16RollupContractPath points at the split Groth16 contract source.
const groth16RollupContractPath = "pkg/covenant/contracts/rollup_groth16.runar.go"

// ---------------------------------------------------------------------------
// Gate 0b SP1 Groth16 fixture loader (Mode 2 form — no witness generator)
// ---------------------------------------------------------------------------

var (
	gate0Groth16GenericOnce     sync.Once
	gate0Groth16GenericVK       *covenant.Groth16VK
	gate0Groth16GenericProof    bn254witness.Proof
	gate0Groth16GenericInputs   covenant.Mode2AdjustedPublicInputs
	gate0Groth16GenericRawInputs []*big.Int
	gate0Groth16GenericLoadErr  error
)

// loadGate0Groth16Generic loads the canonical Gate 0b SP1 Groth16 fixture
// in the form Mode 2 needs:
//
//   - A *covenant.Groth16VK with VK constants ready for
//     CompileGroth16Rollup / buildGroth16ConstructorArgs. Both the sign
//     convention (β pre-negated, γ/δ positive) and the IC0 zero-input
//     workaround are applied by this loader.
//   - The raw proof decomposed into A (G1), B (G2, Fp2), C (G1) — still
//     as *big.Int coordinates so the Mode 2 AdvanceState args can carry
//     them with 254-bit precision.
//   - The 5 adjusted SP1 public inputs (zeros replaced with 1, matching
//     the IC0 adjustment) as *big.Int for the IC linearization.
//
// The zero-input workaround compensates for a Rúnar codegen limitation:
// bn254G1AffineAdd / EmitBN254G1ScalarMul do not special-case BN254 G1
// identity points, so adding IC·0 to the MSM accumulator blows up at
// runtime. See covenant.ApplyZeroInputWorkaround for the derivation.
//
// Results are cached across tests so fixture parsing only runs once.
func loadGate0Groth16Generic(t *testing.T) (*covenant.Groth16VK, bn254witness.Proof, covenant.Mode2AdjustedPublicInputs) {
	t.Helper()
	gate0Groth16GenericOnce.Do(func() {
		vkPath := gate0SP1FixturePath("sp1_groth16_vk.json")
		rawVK, err := covenant.LoadSP1Groth16VK(vkPath)
		if err != nil {
			gate0Groth16GenericLoadErr = err
			return
		}

		rawProofHex, err := os.ReadFile(gate0SP1FixturePath("groth16_raw_proof.hex"))
		if err != nil {
			gate0Groth16GenericLoadErr = err
			return
		}
		proof, err := bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawProofHex)))
		if err != nil {
			gate0Groth16GenericLoadErr = err
			return
		}
		gate0Groth16GenericProof = proof

		rawInputs, err := bn254witness.LoadSP1PublicInputs(gate0SP1FixturePath("groth16_public_inputs.txt"))
		if err != nil {
			gate0Groth16GenericLoadErr = err
			return
		}
		if len(rawInputs) != covenant.Mode2PublicInputCount {
			gate0Groth16GenericLoadErr = errSP1PublicInputCount(len(rawInputs))
			return
		}
		gate0Groth16GenericRawInputs = rawInputs

		adjVK, adjInputs, err := covenant.ApplyZeroInputWorkaround(rawVK, rawInputs)
		if err != nil {
			gate0Groth16GenericLoadErr = err
			return
		}
		gate0Groth16GenericVK = adjVK
		gate0Groth16GenericInputs = adjInputs
	})
	if gate0Groth16GenericLoadErr != nil {
		t.Fatalf("loadGate0Groth16Generic: %v", gate0Groth16GenericLoadErr)
	}
	return gate0Groth16GenericVK, gate0Groth16GenericProof, gate0Groth16GenericInputs
}

type errSP1PublicInputCount int

func (e errSP1PublicInputCount) Error() string {
	return "unexpected SP1 public input count (want 5)"
}

// ---------------------------------------------------------------------------
// AdvanceState argument builder
// ---------------------------------------------------------------------------

// buildGroth16AdvanceArgs produces the 16 positional arguments that the
// Groth16 rollup contract's AdvanceState method expects:
//
//  1. newStateRoot    (ByteString, 32 bytes hex)
//  2. newBlockNumber  (Bigint, int64)
//  3. publicValues    (ByteString, 272 bytes hex)
//  4. batchData       (ByteString hex)
//  5. proofBlob       (ByteString hex)
//  6. proofA          (Point, 64-byte G1 = X || Y hex)
//  7. proofBX0        (*big.Int)
//  8. proofBX1        (*big.Int)
//  9. proofBY0        (*big.Int)
// 10. proofBY1        (*big.Int)
// 11. proofC          (Point, 64-byte G1 hex)
// 12. g16Input0       (*big.Int)
// 13. g16Input1       (*big.Int)
// 14. g16Input2       (*big.Int)
// 15. g16Input3       (*big.Int)
// 16. g16Input4       (*big.Int)
//
// The BN254 points come from the Gate 0b SP1 fixture. The public inputs
// are the ADJUSTED vector from covenant.ApplyZeroInputWorkaround (zeros
// replaced with 1) so the Rúnar codegen never hits its identity-point
// Add blind spot. The IC0 baked into the deployed contract has already
// been adjusted to match, so the on-chain MSM recovers the correct
// prepared_inputs despite the substitution. See the loader doc comment.
//
// Passing *big.Int for the Bigint parameters is critical — the Rúnar SDK
// dispatches on type and uses encodeBigIntScriptNumber to emit a
// full-width (254-bit) Bitcoin Script number push. int64 placeholders
// would silently truncate and wreck the pairing.
func buildGroth16AdvanceArgs(preStateRoot string, newBlockNumber int64, proof bn254witness.Proof, pubInputs covenant.Mode2AdjustedPublicInputs) []interface{} {
	newStateRoot := hexStateRoot(int(newBlockNumber))
	batchDataHex := hexGenBatchData(preStateRoot, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(byte(newBlockNumber), proofBlobSize)
	publicValues := buildFullPV(preStateRoot, newStateRoot, batchDataHex, proofBlobHex, chainID)

	proofAHex := bn254PointHex(proof.A[0], proof.A[1])
	proofCHex := bn254PointHex(proof.C[0], proof.C[1])

	return []interface{}{
		newStateRoot,
		newBlockNumber,
		publicValues,
		batchDataHex,
		proofBlobHex,
		proofAHex,
		// proofB is a G2 point in Rúnar (real, imag) order: (x0, x1, y0, y1).
		new(big.Int).Set(proof.B[0]), // proofBX0
		new(big.Int).Set(proof.B[1]), // proofBX1
		new(big.Int).Set(proof.B[2]), // proofBY0
		new(big.Int).Set(proof.B[3]), // proofBY1
		proofCHex,
		// 5 ADJUSTED public inputs for IC linearization.
		new(big.Int).Set(pubInputs[0]),
		new(big.Int).Set(pubInputs[1]),
		new(big.Int).Set(pubInputs[2]),
		new(big.Int).Set(pubInputs[3]),
		new(big.Int).Set(pubInputs[4]),
	}
}

// bn254PointHex packs a BN254 G1 affine point into a 128-char hex string
// (32-byte big-endian X followed by 32-byte big-endian Y), matching the
// runar.Point ByteString format that the compiled contract reads for
// proofA / proofC arguments.
func bn254PointHex(x, y *big.Int) string {
	return hex.EncodeToString(paddedFp(x)) + hex.EncodeToString(paddedFp(y))
}

// paddedFp left-zero-pads a big.Int to 32 bytes big-endian.
func paddedFp(v *big.Int) []byte {
	out := make([]byte, 32)
	if v == nil {
		return out
	}
	b := v.Bytes()
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out
}

// ---------------------------------------------------------------------------
// Deploy helper
// ---------------------------------------------------------------------------

// deployGroth16Rollup compiles the Groth16-only rollup contract via the
// Rúnar Go pipeline with the Gate 0b SP1 Groth16 VK baked into the 19
// readonly VK constructor-arg slots, funds a fresh regtest wallet, and
// deploys the covenant UTXO. Returns the contract handle, provider,
// signer and wallet.
//
// The VK is converted from SP1's fixture format (β/γ/δ pre-negated) to
// Mode 2's on-chain convention (β pre-negated, γ/δ positive) by
// covenant.LoadSP1Groth16VK. The initial stateRoot is z32 so the first
// advance's preStateRoot check passes against the buildFullPV output
// whose preStateRoot is z32 on block 1.
func deployGroth16Rollup(t *testing.T) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet, error) {
	t.Helper()

	vk, _, _ := loadGate0Groth16Generic(t)

	artifact, err := compileContract(groth16RollupContractPath)
	if err != nil {
		t.Fatalf("compile Groth16 contract: %v", err)
	}
	t.Logf("COMPILE: %s — locking script = %d bytes (%.2f MB)",
		artifact.ContractName, len(artifact.Script)/2, float64(len(artifact.Script)/2)/(1024.0*1024.0))
	t.Logf("         constructor params = %d", len(artifact.ABI.Constructor.Params))
	t.Logf("         state fields       = %d", len(artifact.StateFields))

	wallet := helpers.NewWallet()
	_, _ = helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 10.0); err != nil {
		t.Fatalf("fund wallet: %v", err)
	}
	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	z32 := hexZeros32()
	z33 := "000000000000000000000000000000000000000000000000000000000000000000"

	// Groth16RollupContract declares (in source order):
	//   3 state:       stateRoot, blockNumber, frozen
	//   2 shared:      sP1VerifyingKeyHash, chainId
	//   5 governance:  governanceMode, threshold, key, key2, key3
	//  19 VK:          alphaG1, betaG2X0..Y1 (4), gammaG2X0..Y1 (4),
	//                  deltaG2X0..Y1 (4), iC0..iC5 (6)
	// = 29 constructor args in declaration order.
	//
	// Point-typed fields (alphaG1, iC0..iC5) are passed as hex strings so
	// the compiler emits a 64-byte ByteString push. Bigint-typed Fp2
	// coordinates (betaG2*, gammaG2*, deltaG2*) are passed as *big.Int so
	// the compiler emits a full-width Bitcoin Script number push. Passing
	// them as hex strings silently compiles but pushes 32-byte big-endian
	// blobs — the BN254 runtime reads these as corrupted LE-SM script
	// numbers and the pairing check fails.
	constructorArgs := []interface{}{
		// Mutable state
		z32,      // stateRoot
		int64(0), // blockNumber
		int64(0), // frozen
		// Readonly: shared
		fullMerkleRootHex, // sP1VerifyingKeyHash
		chainID,           // chainId
		// Readonly: governance
		int64(1),           // governanceMode = single_key
		int64(1),           // governanceThreshold = 1
		wallet.PubKeyHex(), // governanceKey
		z33,                // governanceKey2
		z33,                // governanceKey3
		// Readonly: Groth16 VK (Gate 0b SP1 fixture, Mode 2 convention)
		hex.EncodeToString(vk.AlphaG1),        // alphaG1 (runar.Point → hex)
		new(big.Int).SetBytes(vk.BetaG2[0]),   // betaG2X0 (runar.Bigint → *big.Int)
		new(big.Int).SetBytes(vk.BetaG2[1]),   // betaG2X1
		new(big.Int).SetBytes(vk.BetaG2[2]),   // betaG2Y0
		new(big.Int).SetBytes(vk.BetaG2[3]),   // betaG2Y1
		new(big.Int).SetBytes(vk.GammaG2[0]),  // gammaG2X0
		new(big.Int).SetBytes(vk.GammaG2[1]),  // gammaG2X1
		new(big.Int).SetBytes(vk.GammaG2[2]),  // gammaG2Y0
		new(big.Int).SetBytes(vk.GammaG2[3]),  // gammaG2Y1
		new(big.Int).SetBytes(vk.DeltaG2[0]),  // deltaG2X0
		new(big.Int).SetBytes(vk.DeltaG2[1]),  // deltaG2X1
		new(big.Int).SetBytes(vk.DeltaG2[2]),  // deltaG2Y0
		new(big.Int).SetBytes(vk.DeltaG2[3]),  // deltaG2Y1
		hex.EncodeToString(vk.IC0),            // iC0 (runar.Point)
		hex.EncodeToString(vk.IC1),            // iC1
		hex.EncodeToString(vk.IC2),            // iC2
		hex.EncodeToString(vk.IC3),            // iC3
		hex.EncodeToString(vk.IC4),            // iC4
		hex.EncodeToString(vk.IC5),            // iC5
	}

	contract := runar.NewRunarContract(artifact, constructorArgs)

	txid, _, deployErr := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 200_000})
	if deployErr != nil {
		return nil, nil, nil, nil, deployErr
	}
	t.Logf("DEPLOY:  txid=%s", txid)
	return contract, provider, signer, wallet, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRollupGroth16_FullLifecycle deploys the Mode 2 Groth16 rollup
// covenant with real SP1 VK constants and runs 10 state advances, each
// supplying the real SP1 Groth16 proof points and public inputs. The
// on-chain Bn254MultiPairing4 check actually verifies on every spend.
//
// The reason the same proof can be reused for every advance is that the
// Mode 2 contract binds the proof only to the 5 IC linearization inputs
// (which are the SP1 public inputs, fixed for this fixture) — there is
// no per-block commitment in the pairing equation. The public values
// blob's pre/post state roots and batch hash ARE per-block, but they
// live behind separate hash256 checks that do not feed into the
// pairing.
func TestRollupGroth16_FullLifecycle(t *testing.T) {
	totalStart := time.Now()
	contract, provider, signer, _, deployErr := deployGroth16Rollup(t)
	if deployErr != nil {
		t.Fatalf("deploy Groth16 covenant: %v", deployErr)
	}

	_, proof, pubInputs := loadGate0Groth16Generic(t)

	deployTxid := contract.GetCurrentUtxo().Txid
	deploySize := fullGetTxSize(t, deployTxid)
	t.Logf("DEPLOY:  size=%d bytes (%.2f MB)", deploySize, float64(deploySize)/(1024.0*1024.0))

	z32 := hexZeros32()
	pre := z32
	const numAdvances = 10
	var sizes []int
	var times []time.Duration

	for block := int64(1); block <= numAdvances; block++ {
		args := buildGroth16AdvanceArgs(pre, block, proof, pubInputs)
		start := time.Now()
		txid, _, err := contract.Call("advanceState", args, provider, signer, nil)
		dur := time.Since(start)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		txSize := fullGetTxSize(t, txid)
		sizes = append(sizes, txSize)
		times = append(times, dur)
		t.Logf("ADVANCE: block=%d  size=%d bytes (%.2f MB)  time=%s",
			block, txSize, float64(txSize)/(1024.0*1024.0), dur)
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
	t.Logf("GROTH16 ROLLUP FULL INTEGRATION RESULTS")
	t.Logf("================================================================")
	t.Logf("Proof blob:         %d KB", proofBlobSize/1024)
	t.Logf("Batch data:         %d KB", batchDataSize/1024)
	t.Logf("Deploy TX:          %d bytes", deploySize)
	t.Logf("Advances:           %d", numAdvances)
	t.Logf("Advance TX size:    avg=%d KB  min=%d KB  max=%d KB",
		totalSize/numAdvances/1024, minS/1024, maxS/1024)
	t.Logf("Advance time:       avg=%s  total=%s",
		totalTime/time.Duration(numAdvances), totalTime)
	t.Logf("Total time:         %s", totalDur)
	t.Logf("Real BN254 pairing check PASSED on every advance (SP1 Groth16 fixture).")
	t.Logf("================================================================")
}

// TestRollupGroth16_RejectWrongPreStateRoot verifies that an advance
// with a tampered pre-state root in the public values blob is rejected
// by the OP_EQUALVERIFY check against c.StateRoot. This rejection path
// runs AFTER the pairing check, so the pairing must still succeed for
// the StateRoot mismatch to be the operative failure.
func TestRollupGroth16_RejectWrongPreStateRoot(t *testing.T) {
	contract, provider, signer, _, deployErr := deployGroth16Rollup(t)
	if deployErr != nil {
		t.Fatalf("deploy: %v", deployErr)
	}
	_, proof, pubInputs := loadGate0Groth16Generic(t)

	z32 := hexZeros32()
	args := buildGroth16AdvanceArgs(z32, 1, proof, pubInputs)
	pv := args[2].(string)
	args[2] = "ff" + pv[2:]
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong pre-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16_RejectSkippedBlockNumber verifies strict +1
// enforcement on the Groth16 contract. The block-number check runs
// before the pairing check, so this test doesn't even reach the
// pairing.
func TestRollupGroth16_RejectSkippedBlockNumber(t *testing.T) {
	contract, provider, signer, _, deployErr := deployGroth16Rollup(t)
	if deployErr != nil {
		t.Fatalf("deploy: %v", deployErr)
	}
	_, proof, pubInputs := loadGate0Groth16Generic(t)

	z32 := hexZeros32()
	args := buildGroth16AdvanceArgs(z32, 2, proof, pubInputs) // skip block 1, jump to 2
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for skipped block number")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16_RejectBadProofBlob verifies proof-blob hash binding
// on the Groth16 contract.
func TestRollupGroth16_RejectBadProofBlob(t *testing.T) {
	contract, provider, signer, _, deployErr := deployGroth16Rollup(t)
	if deployErr != nil {
		t.Fatalf("deploy: %v", deployErr)
	}
	_, proof, pubInputs := loadGate0Groth16Generic(t)

	z32 := hexZeros32()
	args := buildGroth16AdvanceArgs(z32, 1, proof, pubInputs)
	args[4] = hexGenProofBlob(99, proofBlobSize)
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for tampered proof blob")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRollupGroth16_RejectWrongChainID verifies that an advance whose
// public values encode a different chain ID is rejected on-chain.
func TestRollupGroth16_RejectWrongChainID(t *testing.T) {
	contract, provider, signer, _, deployErr := deployGroth16Rollup(t)
	if deployErr != nil {
		t.Fatalf("deploy: %v", deployErr)
	}
	_, proof, pubInputs := loadGate0Groth16Generic(t)

	z32 := hexZeros32()
	newStateRoot := hexStateRoot(1)
	batchDataHex := hexGenBatchData(z32, newStateRoot, batchDataSize)
	proofBlobHex := hexGenProofBlob(1, proofBlobSize)
	badPV := buildFullPV(z32, newStateRoot, batchDataHex, proofBlobHex, 999)
	args := buildGroth16AdvanceArgs(z32, 1, proof, pubInputs)
	args[2] = badPV
	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong chain ID")
	}
	t.Logf("correctly rejected: %v", err)
}
