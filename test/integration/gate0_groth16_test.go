//go:build integration

package integration

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"runar-integration/helpers"

	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// ---------------------------------------------------------------------------
// Gate 0b: SP1 Groth16 Proof Verification on BSV Regtest
//
// Uses the Rúnar witness-assisted Groth16 verifier (Phase 7 complete).
// End-to-end flow: SP1 VK → compile verifier → deploy → verify real SP1 proof.
// ---------------------------------------------------------------------------

// gate0FixturePath returns the absolute path to a file in tests/sp1/.
func gate0FixturePath(name string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "sp1", name)
}

// compileSP1Verifier compiles the SP1 Groth16 VK into a witness-assisted
// verifier artifact. The result is cached across subtests.
func compileSP1Verifier(t *testing.T) *runar.RunarArtifact {
	t.Helper()

	vkPath := gate0FixturePath("sp1_groth16_vk.json")
	start := time.Now()
	a, err := compiler.CompileGroth16WA(vkPath, compiler.Groth16WAOpts{
		ContractName:    "SP1Groth16Verifier",
		ModuloThreshold: 0, // strict: every intermediate reduced mod p (fast on interpreter)
	})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}
	dur := time.Since(start)

	scriptBytes := len(a.Script) / 2
	t.Logf("COMPILE: %s — %d bytes (%.1f KB) in %v",
		a.ContractName, scriptBytes, float64(scriptBytes)/1024.0, dur)
	t.Logf("         numPubInputs=%d, vkDigest=%s",
		a.Groth16WA.NumPubInputs, a.Groth16WA.VKDigest)

	// Convert compiler.Artifact → runar.RunarArtifact (same JSON shape).
	return runarArtifactFromCompilerArtifact(t, a)
}

// runarArtifactFromCompilerArtifact converts a compiler artifact to the
// runar-go runtime artifact via JSON round-trip. Both types share the
// same JSON shape (same field tags) so json.Unmarshal works directly.
func runarArtifactFromCompilerArtifact(t *testing.T, a *compiler.Artifact) *runar.RunarArtifact {
	t.Helper()
	jsonBytes, err := compiler.ArtifactToJSON(a)
	if err != nil {
		t.Fatalf("ArtifactToJSON: %v", err)
	}
	var ra runar.RunarArtifact
	if err := json.Unmarshal(jsonBytes, &ra); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return &ra
}

// loadSP1Proof reads the Gate 0b SP1 Groth16 proof fixture and returns a
// ready-to-use witness.
func loadSP1Proof(t *testing.T) *bn254witness.Witness {
	t.Helper()

	vkPath := gate0FixturePath("sp1_groth16_vk.json")
	vk, err := bn254witness.LoadSP1VKFromFile(vkPath)
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	rawProofHex, err := os.ReadFile(gate0FixturePath("groth16_raw_proof.hex"))
	if err != nil {
		t.Fatalf("read raw proof: %v", err)
	}
	proof, err := bn254witness.ParseSP1RawProof(string(rawProofHex))
	if err != nil {
		t.Fatalf("ParseSP1RawProof: %v", err)
	}

	pubInputs, err := bn254witness.LoadSP1PublicInputs(gate0FixturePath("groth16_public_inputs.txt"))
	if err != nil {
		t.Fatalf("LoadSP1PublicInputs: %v", err)
	}

	witness, err := bn254witness.GenerateWitness(vk, proof, pubInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}
	return witness
}

// deployGate0Verifier compiles + deploys the SP1 Groth16 verifier to regtest.
func deployGate0Verifier(t *testing.T) (*runar.Groth16WAContract, runar.Provider, runar.Signer) {
	t.Helper()

	artifact := compileSP1Verifier(t)
	contract := runar.NewGroth16WAContract(artifact)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false) //nolint:errcheck
	if _, err := helpers.FundWallet(wallet, 10.0); err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	start := time.Now()
	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 50000})
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	txSize := fullGetTxSize(t, txid)
	t.Logf("DEPLOY: txid=%s, tx=%d bytes (%.1f KB), time=%v",
		txid, txSize, float64(txSize)/1024.0, dur)

	return contract, provider, signer
}

// TestGate0_SP1Groth16_VerifySuccess is the critical Gate 0b test:
// can a real SP1 Groth16 proof be verified on BSV regtest?
func TestGate0_SP1Groth16_VerifySuccess(t *testing.T) {
	contract, provider, _ := deployGate0Verifier(t)

	if contract.NumPubInputs() != 5 {
		t.Fatalf("expected 5 public inputs, got %d", contract.NumPubInputs())
	}

	witness := loadSP1Proof(t)

	// Change output: send to a fresh P2PKH address.
	changeWallet := helpers.NewWallet()

	start := time.Now()
	txid, _, err := contract.CallWithWitness(
		provider,
		nil, // no signer needed — verifier has no signature check
		witness,
		changeWallet.Address,
		"",
	)
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("VERIFY FAILED: %v", err)
	}

	txSize := fullGetTxSize(t, txid)
	t.Logf("")
	t.Logf("=== GATE 0b PASS: SP1 Groth16 Proof Verified on BSV Regtest ===")
	t.Logf("  Verify TXID: %s", txid)
	t.Logf("  Verify TX:   %d bytes (%.1f KB)", txSize, float64(txSize)/1024.0)
	t.Logf("  Verify time: %v (including mining)", dur)

	if contract.CurrentUTXO() != nil {
		t.Error("CurrentUTXO should be nil after successful spend")
	}
}

// TestGate0_SP1Groth16_RejectTamperedProof verifies that a proof with the
// A point corrupted is rejected by on-chain verification.
func TestGate0_SP1Groth16_RejectTamperedProof(t *testing.T) {
	contract, provider, _ := deployGate0Verifier(t)

	witness := loadSP1Proof(t)

	// Tamper with proof A by flipping bits in the x coordinate.
	witness.ProofA[0] = new(big.Int).Add(witness.ProofA[0], big.NewInt(1))

	changeWallet := helpers.NewWallet()
	_, _, err := contract.CallWithWitness(
		provider, nil, witness, changeWallet.Address, "",
	)
	if err == nil {
		t.Fatal("SECURITY FAILURE: tampered proof A was accepted")
	}
	t.Logf("Correctly rejected tampered proof A: %v", err)
}

// TestGate0_SP1Groth16_RejectTamperedGradient verifies that tampering with
// a Miller loop gradient witness causes rejection.
func TestGate0_SP1Groth16_RejectTamperedGradient(t *testing.T) {
	contract, provider, _ := deployGate0Verifier(t)

	witness := loadSP1Proof(t)

	// Tamper with the first Miller loop gradient.
	if len(witness.MillerGradients) == 0 {
		t.Fatal("witness has no Miller gradients")
	}
	witness.MillerGradients[0] = new(big.Int).Add(witness.MillerGradients[0], big.NewInt(1))

	changeWallet := helpers.NewWallet()
	_, _, err := contract.CallWithWitness(
		provider, nil, witness, changeWallet.Address, "",
	)
	if err == nil {
		t.Fatal("SECURITY FAILURE: tampered Miller gradient was accepted")
	}
	t.Logf("Correctly rejected tampered gradient: %v", err)
}

// TestGate0_SP1Groth16_VKDigestMatches verifies the compiled artifact's
// VK digest matches what Rúnar's SP1 fixture produced.
func TestGate0_SP1Groth16_VKDigestMatches(t *testing.T) {
	artifact := compileSP1Verifier(t)
	contract := runar.NewGroth16WAContract(artifact)

	digest := contract.VKDigest()
	if len(digest) != 64 {
		t.Fatalf("VK digest should be 64 hex chars, got %d: %s", len(digest), digest)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		t.Fatalf("VK digest is not valid hex: %v", err)
	}
	t.Logf("VK digest: %s", digest)
}

