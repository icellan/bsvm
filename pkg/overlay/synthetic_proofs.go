package overlay

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/prover"

	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// syntheticFRIProof returns a FRIProof populated with the deterministic
// mock values used by the hermetic test suite. Real prover binaries
// replace these with values extracted from the SP1 proof envelope.
//
// Mode 1 (FRIRollupContract) does not verify the SP1 FRI proof on-chain,
// so no KoalaBear field elements or Merkle authentication paths are
// required — the 5-arg advanceState call just forwards the proof blob
// for off-chain verification.
//
// The publicValues field is REBUILT in the rollup contract's expected
// layout rather than re-using the prover's PublicValues.Encode() blob:
// the prover's raw layout places receipts hash / gas used at offsets
// that conflict with the contract's batchDataHash / chainId-LE
// expectations. Mode 1, Mode 2, and Mode 3 all share the same layout,
// assembled by buildAdvancePublicValues below.
func syntheticFRIProof(proverValues, batch, blob []byte) *covenant.FRIProof {
	// Parse the pre/post state roots, chain ID, and block number from the
	// prover's 280-byte PublicValues blob so we can re-serialise them in
	// the rollup contract layout. The prover writes:
	//   [0..32]   PreStateRoot
	//   [32..64]  PostStateRoot
	//   [136..144] ChainID (big-endian uint64)
	//   [272..280] BlockNumber (big-endian uint64)
	var preRoot, postRoot [32]byte
	var chainID, blockNumber uint64
	if len(proverValues) >= 144 {
		copy(preRoot[:], proverValues[0:32])
		copy(postRoot[:], proverValues[32:64])
		chainID = binary.BigEndian.Uint64(proverValues[136:144])
	}
	if len(proverValues) >= 280 {
		blockNumber = binary.BigEndian.Uint64(proverValues[272:280])
	}

	pv := buildAdvancePublicValues(preRoot[:], postRoot[:], batch, blob, chainID, blockNumber)

	return &covenant.FRIProof{
		Values: pv,
		Batch:  batch,
		Blob:   blob,
	}
}

// buildAdvancePublicValues returns the 280-byte public-values blob
// expected by every rollup contract's AdvanceState on-chain checks.
// chainID and blockNumber are serialised as 8 little-endian bytes to
// match runar.Num2Bin(…, 8). The hash256 helper implements Bitcoin's
// OP_HASH256 (sha256(sha256(data))) matching runar.Hash256 on the
// contract side.
func buildAdvancePublicValues(preStateRoot, postStateRoot, batchData, proofBlob []byte, chainID, blockNumber uint64) []byte {
	buf := make([]byte, 280)
	copy(buf[0:32], preStateRoot)
	copy(buf[32:64], postStateRoot)
	proofHash := hash256(proofBlob)
	copy(buf[64:96], proofHash[:])
	// [96..104) zero padding (reserved)
	batchHash := hash256(batchData)
	copy(buf[104:136], batchHash[:])
	binary.LittleEndian.PutUint64(buf[136:144], chainID)
	// [144..272) four 32-byte zero slots (reserved)
	binary.LittleEndian.PutUint64(buf[272:280], blockNumber)
	return buf
}

// syntheticGroth16Proof returns a Groth16Proof for Mode 2. The
// BN254 proof points and adjusted public inputs come from the embedded Gate 0b
// SP1 fixture (applied via covenant.ApplyZeroInputWorkaround), so the produced
// proof actually satisfies the on-chain pairing check in the Mode 2 rollup
// contract. The publicValues blob is rebuilt in the Mode 2 contract's expected
// layout (same as Mode 1 / Mode 3), and the pre/post state roots, chainID and
// block number are extracted from the prover's 280-byte PublicValues blob at
// the SP1 layout offsets.
//
// The mock prover does not regenerate a different BN254 proof per batch: the
// Mode 2 contract binds the proof only to the fixed SP1 public inputs (no
// per-block commitment in the pairing equation), so the same fixture-backed
// proof is valid for every advance. The per-block pre/post state roots and
// batch hash live behind separate hash256 checks that do not feed into the
// pairing.
func syntheticGroth16Proof(proverValues, batch, blob []byte) (*covenant.Groth16Proof, error) {
	fixture, err := loadSyntheticGroth16Fixture()
	if err != nil {
		return nil, err
	}

	var preRoot, postRoot [32]byte
	var chainID, blockNumber uint64
	if len(proverValues) >= 144 {
		copy(preRoot[:], proverValues[0:32])
		copy(postRoot[:], proverValues[32:64])
		chainID = binary.BigEndian.Uint64(proverValues[136:144])
	}
	if len(proverValues) >= 280 {
		blockNumber = binary.BigEndian.Uint64(proverValues[272:280])
	}

	pv := buildAdvancePublicValues(preRoot[:], postRoot[:], batch, blob, chainID, blockNumber)

	return &covenant.Groth16Proof{
		Values:   pv,
		Batch:    batch,
		Blob:     blob,
		ProofAx:  new(big.Int).Set(fixture.proof.A[0]),
		ProofAy:  new(big.Int).Set(fixture.proof.A[1]),
		ProofBx0: new(big.Int).Set(fixture.proof.B[0]),
		ProofBx1: new(big.Int).Set(fixture.proof.B[1]),
		ProofBy0: new(big.Int).Set(fixture.proof.B[2]),
		ProofBy1: new(big.Int).Set(fixture.proof.B[3]),
		ProofCx:  new(big.Int).Set(fixture.proof.C[0]),
		ProofCy:  new(big.Int).Set(fixture.proof.C[1]),
		PublicInputs: [5]*big.Int{
			new(big.Int).Set(fixture.adjustedInputs[0]),
			new(big.Int).Set(fixture.adjustedInputs[1]),
			new(big.Int).Set(fixture.adjustedInputs[2]),
			new(big.Int).Set(fixture.adjustedInputs[3]),
			new(big.Int).Set(fixture.adjustedInputs[4]),
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Gate 0b SP1 Groth16 fixtures — embedded at compile time so the overlay can
// load a real BN254 witness bundle for the synthetic Mode 3 proof path
// without touching the filesystem. The files are small (~4 KB total) and
// come straight from tests/sp1/ where Gate 0b originally deposited them.
// ---------------------------------------------------------------------------

//go:embed testdata/sp1_groth16_vk.json
var embeddedSP1Groth16VK []byte

//go:embed testdata/groth16_raw_proof.hex
var embeddedSP1Groth16RawProof []byte

//go:embed testdata/groth16_public_inputs.txt
var embeddedSP1Groth16PublicInputs []byte

// syntheticSP1FixturePaths holds the on-disk paths to the materialised SP1
// fixture files. bn254witness.LoadSP1VKFromFile / LoadSP1PublicInputs both
// take file paths, so the embedded bytes must be materialised into a
// per-process temp directory before being handed off. The files are tiny
// (~4 KB total) and live for the process lifetime.
type syntheticSP1FixturePaths struct {
	vkPath  string
	pubPath string
}

var (
	syntheticSP1FixturePathsOnce sync.Once
	syntheticSP1FixturePathsVal  syntheticSP1FixturePaths
	syntheticSP1FixturePathsErr  error
)

// materialiseSP1Fixtures writes the embedded SP1 VK and public-inputs bytes
// into a per-process temp directory and returns the resulting paths. The
// files are written once and reused across every subsequent loader call, so
// both the Mode 2 and Mode 3 synthetic proof paths share the same on-disk
// fixture directory.
func materialiseSP1Fixtures() (syntheticSP1FixturePaths, error) {
	syntheticSP1FixturePathsOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "bsvm-overlay-sp1-")
		if err != nil {
			syntheticSP1FixturePathsErr = fmt.Errorf("materialiseSP1Fixtures: mktempdir: %w", err)
			return
		}
		vkPath := filepath.Join(tmpDir, "sp1_groth16_vk.json")
		if err := os.WriteFile(vkPath, embeddedSP1Groth16VK, 0600); err != nil {
			syntheticSP1FixturePathsErr = fmt.Errorf("materialiseSP1Fixtures: write vk: %w", err)
			return
		}
		pubPath := filepath.Join(tmpDir, "groth16_public_inputs.txt")
		if err := os.WriteFile(pubPath, embeddedSP1Groth16PublicInputs, 0600); err != nil {
			syntheticSP1FixturePathsErr = fmt.Errorf("materialiseSP1Fixtures: write public inputs: %w", err)
			return
		}
		syntheticSP1FixturePathsVal = syntheticSP1FixturePaths{
			vkPath:  vkPath,
			pubPath: pubPath,
		}
	})
	return syntheticSP1FixturePathsVal, syntheticSP1FixturePathsErr
}

var (
	syntheticWAWitnessOnce sync.Once
	syntheticWAWitness     *bn254witness.Witness
	syntheticWAWitnessErr  error
)

// loadSyntheticGroth16WAWitness loads (once) the embedded Gate 0b SP1
// fixtures and generates a real BN254 witness bundle. The result is cached
// across every synthetic proof call — the mock prover does not regenerate
// a different witness per batch, it reuses the same real one because the
// on-chain witness-assisted verifier only cares that the bundle is internally
// consistent with the baked-in SP1 VK.
func loadSyntheticGroth16WAWitness() (*bn254witness.Witness, error) {
	syntheticWAWitnessOnce.Do(func() {
		paths, err := materialiseSP1Fixtures()
		if err != nil {
			syntheticWAWitnessErr = fmt.Errorf("loadSyntheticGroth16WAWitness: %w", err)
			return
		}

		vk, err := bn254witness.LoadSP1VKFromFile(paths.vkPath)
		if err != nil {
			syntheticWAWitnessErr = fmt.Errorf("loadSyntheticGroth16WAWitness: vk: %w", err)
			return
		}
		proof, err := bn254witness.ParseSP1RawProof(string(embeddedSP1Groth16RawProof))
		if err != nil {
			syntheticWAWitnessErr = fmt.Errorf("loadSyntheticGroth16WAWitness: proof: %w", err)
			return
		}
		pubInputs, err := bn254witness.LoadSP1PublicInputs(paths.pubPath)
		if err != nil {
			syntheticWAWitnessErr = fmt.Errorf("loadSyntheticGroth16WAWitness: public inputs: %w", err)
			return
		}
		witness, err := bn254witness.GenerateWitness(vk, proof, pubInputs)
		if err != nil {
			syntheticWAWitnessErr = fmt.Errorf("loadSyntheticGroth16WAWitness: GenerateWitness: %w", err)
			return
		}
		syntheticWAWitness = witness
	})
	return syntheticWAWitness, syntheticWAWitnessErr
}

// syntheticGroth16Fixture caches the Mode 2 inputs derived from the
// embedded Gate 0b SP1 fixture: the decomposed BN254 proof and the adjusted
// public input vector produced by covenant.ApplyZeroInputWorkaround.
//
// The VK is not cached here because the deploy helper in test/integration
// loads it independently (both sides must agree on the IC0 adjustment for
// the on-chain MSM to recover the correct prepared_inputs).
type syntheticGroth16Fixture struct {
	proof          bn254witness.Proof
	adjustedInputs covenant.Mode2AdjustedPublicInputs
}

var (
	syntheticGroth16FixtureOnce sync.Once
	syntheticGroth16FixtureVal  *syntheticGroth16Fixture
	syntheticGroth16FixtureErr  error
)

// loadSyntheticGroth16Fixture loads (once) the embedded Gate 0b SP1
// fixture in the form the Mode 2 synthetic proof needs: the decomposed
// BN254 proof (A, B, C as *big.Int coordinates) and the adjusted public
// input vector (zeros replaced with 1 to sidestep the Rúnar codegen's
// identity-point limitation — see covenant.ApplyZeroInputWorkaround).
//
// The loader reuses the shared on-disk SP1 fixture paths from
// materialiseSP1Fixtures so Mode 2 and Mode 3 share one temp directory
// per process.
func loadSyntheticGroth16Fixture() (*syntheticGroth16Fixture, error) {
	syntheticGroth16FixtureOnce.Do(func() {
		paths, err := materialiseSP1Fixtures()
		if err != nil {
			syntheticGroth16FixtureErr = fmt.Errorf("loadSyntheticGroth16Fixture: %w", err)
			return
		}

		proof, err := bn254witness.ParseSP1RawProof(string(embeddedSP1Groth16RawProof))
		if err != nil {
			syntheticGroth16FixtureErr = fmt.Errorf("loadSyntheticGroth16Fixture: proof: %w", err)
			return
		}

		rawInputs, err := bn254witness.LoadSP1PublicInputs(paths.pubPath)
		if err != nil {
			syntheticGroth16FixtureErr = fmt.Errorf("loadSyntheticGroth16Fixture: public inputs: %w", err)
			return
		}
		if len(rawInputs) != covenant.Mode2PublicInputCount {
			syntheticGroth16FixtureErr = fmt.Errorf(
				"loadSyntheticGroth16Fixture: expected %d SP1 public inputs, got %d",
				covenant.Mode2PublicInputCount, len(rawInputs),
			)
			return
		}

		rawVK, err := covenant.LoadSP1Groth16VK(paths.vkPath)
		if err != nil {
			syntheticGroth16FixtureErr = fmt.Errorf("loadSyntheticGroth16Fixture: vk: %w", err)
			return
		}
		_, adjInputs, err := covenant.ApplyZeroInputWorkaround(rawVK, rawInputs)
		if err != nil {
			syntheticGroth16FixtureErr = fmt.Errorf("loadSyntheticGroth16Fixture: workaround: %w", err)
			return
		}

		syntheticGroth16FixtureVal = &syntheticGroth16Fixture{
			proof:          proof,
			adjustedInputs: adjInputs,
		}
	})
	return syntheticGroth16FixtureVal, syntheticGroth16FixtureErr
}

// syntheticGroth16WAProof returns a Groth16WAProof for Mode 3. The
// publicValues blob is rebuilt in the Mode 3 contract's expected layout
// (same as Basefold), and the witness is the cached real Gate 0b witness
// bundle. The caller MUST have already ensured the overlay is wired up
// for Mode 3 (chainID / contract VK match Gate 0b's SP1 fixture).
//
// In the mock prover path the preStateRoot / postStateRoot / chainID /
// blockNumber are read from the prover's 280-byte PublicValues blob at
// the SP1 layout offsets and re-serialized in the on-chain layout.
func syntheticGroth16WAProof(proverValues, batch, blob []byte) (*covenant.Groth16WAProof, error) {
	witness, err := loadSyntheticGroth16WAWitness()
	if err != nil {
		return nil, err
	}

	var preRoot, postRoot [32]byte
	var chainID, blockNumber uint64
	if len(proverValues) >= 144 {
		copy(preRoot[:], proverValues[0:32])
		copy(postRoot[:], proverValues[32:64])
		chainID = binary.BigEndian.Uint64(proverValues[136:144])
	}
	if len(proverValues) >= 280 {
		blockNumber = binary.BigEndian.Uint64(proverValues[272:280])
	}

	pv := buildAdvancePublicValues(preRoot[:], postRoot[:], batch, blob, chainID, blockNumber)

	return &covenant.Groth16WAProof{
		Values:  pv,
		Batch:   batch,
		Blob:    blob,
		Witness: witness,
	}, nil
}

// BuildAdvanceProofForOutput returns the mode-specific AdvanceProof for a
// prover output. Real prover binaries will produce this directly from
// proof bytes; the mock path synthesises placeholder proof scaffolding.
func BuildAdvanceProofForOutput(
	out *prover.ProveOutput,
	batch []byte,
) (covenant.AdvanceProof, error) {
	switch out.Mode {
	case prover.ProofModeFRI:
		return syntheticFRIProof(out.PublicValues, batch, out.Proof), nil
	case prover.ProofModeGroth16:
		return syntheticGroth16Proof(out.PublicValues, batch, out.Proof)
	case prover.ProofModeGroth16WA:
		return syntheticGroth16WAProof(out.PublicValues, batch, out.Proof)
	default:
		return nil, unknownProofModeError(out.Mode)
	}
}

type unknownProofModeError prover.ProofMode

func (e unknownProofModeError) Error() string {
	return "overlay: unknown proof mode " + prover.ProofMode(e).String()
}
