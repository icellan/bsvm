package covenant

import (
	"bytes"
	"testing"
)

// TestScriptDeterminism_Basefold verifies that compiling the same Basefold
// rollup twice (same SP1 VK, chain ID, and governance config) yields
// byte-identical locking scripts. Determinism is essential: nodes joining
// a shard must re-compile the covenant locally and match the on-chain
// script hash. Any hidden non-determinism (map ordering, timestamps,
// random salts) would break node syncing.
func TestScriptDeterminism_Basefold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation determinism test in short mode")
	}

	vk := []byte("deterministic-sp1-vk-basefold-mode")
	chainID := uint64(8453111)
	gov := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
		Threshold: 2,
	}

	a, err := CompileFRIRollup(vk, chainID, gov)
	if err != nil {
		t.Fatalf("first Basefold compile failed: %v", err)
	}
	b, err := CompileFRIRollup(vk, chainID, gov)
	if err != nil {
		t.Fatalf("second Basefold compile failed: %v", err)
	}

	if !bytes.Equal(a.LockingScript, b.LockingScript) {
		t.Fatalf("Basefold locking scripts differ between compilations\n  first: %d bytes\n  second: %d bytes",
			len(a.LockingScript), len(b.LockingScript))
	}
	if a.ScriptHash != b.ScriptHash {
		t.Errorf("Basefold script hash differs:\n  first:  %x\n  second: %x", a.ScriptHash, b.ScriptHash)
	}
}

// TestScriptDeterminism_Groth16 verifies that compiling the same Groth16
// rollup twice (same SP1 VK, chain ID, governance, AND Groth16VK) yields
// byte-identical locking scripts.
func TestScriptDeterminism_Groth16(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation determinism test in short mode")
	}

	vk := []byte("deterministic-sp1-vk-groth16-mode")
	chainID := uint64(8453111)
	gov := GovernanceConfig{Mode: GovernanceNone}

	// Construct a deterministic placeholder Groth16VK. The contents don't
	// have to be cryptographically valid for the compile to succeed — the
	// VK components are just baked in as script constants.
	g16 := deterministicGroth16VK()

	a, err := CompileGroth16Rollup(vk, chainID, gov, g16)
	if err != nil {
		t.Fatalf("first Groth16 compile failed: %v", err)
	}
	b, err := CompileGroth16Rollup(vk, chainID, gov, g16)
	if err != nil {
		t.Fatalf("second Groth16 compile failed: %v", err)
	}

	if !bytes.Equal(a.LockingScript, b.LockingScript) {
		t.Fatalf("Groth16 locking scripts differ between compilations\n  first: %d bytes\n  second: %d bytes",
			len(a.LockingScript), len(b.LockingScript))
	}
	if a.ScriptHash != b.ScriptHash {
		t.Errorf("Groth16 script hash differs:\n  first:  %x\n  second: %x", a.ScriptHash, b.ScriptHash)
	}
}

// TestScriptDeterminism_Groth16WA verifies the witness-assisted Groth16
// rollup (Mode 3) is also deterministic across compilations, using the
// shipped sp1_groth16_vk.json fixture.
func TestScriptDeterminism_Groth16WA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Mode 3 determinism test in short mode")
	}

	vkPath := bsvmTestSP1VKPath(t)
	vk := []byte("deterministic-sp1-vk-groth16-wa-mode")
	chainID := uint64(8453111)
	gov := GovernanceConfig{Mode: GovernanceNone}

	a, err := CompileGroth16WARollup(vk, chainID, gov, vkPath)
	if err != nil {
		t.Fatalf("first Groth16WA compile failed: %v", err)
	}
	b, err := CompileGroth16WARollup(vk, chainID, gov, vkPath)
	if err != nil {
		t.Fatalf("second Groth16WA compile failed: %v", err)
	}

	if !bytes.Equal(a.LockingScript, b.LockingScript) {
		t.Fatalf("Groth16WA locking scripts differ between compilations\n  first: %d bytes\n  second: %d bytes",
			len(a.LockingScript), len(b.LockingScript))
	}
	if a.ScriptHash != b.ScriptHash {
		t.Errorf("Groth16WA script hash differs:\n  first:  %x\n  second: %x", a.ScriptHash, b.ScriptHash)
	}
}

// deterministicGroth16VK builds a Groth16VK with stable, non-zero
// placeholder bytes. Using all-zero components would silently collapse
// some BN254-encoded constants (e.g. OP_0) and hide determinism bugs.
func deterministicGroth16VK() *Groth16VK {
	mk32 := func(seed byte) []byte {
		out := make([]byte, 32)
		for i := range out {
			out[i] = seed + byte(i)
		}
		return out
	}
	mk64 := func(seed byte) []byte {
		out := make([]byte, 64)
		for i := range out {
			out[i] = seed + byte(i)
		}
		return out
	}
	return &Groth16VK{
		AlphaG1: mk64(0xa0),
		BetaG2:  [4][]byte{mk32(0xb0), mk32(0xb1), mk32(0xb2), mk32(0xb3)},
		GammaG2: [4][]byte{mk32(0xc0), mk32(0xc1), mk32(0xc2), mk32(0xc3)},
		DeltaG2: [4][]byte{mk32(0xd0), mk32(0xd1), mk32(0xd2), mk32(0xd3)},
		IC0:     mk64(0x10),
		IC1:     mk64(0x11),
		IC2:     mk64(0x12),
		IC3:     mk64(0x13),
		IC4:     mk64(0x14),
		IC5:     mk64(0x15),
	}
}
