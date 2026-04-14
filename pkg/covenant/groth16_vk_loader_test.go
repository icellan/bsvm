package covenant

import (
	"math/big"
	"path/filepath"
	"runtime"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// gate0VKPath returns the absolute path to the Gate 0b SP1 Groth16 vk.json
// fixture shipped in tests/sp1/. Used to validate the Mode 2 VK loader.
func gate0VKPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "sp1", "sp1_groth16_vk.json")
}

// TestLoadSP1Groth16VK_BetaPreNegated verifies that the Mode 2 loader
// stores BetaG2 with a negated y-coordinate (i.e., copies the SP1
// BetaNegG2 verbatim). This matches the runtime y-negation in the
// rollup_groth16.runar.go contract.
func TestLoadSP1Groth16VK_BetaPreNegated(t *testing.T) {
	vk, err := bn254witness.LoadSP1VKFromFile(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	g16, err := LoadSP1Groth16VK(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1Groth16VK: %v", err)
	}

	// Beta is copied verbatim from SP1's BetaNegG2 (which is stored with y
	// negated). Mode 2 contract negates y at runtime to recover positive β.
	wantBetaY0 := vk.BetaNegG2[2]
	gotBetaY0 := new(big.Int).SetBytes(g16.BetaG2[2])
	if gotBetaY0.Cmp(wantBetaY0) != 0 {
		t.Errorf("BetaG2[2] = %s, want %s (verbatim SP1 BetaNegG2)", gotBetaY0, wantBetaY0)
	}
}

// TestLoadSP1Groth16VK_GammaPositive verifies that the Mode 2 loader
// re-negates the y-coordinate of SP1's GammaNegG2 to produce positive
// gamma.y (matching the verbatim use of GammaG2 in the contract pairing).
func TestLoadSP1Groth16VK_GammaPositive(t *testing.T) {
	vk, err := bn254witness.LoadSP1VKFromFile(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	g16, err := LoadSP1Groth16VK(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1Groth16VK: %v", err)
	}

	// Loader should produce: stored.y = Bn254FieldNeg(neg.y).
	wantGammaY0 := runar.Bn254FieldNeg(vk.GammaNegG2[2])
	gotGammaY0 := new(big.Int).SetBytes(g16.GammaG2[2])
	if gotGammaY0.Cmp(wantGammaY0) != 0 {
		t.Errorf("GammaG2[2] = %s, want %s (Bn254FieldNeg(SP1 GammaNegG2))", gotGammaY0, wantGammaY0)
	}

	// X coordinates copied verbatim.
	wantGammaX0 := vk.GammaNegG2[0]
	gotGammaX0 := new(big.Int).SetBytes(g16.GammaG2[0])
	if gotGammaX0.Cmp(wantGammaX0) != 0 {
		t.Errorf("GammaG2[0] = %s, want %s (verbatim SP1 GammaNegG2.x0)", gotGammaX0, wantGammaX0)
	}
}

// TestLoadSP1Groth16VK_AllICs verifies that all 6 IC points are loaded
// and match the SP1 fixture verbatim (G1 points are positive in both
// conventions).
func TestLoadSP1Groth16VK_AllICs(t *testing.T) {
	vk, err := bn254witness.LoadSP1VKFromFile(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	g16, err := LoadSP1Groth16VK(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1Groth16VK: %v", err)
	}

	icSlots := [][]byte{g16.IC0, g16.IC1, g16.IC2, g16.IC3, g16.IC4, g16.IC5}
	for i := 0; i < 6; i++ {
		got := icSlots[i]
		if len(got) != 64 {
			t.Errorf("IC[%d] length = %d, want 64", i, len(got))
			continue
		}
		gotX := new(big.Int).SetBytes(got[0:32])
		gotY := new(big.Int).SetBytes(got[32:64])
		if gotX.Cmp(vk.IC[i][0]) != 0 {
			t.Errorf("IC[%d].x mismatch", i)
		}
		if gotY.Cmp(vk.IC[i][1]) != 0 {
			t.Errorf("IC[%d].y mismatch", i)
		}
	}
}
