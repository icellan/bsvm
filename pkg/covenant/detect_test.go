package covenant

import (
	"encoding/hex"
	"testing"
)

// TestDetectVerificationMode_FRI compiles a real FRI covenant, feeds
// its hex-encoded locking script to DetectVerificationMode, and
// expects VerifyFRI. This exercises the full detection loop: compile
// placeholder template → JSON round-trip → runar.MatchesArtifact.
func TestDetectVerificationMode_FRI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy detection test in short mode")
	}
	vk := []byte("test-sp1-verifying-key-fri-detection")
	gov := GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	compiled, err := CompileFRIRollup(vk, 42, gov)
	if err != nil {
		t.Fatalf("CompileFRIRollup: %v", err)
	}
	scriptHex := hex.EncodeToString(compiled.LockingScript)

	mode, err := DetectVerificationMode(scriptHex)
	if err != nil {
		t.Fatalf("DetectVerificationMode: %v", err)
	}
	if mode != VerifyFRI {
		t.Errorf("got mode %s, want fri", mode.String())
	}
}

// TestDetectVerificationMode_DevKey exercises the same path for the
// devnet DevKey rollup.
func TestDetectVerificationMode_DevKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy detection test in short mode")
	}
	vk := []byte("test-sp1-verifying-key-devkey-detection")
	gov := GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(2)},
	}
	compiled, err := CompileDevKeyRollup(vk, 123, gov)
	if err != nil {
		t.Fatalf("CompileDevKeyRollup: %v", err)
	}
	scriptHex := hex.EncodeToString(compiled.LockingScript)

	mode, err := DetectVerificationMode(scriptHex)
	if err != nil {
		t.Fatalf("DetectVerificationMode: %v", err)
	}
	if mode != VerifyDevKey {
		t.Errorf("got mode %s, want devkey", mode.String())
	}
}

// TestDetectVerificationMode_Empty rejects empty input.
func TestDetectVerificationMode_Empty(t *testing.T) {
	if _, err := DetectVerificationMode(""); err == nil {
		t.Fatal("expected error for empty script")
	}
}

// TestDetectVerificationMode_Garbage returns a no-match error when the
// script is well-formed hex but doesn't match any known template.
func TestDetectVerificationMode_Garbage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy detection test in short mode")
	}
	garbage := "76a914" + "00112233445566778899aabbccddeeff00112233" + "88ac"
	if _, err := DetectVerificationMode(garbage); err == nil {
		t.Fatal("expected no-match error, got nil")
	}
}
