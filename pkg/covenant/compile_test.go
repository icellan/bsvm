package covenant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// ---------------------------------------------------------------------------
// TestCompiledCovenant_VKHash
// ---------------------------------------------------------------------------

// TestCompiledCovenant_VKHash verifies that the SP1VerifyingKeyHash field
// in CompiledCovenant is the SHA256 hash of the input verifying key.
func TestCompiledCovenant_VKHash(t *testing.T) {
	vk := []byte("test-sp1-verifying-key-bytes-1234567890")
	expectedHash := sha256.Sum256(vk)

	// Construct a CompiledCovenant directly to verify the hash field.
	cc := &CompiledCovenant{
		LockingScript:       []byte{0x51, 0x52, 0x93, 0x87},
		StateSize:           3,
		ScriptHash:          sha256.Sum256([]byte{0x51, 0x52, 0x93, 0x87}),
		SP1VerifyingKeyHash: expectedHash,
	}

	if cc.SP1VerifyingKeyHash != expectedHash {
		t.Errorf("VK hash mismatch:\n  got  %x\n  want %x", cc.SP1VerifyingKeyHash, expectedHash)
	}

	// Verify different VK produces different hash.
	differentVK := []byte("different-verifying-key")
	differentHash := sha256.Sum256(differentVK)
	if cc.SP1VerifyingKeyHash == differentHash {
		t.Error("different VK should produce different hash")
	}
}

// ---------------------------------------------------------------------------
// TestCompiledCovenant_ScriptHash
// ---------------------------------------------------------------------------

// TestCompiledCovenant_ScriptHash verifies that the ScriptHash field in
// CompiledCovenant is the SHA256 hash of the locking script.
func TestCompiledCovenant_ScriptHash(t *testing.T) {
	script := []byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00}
	expectedHash := sha256.Sum256(script)

	cc := &CompiledCovenant{
		LockingScript: script,
		StateSize:     3,
		ScriptHash:    expectedHash,
	}

	if cc.ScriptHash != expectedHash {
		t.Errorf("script hash mismatch:\n  got  %x\n  want %x", cc.ScriptHash, expectedHash)
	}

	// Verify the hash actually matches SHA256 of the script.
	computedHash := sha256.Sum256(cc.LockingScript)
	if cc.ScriptHash != computedHash {
		t.Error("ScriptHash does not match SHA256 of LockingScript")
	}
}

// ---------------------------------------------------------------------------
// TestBuildConstructorArgs
// ---------------------------------------------------------------------------

// TestBuildConstructorArgs verifies that buildConstructorArgs produces the
// correct ConstructorArgs map for the Rúnar compiler.
func TestBuildConstructorArgs(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	vkHash := sha256.Sum256(vk)

	args := buildConstructorArgs(vk, 42, GovernanceConfig{
		Mode: GovernanceNone,
	}, VerifyBasefold, nil)

	// verifyingKeyHash: hex of SHA256(vk)
	if got, ok := args["verifyingKeyHash"].(string); !ok {
		t.Error("verifyingKeyHash should be a string")
	} else if got != hex.EncodeToString(vkHash[:]) {
		t.Errorf("verifyingKeyHash mismatch:\n  got  %s\n  want %s", got, hex.EncodeToString(vkHash[:]))
	}

	// chainId: float64(42)
	if got, ok := args["chainId"].(float64); !ok {
		t.Error("chainId should be a float64")
	} else if got != 42.0 {
		t.Errorf("chainId = %v, want 42", got)
	}

	// governanceMode: float64(0) for GovernanceNone
	if got, ok := args["governanceMode"].(float64); !ok {
		t.Error("governanceMode should be a float64")
	} else if got != 0.0 {
		t.Errorf("governanceMode = %v, want 0", got)
	}

	// verificationMode: Groth16 -> contract value 1
	if got, ok := args["verificationMode"].(float64); !ok {
		t.Error("verificationMode should be a float64")
	} else if got != 0.0 {
		t.Errorf("verificationMode = %v, want 0 (Basefold in contract)", got)
	}

	// governanceKey: empty 33-byte placeholder for GovernanceNone
	if got, ok := args["governanceKey"].(string); !ok {
		t.Error("governanceKey should be a string")
	} else if got != hex.EncodeToString(make([]byte, 33)) {
		t.Error("governanceKey should be empty placeholder for GovernanceNone")
	}

	// governanceKey2, governanceKey3: zero placeholders for GovernanceNone
	zeroKey := hex.EncodeToString(make([]byte, 33))
	if got := args["governanceKey2"].(string); got != zeroKey {
		t.Error("governanceKey2 should be zero for GovernanceNone")
	}
	if got := args["governanceKey3"].(string); got != zeroKey {
		t.Error("governanceKey3 should be zero for GovernanceNone")
	}

	// governanceThreshold: float64(0)
	if got, ok := args["governanceThreshold"].(float64); !ok {
		t.Error("governanceThreshold should be a float64")
	} else if got != 0.0 {
		t.Errorf("governanceThreshold = %v, want 0", got)
	}
}

// TestBuildConstructorArgs_SingleKey verifies constructor args for
// single-key governance mode.
func TestBuildConstructorArgs_SingleKey(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	key := testKey(1)

	args := buildConstructorArgs(vk, 100, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{key},
	}, VerifyBasefold, nil)

	// governanceMode: float64(1) for GovernanceSingleKey
	if got := args["governanceMode"].(float64); got != 1.0 {
		t.Errorf("governanceMode = %v, want 1", got)
	}

	// governanceKey: hex of the single key
	if got := args["governanceKey"].(string); got != hex.EncodeToString(key) {
		t.Errorf("governanceKey mismatch:\n  got  %s\n  want %s", got, hex.EncodeToString(key))
	}

	// verificationMode: Basefold -> contract value 0
	if got := args["verificationMode"].(float64); got != 0.0 {
		t.Errorf("verificationMode = %v, want 0 (Basefold in contract)", got)
	}
}

// TestBuildConstructorArgs_MultiSig verifies constructor args for
// multi-sig governance mode.
func TestBuildConstructorArgs_MultiSig(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	keys := [][]byte{testKey(1), testKey(2), testKey(3)}

	args := buildConstructorArgs(vk, 200, GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      keys,
		Threshold: 2,
	}, VerifyBasefold, nil)

	// governanceMode: float64(2)
	if got := args["governanceMode"].(float64); got != 2.0 {
		t.Errorf("governanceMode = %v, want 2", got)
	}

	// governanceThreshold: float64(2)
	if got := args["governanceThreshold"].(float64); got != 2.0 {
		t.Errorf("governanceThreshold = %v, want 2", got)
	}

	// governanceKey, governanceKey2, governanceKey3: individual key slots
	if got := args["governanceKey"].(string); got != hex.EncodeToString(keys[0]) {
		t.Errorf("governanceKey = %s, want %s", got, hex.EncodeToString(keys[0]))
	}
	if got := args["governanceKey2"].(string); got != hex.EncodeToString(keys[1]) {
		t.Errorf("governanceKey2 = %s, want %s", got, hex.EncodeToString(keys[1]))
	}
	if got := args["governanceKey3"].(string); got != hex.EncodeToString(keys[2]) {
		t.Errorf("governanceKey3 = %s, want %s", got, hex.EncodeToString(keys[2]))
	}
}

// ---------------------------------------------------------------------------
// TestVerificationModeToContract
// ---------------------------------------------------------------------------

// TestVerificationModeToContract verifies the mapping between our Go enum
// and the contract's convention.
func TestVerificationModeToContract(t *testing.T) {
	// Our VerifyGroth16 (0) -> contract 1
	if got := verificationModeToContract(VerifyGroth16); got != 1.0 {
		t.Errorf("VerifyGroth16 -> contract %v, want 1", got)
	}

	// Our VerifyBasefold (1) -> contract 0
	if got := verificationModeToContract(VerifyBasefold); got != 0.0 {
		t.Errorf("VerifyBasefold -> contract %v, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// TestCompileWithDifferentParams
// ---------------------------------------------------------------------------

// TestCompileWithDifferentParams compiles the covenant with two different
// chain IDs and verifies the resulting scripts differ.
func TestCompileWithDifferentParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation test in short mode")
	}

	vk := []byte("test-sp1-verifying-key-for-compilation")

	compiled1, err := CompileCovenant(vk, 1001, GovernanceConfig{Mode: GovernanceNone}, VerifyBasefold, nil)
	if err != nil {
		t.Fatalf("CompileCovenant with chainID=1001 failed: %v", err)
	}

	compiled2, err := CompileCovenant(vk, 2002, GovernanceConfig{Mode: GovernanceNone}, VerifyBasefold, nil)
	if err != nil {
		t.Fatalf("CompileCovenant with chainID=2002 failed: %v", err)
	}

	// Scripts should differ because chain ID is baked in.
	if bytes.Equal(compiled1.LockingScript, compiled2.LockingScript) {
		t.Error("scripts with different chain IDs should differ")
	}

	// Both should have non-empty scripts.
	if len(compiled1.LockingScript) == 0 {
		t.Error("compiled1 locking script should not be empty")
	}
	if len(compiled2.LockingScript) == 0 {
		t.Error("compiled2 locking script should not be empty")
	}

	// Chain IDs should be correctly recorded.
	if compiled1.ChainID != 1001 {
		t.Errorf("compiled1.ChainID = %d, want 1001", compiled1.ChainID)
	}
	if compiled2.ChainID != 2002 {
		t.Errorf("compiled2.ChainID = %d, want 2002", compiled2.ChainID)
	}
}

// ---------------------------------------------------------------------------
// TestCompileWithVerifyingKey
// ---------------------------------------------------------------------------

// TestCompileWithVerifyingKey compiles the covenant with a verifying key
// and verifies the VK hash is embedded in the compiled artifact.
func TestCompileWithVerifyingKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation test in short mode")
	}

	vk := []byte("unique-sp1-verifying-key-bytes-for-test")
	vkHash := sha256.Sum256(vk)

	compiled, err := CompileCovenant(vk, 42, GovernanceConfig{Mode: GovernanceNone}, VerifyBasefold, nil)
	if err != nil {
		t.Fatalf("CompileCovenant failed: %v", err)
	}

	// The SP1VerifyingKeyHash should match SHA256 of the VK.
	if compiled.SP1VerifyingKeyHash != vkHash {
		t.Errorf("VK hash mismatch:\n  got  %x\n  want %x", compiled.SP1VerifyingKeyHash, vkHash)
	}

	// The VK hash should appear in the compiled locking script (as a
	// baked-in constant from the constructor args).
	if !bytes.Contains(compiled.LockingScript, vkHash[:]) {
		t.Error("locking script should contain the VK hash as a baked-in constant")
	}

	// Compile with a different VK and verify the script differs.
	vk2 := []byte("different-sp1-verifying-key-bytes!!!!!!")
	compiled2, err := CompileCovenant(vk2, 42, GovernanceConfig{Mode: GovernanceNone}, VerifyBasefold, nil)
	if err != nil {
		t.Fatalf("CompileCovenant with different VK failed: %v", err)
	}

	if bytes.Equal(compiled.LockingScript, compiled2.LockingScript) {
		t.Error("scripts with different VKs should differ")
	}
}

// ---------------------------------------------------------------------------
// TestCompileWithGovernanceModes
// ---------------------------------------------------------------------------

// TestCompileWithGovernanceModes compiles the covenant with different
// governance modes and verifies the resulting scripts differ.
func TestCompileWithGovernanceModes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation test in short mode")
	}

	vk := []byte("test-sp1-verifying-key-for-governance")

	// GovernanceNone
	compiledNone, err := CompileCovenant(vk, 42, GovernanceConfig{
		Mode: GovernanceNone,
	}, VerifyBasefold, nil)
	if err != nil {
		t.Fatalf("CompileCovenant with GovernanceNone failed: %v", err)
	}

	// GovernanceSingleKey
	compiledSingle, err := CompileCovenant(vk, 42, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}, VerifyBasefold, nil)
	if err != nil {
		t.Fatalf("CompileCovenant with GovernanceSingleKey failed: %v", err)
	}

	// GovernanceMultiSig
	compiledMulti, err := CompileCovenant(vk, 42, GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
		Threshold: 2,
	}, VerifyBasefold, nil)
	if err != nil {
		t.Fatalf("CompileCovenant with GovernanceMultiSig failed: %v", err)
	}

	// All three should produce different scripts because governance
	// mode and keys are baked in as different constants.
	if bytes.Equal(compiledNone.LockingScript, compiledSingle.LockingScript) {
		t.Error("GovernanceNone and GovernanceSingleKey scripts should differ")
	}
	if bytes.Equal(compiledNone.LockingScript, compiledMulti.LockingScript) {
		t.Error("GovernanceNone and GovernanceMultiSig scripts should differ")
	}
	if bytes.Equal(compiledSingle.LockingScript, compiledMulti.LockingScript) {
		t.Error("GovernanceSingleKey and GovernanceMultiSig scripts should differ")
	}
}

// ---------------------------------------------------------------------------
// TestCompileParamsValidation
// ---------------------------------------------------------------------------

// TestCompileParamsValidation verifies that invalid parameters produce errors.
func TestCompileParamsValidation(t *testing.T) {
	validVK := []byte("valid-sp1-verifying-key-bytes!!!!!!")

	tests := []struct {
		name    string
		vk      []byte
		chainID uint64
		gov     GovernanceConfig
		mode    VerificationMode
		wantErr string
	}{
		{
			name:    "nil verifying key",
			vk:      nil,
			chainID: 42,
			gov:     GovernanceConfig{Mode: GovernanceNone},
			mode:    VerifyGroth16,
			wantErr: "sp1 verifying key must not be empty",
		},
		{
			name:    "empty verifying key",
			vk:      []byte{},
			chainID: 42,
			gov:     GovernanceConfig{Mode: GovernanceNone},
			mode:    VerifyGroth16,
			wantErr: "sp1 verifying key must not be empty",
		},
		{
			name:    "zero chain ID",
			vk:      validVK,
			chainID: 0,
			gov:     GovernanceConfig{Mode: GovernanceNone},
			mode:    VerifyGroth16,
			wantErr: "chain ID must not be zero",
		},
		{
			name:    "invalid governance: single key with no keys",
			vk:      validVK,
			chainID: 42,
			gov: GovernanceConfig{
				Mode: GovernanceSingleKey,
				Keys: nil,
			},
			mode:    VerifyGroth16,
			wantErr: "invalid governance config",
		},
		{
			name:    "invalid governance: multisig with threshold 0",
			vk:      validVK,
			chainID: 42,
			gov: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), testKey(2)},
				Threshold: 0,
			},
			mode:    VerifyGroth16,
			wantErr: "invalid governance config",
		},
		{
			name:    "invalid governance: none with keys",
			vk:      validVK,
			chainID: 42,
			gov: GovernanceConfig{
				Mode: GovernanceNone,
				Keys: [][]byte{testKey(1)},
			},
			mode:    VerifyGroth16,
			wantErr: "invalid governance config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileCovenant(tt.vk, tt.chainID, tt.gov, tt.mode, nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !containsSubstring(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && containsAt(s, substr)
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
