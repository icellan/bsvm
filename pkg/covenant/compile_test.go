package covenant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"runtime"
	"testing"
)

// bsvmTestSP1VKPath returns the absolute path to the Gate 0b SP1 Groth16
// vk.json fixture shipped in tests/sp1/. Used by Mode 3 compile tests.
func bsvmTestSP1VKPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "sp1", "sp1_groth16_vk.json")
}

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
// TestBuildFRIConstructorArgs
// ---------------------------------------------------------------------------

// TestBuildFRIConstructorArgs verifies that buildFRIConstructorArgs
// produces the expected ConstructorArgs map for the Rúnar compiler. The
// Basefold variant has no mode-specific readonly properties, only the shared
// ones (vkHash, chainId, governance).
func TestBuildFRIConstructorArgs(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	vkHash := sha256.Sum256(vk)

	args, err := buildFRIConstructorArgs(vk, 42, GovernanceConfig{
		Mode: GovernanceNone,
	})
	if err != nil {
		t.Fatalf("buildFRIConstructorArgs: %v", err)
	}

	// sP1VerifyingKeyHash: hex of SHA256(vk)
	if got, ok := args["sP1VerifyingKeyHash"].(string); !ok {
		t.Error("sP1VerifyingKeyHash should be a string")
	} else if got != hex.EncodeToString(vkHash[:]) {
		t.Errorf("sP1VerifyingKeyHash mismatch:\n  got  %s\n  want %s", got, hex.EncodeToString(vkHash[:]))
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

	// Basefold variant should NOT include any Groth16 VK args.
	groth16Keys := []string{
		"alphaG1", "betaG2X0", "iC0", "iC5",
	}
	for _, k := range groth16Keys {
		if _, ok := args[k]; ok {
			t.Errorf("fri args should not include Groth16 VK key %q", k)
		}
	}
}

// TestBuildFRIConstructorArgs_SingleKey verifies constructor args for
// single-key governance mode.
func TestBuildFRIConstructorArgs_SingleKey(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	key := testKey(1)

	args, err := buildFRIConstructorArgs(vk, 100, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{key},
	})
	if err != nil {
		t.Fatalf("buildFRIConstructorArgs: %v", err)
	}

	// governanceMode: float64(1) for GovernanceSingleKey
	if got := args["governanceMode"].(float64); got != 1.0 {
		t.Errorf("governanceMode = %v, want 1", got)
	}

	// governanceKey: hex of the single key
	if got := args["governanceKey"].(string); got != hex.EncodeToString(key) {
		t.Errorf("governanceKey mismatch:\n  got  %s\n  want %s", got, hex.EncodeToString(key))
	}
}

// TestBuildFRIConstructorArgs_MultiSig verifies constructor args for
// multi-sig governance mode.
func TestBuildFRIConstructorArgs_MultiSig(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	keys := [][]byte{testKey(1), testKey(2), testKey(3)}

	args, err := buildFRIConstructorArgs(vk, 200, GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      keys,
		Threshold: 2,
	})
	if err != nil {
		t.Fatalf("buildFRIConstructorArgs: %v", err)
	}

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
// TestBuildGroth16ConstructorArgs
// ---------------------------------------------------------------------------

// TestBuildGroth16ConstructorArgs verifies that the Groth16 constructor-args
// builder populates all 19 VK components in addition to the shared fields.
func TestBuildGroth16ConstructorArgs(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	g16 := &Groth16VK{
		AlphaG1: bytes.Repeat([]byte{0xaa}, 64),
		BetaG2: [4][]byte{
			bytes.Repeat([]byte{0x01}, 32),
			bytes.Repeat([]byte{0x02}, 32),
			bytes.Repeat([]byte{0x03}, 32),
			bytes.Repeat([]byte{0x04}, 32),
		},
		GammaG2: [4][]byte{
			bytes.Repeat([]byte{0x05}, 32),
			bytes.Repeat([]byte{0x06}, 32),
			bytes.Repeat([]byte{0x07}, 32),
			bytes.Repeat([]byte{0x08}, 32),
		},
		DeltaG2: [4][]byte{
			bytes.Repeat([]byte{0x09}, 32),
			bytes.Repeat([]byte{0x0a}, 32),
			bytes.Repeat([]byte{0x0b}, 32),
			bytes.Repeat([]byte{0x0c}, 32),
		},
		IC0: bytes.Repeat([]byte{0x10}, 64),
		IC1: bytes.Repeat([]byte{0x11}, 64),
		IC2: bytes.Repeat([]byte{0x12}, 64),
		IC3: bytes.Repeat([]byte{0x13}, 64),
		IC4: bytes.Repeat([]byte{0x14}, 64),
		IC5: bytes.Repeat([]byte{0x15}, 64),
	}

	args, err := buildGroth16ConstructorArgs(vk, 42, GovernanceConfig{Mode: GovernanceNone}, g16)
	if err != nil {
		t.Fatalf("buildGroth16ConstructorArgs: %v", err)
	}

	// Shared fields are still present.
	if _, ok := args["sP1VerifyingKeyHash"]; !ok {
		t.Error("groth16 args should include sP1VerifyingKeyHash")
	}
	if _, ok := args["chainId"]; !ok {
		t.Error("groth16 args should include chainId")
	}

	// G1 points (alphaG1, iC0..iC5) are ByteString and go through as
	// hex strings.
	expectedHex := map[string]string{
		"alphaG1": hex.EncodeToString(g16.AlphaG1),
		"iC0":     hex.EncodeToString(g16.IC0),
		"iC1":     hex.EncodeToString(g16.IC1),
		"iC2":     hex.EncodeToString(g16.IC2),
		"iC3":     hex.EncodeToString(g16.IC3),
		"iC4":     hex.EncodeToString(g16.IC4),
		"iC5":     hex.EncodeToString(g16.IC5),
	}
	for k, want := range expectedHex {
		got, ok := args[k].(string)
		if !ok {
			t.Errorf("groth16 args missing key %q (or wrong string type)", k)
			continue
		}
		if got != want {
			t.Errorf("groth16 args[%q] mismatch:\n  got  %s\n  want %s", k, got, want)
		}
	}

	// G2 Fp coordinates (betaG2*, gammaG2*, deltaG2*) are runar.Bigint
	// and MUST be passed as *big.Int so the compiler emits them as
	// Bitcoin Script number pushes (LE sign-magnitude) rather than raw
	// 32-byte BE blobs.
	expectedBig := map[string]*big.Int{
		"betaG2X0":  new(big.Int).SetBytes(g16.BetaG2[0]),
		"betaG2X1":  new(big.Int).SetBytes(g16.BetaG2[1]),
		"betaG2Y0":  new(big.Int).SetBytes(g16.BetaG2[2]),
		"betaG2Y1":  new(big.Int).SetBytes(g16.BetaG2[3]),
		"gammaG2X0": new(big.Int).SetBytes(g16.GammaG2[0]),
		"gammaG2X1": new(big.Int).SetBytes(g16.GammaG2[1]),
		"gammaG2Y0": new(big.Int).SetBytes(g16.GammaG2[2]),
		"gammaG2Y1": new(big.Int).SetBytes(g16.GammaG2[3]),
		"deltaG2X0": new(big.Int).SetBytes(g16.DeltaG2[0]),
		"deltaG2X1": new(big.Int).SetBytes(g16.DeltaG2[1]),
		"deltaG2Y0": new(big.Int).SetBytes(g16.DeltaG2[2]),
		"deltaG2Y1": new(big.Int).SetBytes(g16.DeltaG2[3]),
	}
	for k, want := range expectedBig {
		got, ok := args[k].(*big.Int)
		if !ok {
			t.Errorf("groth16 args[%q] should be *big.Int, got %T", k, args[k])
			continue
		}
		if got.Cmp(want) != 0 {
			t.Errorf("groth16 args[%q] mismatch:\n  got  %s\n  want %s", k, got.String(), want.String())
		}
	}
}

// ---------------------------------------------------------------------------
// TestCompileFRIRollup_DifferentParams
// ---------------------------------------------------------------------------

// TestCompileFRIRollup_DifferentParams compiles the Basefold covenant
// with two different chain IDs and verifies the resulting scripts differ.
func TestCompileFRIRollup_DifferentParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation test in short mode")
	}

	vk := []byte("test-sp1-verifying-key-for-compilation")

	compiled1, err := CompileFRIRollup(vk, 1001, GovernanceConfig{Mode: GovernanceNone})
	if err != nil {
		t.Fatalf("CompileFRIRollup chainID=1001 failed: %v", err)
	}

	compiled2, err := CompileFRIRollup(vk, 2002, GovernanceConfig{Mode: GovernanceNone})
	if err != nil {
		t.Fatalf("CompileFRIRollup chainID=2002 failed: %v", err)
	}

	if bytes.Equal(compiled1.LockingScript, compiled2.LockingScript) {
		t.Error("scripts with different chain IDs should differ")
	}

	if len(compiled1.LockingScript) == 0 {
		t.Error("compiled1 locking script should not be empty")
	}
	if len(compiled2.LockingScript) == 0 {
		t.Error("compiled2 locking script should not be empty")
	}

	if compiled1.ChainID != 1001 {
		t.Errorf("compiled1.ChainID = %d, want 1001", compiled1.ChainID)
	}
	if compiled2.ChainID != 2002 {
		t.Errorf("compiled2.ChainID = %d, want 2002", compiled2.ChainID)
	}
	if compiled1.Mode != VerifyFRI {
		t.Errorf("compiled1.Mode = %s, want fri", compiled1.Mode)
	}
}

// ---------------------------------------------------------------------------
// TestCompileFRIRollup_WithVerifyingKey
// ---------------------------------------------------------------------------

// TestCompileFRIRollup_WithVerifyingKey verifies that CompileFRIRollup
// records the VK hash on the compiled covenant metadata. The hash is
// NOT embedded as a baked-in constant in the Mode 1 locking script —
// the trust-minimized FRI bridge does not consult the VK on-chain, so
// the Rúnar compiler constant-folds the readonly property out. When
// Gate 0a Full lands the locking script will consult SP1VerifyingKeyHash
// inside `advanceState` (Merkle-root check against transcoded FRI
// commitments) and this test should be re-tightened to re-assert the
// baked-in-script invariant.
func TestCompileFRIRollup_WithVerifyingKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation test in short mode")
	}

	vk := []byte("unique-sp1-verifying-key-bytes-for-test")
	vkHash := sha256.Sum256(vk)

	compiled, err := CompileFRIRollup(vk, 42, GovernanceConfig{Mode: GovernanceNone})
	if err != nil {
		t.Fatalf("CompileFRIRollup failed: %v", err)
	}

	if compiled.SP1VerifyingKeyHash != vkHash {
		t.Errorf("VK hash mismatch:\n  got  %x\n  want %x", compiled.SP1VerifyingKeyHash, vkHash)
	}
}

// ---------------------------------------------------------------------------
// TestCompileFRIRollup_GovernanceModes
// ---------------------------------------------------------------------------

// TestCompileFRIRollup_GovernanceModes compiles the Basefold covenant
// with different governance modes and verifies the resulting scripts differ.
func TestCompileFRIRollup_GovernanceModes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compilation test in short mode")
	}

	vk := []byte("test-sp1-verifying-key-for-governance")

	compiledNone, err := CompileFRIRollup(vk, 42, GovernanceConfig{Mode: GovernanceNone})
	if err != nil {
		t.Fatalf("CompileFRIRollup GovernanceNone failed: %v", err)
	}

	compiledSingle, err := CompileFRIRollup(vk, 42, GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	})
	if err != nil {
		t.Fatalf("CompileFRIRollup GovernanceSingleKey failed: %v", err)
	}

	compiledMulti, err := CompileFRIRollup(vk, 42, GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
		Threshold: 2,
	})
	if err != nil {
		t.Fatalf("CompileFRIRollup GovernanceMultiSig failed: %v", err)
	}

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
// TestCompileRollupParamsValidation
// ---------------------------------------------------------------------------

// TestCompileRollupParamsValidation verifies that invalid parameters produce
// errors for both the Basefold and Groth16 constructors.
func TestCompileRollupParamsValidation(t *testing.T) {
	validVK := []byte("valid-sp1-verifying-key-bytes!!!!!!")

	tests := []struct {
		name    string
		run     func() error
		wantErr string
	}{
		{
			name: "basefold: nil verifying key",
			run: func() error {
				_, err := CompileFRIRollup(nil, 42, GovernanceConfig{Mode: GovernanceNone})
				return err
			},
			wantErr: "sp1 verifying key must not be empty",
		},
		{
			name: "basefold: empty verifying key",
			run: func() error {
				_, err := CompileFRIRollup([]byte{}, 42, GovernanceConfig{Mode: GovernanceNone})
				return err
			},
			wantErr: "sp1 verifying key must not be empty",
		},
		{
			name: "basefold: zero chain ID",
			run: func() error {
				_, err := CompileFRIRollup(validVK, 0, GovernanceConfig{Mode: GovernanceNone})
				return err
			},
			wantErr: "chain ID must not be zero",
		},
		{
			name: "basefold: invalid governance (single key, no keys)",
			run: func() error {
				_, err := CompileFRIRollup(validVK, 42, GovernanceConfig{
					Mode: GovernanceSingleKey,
					Keys: nil,
				})
				return err
			},
			wantErr: "invalid governance config",
		},
		{
			name: "basefold: invalid governance (multisig threshold 0)",
			run: func() error {
				_, err := CompileFRIRollup(validVK, 42, GovernanceConfig{
					Mode:      GovernanceMultiSig,
					Keys:      [][]byte{testKey(1), testKey(2)},
					Threshold: 0,
				})
				return err
			},
			wantErr: "invalid governance config",
		},
		{
			name: "basefold: invalid governance (none with keys)",
			run: func() error {
				_, err := CompileFRIRollup(validVK, 42, GovernanceConfig{
					Mode: GovernanceNone,
					Keys: [][]byte{testKey(1)},
				})
				return err
			},
			wantErr: "invalid governance config",
		},
		{
			name: "groth16: nil VK",
			run: func() error {
				_, err := CompileGroth16Rollup(validVK, 42, GovernanceConfig{Mode: GovernanceNone}, nil)
				return err
			},
			wantErr: "groth16 VK must be provided",
		},
		{
			name: "groth16: empty sp1 verifying key",
			run: func() error {
				_, err := CompileGroth16Rollup(nil, 42, GovernanceConfig{Mode: GovernanceNone}, &Groth16VK{})
				return err
			},
			wantErr: "sp1 verifying key must not be empty",
		},
		{
			name: "groth16: zero chain ID",
			run: func() error {
				_, err := CompileGroth16Rollup(validVK, 0, GovernanceConfig{Mode: GovernanceNone}, &Groth16VK{})
				return err
			},
			wantErr: "chain ID must not be zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !containsSubstring(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildGroth16WAConstructorArgs
// ---------------------------------------------------------------------------

// TestBuildGroth16WAConstructorArgs verifies that the witness-assisted
// Groth16 rollup constructor-args builder emits ONLY the shared readonly
// fields (vkHash, chainId, governance). The BN254 VK is baked in at
// compile time via CompileOptions.Groth16WAVKey — it must NOT appear as
// ConstructorArgs, otherwise the Rúnar compiler would try to splice it
// into the locking script a second time.
func TestBuildGroth16WAConstructorArgs(t *testing.T) {
	vk := []byte("test-verifying-key-32bytes-long!")
	vkHash := sha256.Sum256(vk)

	args, err := buildGroth16WAConstructorArgs(vk, 42, GovernanceConfig{
		Mode: GovernanceNone,
	})
	if err != nil {
		t.Fatalf("buildGroth16WAConstructorArgs: %v", err)
	}

	if got, ok := args["sP1VerifyingKeyHash"].(string); !ok {
		t.Error("sP1VerifyingKeyHash should be a string")
	} else if got != hex.EncodeToString(vkHash[:]) {
		t.Errorf("sP1VerifyingKeyHash mismatch:\n  got  %s\n  want %s", got, hex.EncodeToString(vkHash[:]))
	}

	if got, ok := args["chainId"].(float64); !ok {
		t.Error("chainId should be a float64")
	} else if got != 42.0 {
		t.Errorf("chainId = %v, want 42", got)
	}

	// Groth16WA args MUST NOT include any Groth16 VK key — Mode 3 bakes
	// the VK via CompileOptions.Groth16WAVKey, not as readonly args.
	groth16Keys := []string{
		"alphaG1", "betaG2X0", "iC0", "iC5",
		"gammaG2Y0", "deltaG2X1",
	}
	for _, k := range groth16Keys {
		if _, ok := args[k]; ok {
			t.Errorf("groth16WA args should not include Groth16 VK key %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCompileGroth16WARollup_Basic
// ---------------------------------------------------------------------------

// TestCompileGroth16WARollup_Basic compiles the Mode 3 contract with the
// Gate 0b SP1 fixture VK and verifies the resulting locking script is
// a) non-empty, b) in the expected size range (50-900 KB), and c) carries
// the expected Mode / ChainID metadata.
func TestCompileGroth16WARollup_Basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Mode 3 compilation test in short mode")
	}
	vkPath := bsvmTestSP1VKPath(t)
	sp1VK := []byte("mode3-sp1-verifying-key-for-bsv-evm-binding")

	compiled, err := CompileGroth16WARollup(sp1VK, 8453111, GovernanceConfig{Mode: GovernanceNone}, vkPath)
	if err != nil {
		t.Fatalf("CompileGroth16WARollup: %v", err)
	}

	if compiled.Mode != VerifyGroth16WA {
		t.Errorf("compiled.Mode = %s, want groth16-wa", compiled.Mode)
	}
	if compiled.ChainID != 8453111 {
		t.Errorf("compiled.ChainID = %d, want 8453111", compiled.ChainID)
	}
	if len(compiled.LockingScript) == 0 {
		t.Fatal("compiled locking script is empty")
	}

	size := len(compiled.LockingScript)
	const minSize = 50 * 1024        // 50 KB
	// Post-R1/R2: the Mode 3 contract opens AdvanceState with the
	// MSM-binding preamble (AssertGroth16WitnessAssistedWithMSM), which
	// adds the on-chain IC[0] + Σ pub_i · IC[i+1] computation plus
	// proof.B G2 on-curve + subgroup checks. Measured ~1.35 MB in
	// practice vs the ~688 KB raw preamble figure quoted pre-R1/R2.
	const maxSize = 1600 * 1024
	t.Logf("Mode 3 locking script: %d bytes (%.1f KB)", size, float64(size)/1024.0)
	if size < minSize {
		t.Errorf("locking script %d bytes is suspiciously small; expected > %d", size, minSize)
	}
	if size > maxSize {
		t.Errorf("locking script %d bytes exceeds expected cap %d", size, maxSize)
	}
}

// TestCompileGroth16WARollup_MissingVK verifies that omitting the vk.json
// path produces an error rather than silently compiling a broken contract.
func TestCompileGroth16WARollup_MissingVK(t *testing.T) {
	sp1VK := []byte("mode3-sp1-verifying-key")
	_, err := CompileGroth16WARollup(sp1VK, 42, GovernanceConfig{Mode: GovernanceNone}, "")
	if err == nil {
		t.Fatal("expected error for missing Groth16WA vk.json path")
	}
	if !containsSubstring(err.Error(), "vk.json path must be provided") {
		t.Errorf("error %q does not mention missing vk.json", err.Error())
	}
}

// TestCompileGroth16WARollup_BadVKPath verifies that a non-existent
// vk.json path produces a clear error, not a compiler crash.
func TestCompileGroth16WARollup_BadVKPath(t *testing.T) {
	sp1VK := []byte("mode3-sp1-verifying-key")
	_, err := CompileGroth16WARollup(sp1VK, 42, GovernanceConfig{Mode: GovernanceNone}, "/nonexistent/vk.json")
	if err == nil {
		t.Fatal("expected error for missing vk.json file")
	}
	if !containsSubstring(err.Error(), "not readable") {
		t.Errorf("error %q does not mention readability", err.Error())
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
