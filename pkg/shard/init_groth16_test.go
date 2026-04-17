package shard

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/covenant"
)

// TestInitShard_Groth16_MissingVK verifies that calling InitShard with
// Verification=VerifyGroth16 and no Groth16 VK produces an error. This
// surfaces a structural gap in InitShardParams: there is currently no
// way to plumb a Groth16VK through — so Groth16 mode can never be
// successfully initialized through the shard-layer API.
//
// Expected behaviour: PrepareGenesis reaches CompileGroth16Rollup with
// a nil VK and returns "groth16 VK must be provided".
func TestInitShard_Groth16_MissingVK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping InitShard Groth16 test in short mode")
	}

	dir := t.TempDir()

	_, _, err := InitShard(&InitShardParams{
		ChainID:         testChainID,
		DataDir:         dir,
		Governance:      covenant.GovernanceConfig{Mode: covenant.GovernanceNone},
		Verification:    covenant.VerifyGroth16,
		SP1VerifyingKey: []byte("test-vk"),
	})
	if err == nil {
		t.Fatal("expected error when Verification=VerifyGroth16 but InitShardParams has no Groth16VK field")
	}

	// The error must clearly communicate that the Groth16 VK is missing.
	if !strings.Contains(err.Error(), "groth16 VK must be provided") {
		t.Errorf("error %q should mention the missing Groth16 VK", err.Error())
	}
}

// TestInitShard_Groth16WA_MissingVKPath verifies that calling InitShard
// with Verification=VerifyGroth16WA and no Groth16WAVKPath produces a
// clear error. Same structural gap: InitShardParams has no way to plumb
// Groth16WAVKPath to the covenant layer.
func TestInitShard_Groth16WA_MissingVKPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping InitShard Groth16WA test in short mode")
	}

	dir := t.TempDir()

	_, _, err := InitShard(&InitShardParams{
		ChainID:         testChainID,
		DataDir:         dir,
		Governance:      covenant.GovernanceConfig{Mode: covenant.GovernanceNone},
		Verification:    covenant.VerifyGroth16WA,
		SP1VerifyingKey: []byte("test-vk"),
	})
	if err == nil {
		t.Fatal("expected error when Verification=VerifyGroth16WA but no Groth16WAVKPath is plumbed")
	}

	// The covenant-layer error for Groth16WA says the vk.json path must
	// be provided. Accept either the "must be provided" or "not readable"
	// wording in case future changes propagate the path differently.
	msg := err.Error()
	if !strings.Contains(msg, "vk.json path must be provided") && !strings.Contains(msg, "not readable") {
		t.Errorf("error %q should mention missing Groth16WA vk.json path", msg)
	}
}

// fixtureGroth16VKPath resolves the absolute path to the shared SP1
// Groth16 verification key fixture (tests/sp1/sp1_groth16_vk.json).
func fixtureGroth16VKPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "sp1", "sp1_groth16_vk.json")
}

// TestInitShard_Groth16_HappyPath_TODO exercises the full shard-level
// Groth16 init path: InitShard plumbs a *covenant.Groth16VK through to
// covenant.PrepareGenesis, which compiles the Groth16 rollup contract
// with the VK baked in as readonly constructor args.
//
// The test uses the shared SP1 Groth16 VK fixture
// (tests/sp1/sp1_groth16_vk.json) loaded via covenant.LoadSP1Groth16VK.
// Requires the Rúnar compiler, so it is skipped in -short mode.
func TestInitShard_Groth16_HappyPath_TODO(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping InitShard Groth16 happy-path test in short mode (requires runar compiler)")
	}

	vk, err := covenant.LoadSP1Groth16VK(fixtureGroth16VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1Groth16VK: %v", err)
	}

	dir := t.TempDir()
	cfg, header, err := InitShard(&InitShardParams{
		ChainID:         testChainID,
		DataDir:         dir,
		Governance:      covenant.GovernanceConfig{Mode: covenant.GovernanceNone},
		Verification:    covenant.VerifyGroth16,
		SP1VerifyingKey: []byte("test-vk"),
		Groth16VK:       vk,
	})
	if err != nil {
		t.Fatalf("InitShard: %v", err)
	}

	if cfg.VerificationMode != "groth16" {
		t.Errorf("VerificationMode: got %q, want %q", cfg.VerificationMode, "groth16")
	}
	if header.StateRoot.Hex() != cfg.GenesisStateRoot {
		t.Errorf("GenesisStateRoot %q != header.StateRoot %q", cfg.GenesisStateRoot, header.StateRoot.Hex())
	}
}
