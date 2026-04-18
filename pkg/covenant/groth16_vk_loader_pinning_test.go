package covenant

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// F06 VK pinning coverage across all three VKTrustPolicy branches plus
// compile-glue rejection and genesis-level guardrails.

func gate0VKPathForPinningTest(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "sp1", "sp1_groth16_vk.json")
}

// writeTempVKClone copies the gate0 fixture into a temporary directory
// after perturbing the file so its sha256 differs from the pinned entry.
func writeTempVKClone(t *testing.T, modifyTail bool) string {
	t.Helper()
	src := gate0VKPathForPinningTest(t)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read gate0 fixture: %v", err)
	}
	if modifyTail {
		// Appending whitespace perturbs the sha256 without breaking JSON.
		raw = append(raw, '\n')
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "vk_clone.json")
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatalf("write clone: %v", err)
	}
	return dst
}

// TestVKPinning_Gate0Fixture_AcceptsPinnedVK — positive control.
func TestVKPinning_Gate0Fixture_AcceptsPinnedVK(t *testing.T) {
	path := gate0VKPathForPinningTest(t)
	if err := VerifyPinnedVKHash(path, VKTrustPolicyGate0Fixture); err != nil {
		t.Fatalf("VerifyPinnedVKHash gate0: %v", err)
	}
	vk, err := LoadSP1Groth16VKPinned(path, VKTrustPolicyGate0Fixture)
	if err != nil {
		t.Fatalf("LoadSP1Groth16VKPinned gate0: %v", err)
	}
	if vk == nil {
		t.Fatal("expected non-nil VK")
	}
}

// TestVKPinning_Gate0Fixture_RejectsPerturbedVK — load-bearing negative.
// A file that parses cleanly but sha256-differs must be refused.
func TestVKPinning_Gate0Fixture_RejectsPerturbedVK(t *testing.T) {
	path := writeTempVKClone(t, true)
	err := VerifyPinnedVKHash(path, VKTrustPolicyGate0Fixture)
	if err == nil {
		t.Fatal("expected rejection of perturbed VK under Gate0 policy")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("expected sha256 mismatch error, got: %v", err)
	}
}

// TestVKPinning_Gate0Fixture_MatchesHashConstant guards against drift
// between the pinned constant and the on-disk fixture.
func TestVKPinning_Gate0Fixture_MatchesHashConstant(t *testing.T) {
	raw, err := os.ReadFile(gate0VKPathForPinningTest(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got := sha256.Sum256(raw)
	want, ok := PinnedSP1Groth16VKHashes["gate0-fixture"]
	if !ok {
		t.Fatal("PinnedSP1Groth16VKHashes missing gate0-fixture entry")
	}
	if !bytes.Equal(got[:], want[:]) {
		t.Errorf("gate0 fixture sha256 drift:\n  got  %x\n  want %x", got, want)
	}
}

// TestVKPinning_Mainnet_RejectsGate0Fixture is the mainnet guardrail.
// The gate0 fixture is NOT from a real ceremony.
func TestVKPinning_Mainnet_RejectsGate0Fixture(t *testing.T) {
	path := gate0VKPathForPinningTest(t)
	err := VerifyPinnedVKHash(path, VKTrustPolicyMainnet)
	if err == nil {
		t.Fatal("expected rejection of gate0 fixture under Mainnet policy")
	}
	if !strings.Contains(err.Error(), "not in PinnedSP1Groth16VKHashes for mainnet policy") {
		t.Errorf("expected mainnet policy error, got: %v", err)
	}
}

// TestVKPinning_Mainnet_RejectsRandomFile ensures random bytes cannot
// reach mainnet compile.
func TestVKPinning_Mainnet_RejectsRandomFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "random.json")
	if err := os.WriteFile(path, []byte(`{"not":"a","real":"vk"}`), 0o644); err != nil {
		t.Fatalf("write random: %v", err)
	}
	if err := VerifyPinnedVKHash(path, VKTrustPolicyMainnet); err == nil {
		t.Fatal("expected rejection of random file under Mainnet policy")
	}
}

// TestVKPinning_AllowUnpinned_AcceptsGate0 — historical permissive path.
func TestVKPinning_AllowUnpinned_AcceptsGate0(t *testing.T) {
	path := gate0VKPathForPinningTest(t)
	if err := VerifyPinnedVKHash(path, VKTrustPolicyAllowUnpinned); err != nil {
		t.Fatalf("AllowUnpinned policy should never reject: %v", err)
	}
}

// TestVKPinning_AllowUnpinned_AcceptsPerturbed confirms the unpinned
// policy skips the sha256 check.
func TestVKPinning_AllowUnpinned_AcceptsPerturbed(t *testing.T) {
	path := writeTempVKClone(t, true)
	if err := VerifyPinnedVKHash(path, VKTrustPolicyAllowUnpinned); err != nil {
		t.Fatalf("AllowUnpinned policy rejected: %v", err)
	}
}

// TestCompileGroth16WARollupPinned_RejectsMainnetUnpinnedVK verifies the
// compile-path integration of F06: a gate0 fixture under Mainnet policy
// must fail at the pinning step, never invoking Rúnar.
func TestCompileGroth16WARollupPinned_RejectsMainnetUnpinnedVK(t *testing.T) {
	vkPath := gate0VKPathForPinningTest(t)
	_, err := CompileGroth16WARollupPinned(
		[]byte("test-sp1-vk"),
		42,
		GovernanceConfig{Mode: GovernanceNone},
		vkPath,
		VKTrustPolicyMainnet,
	)
	if err == nil {
		t.Fatal("expected mainnet policy to reject gate0 fixture at compile")
	}
	if !strings.Contains(err.Error(), "pinning check") {
		t.Errorf("expected pinning error, got: %v", err)
	}
}

// TestPrepareGenesis_MainnetAllowsMode3UnderPinnedPolicy pins that the
// old mainnet block on Mode 3 (keyed on F02 / F03 / F01 codegen TODOs)
// has been lifted now that Rúnar R1 + R1b + R2 landed. Mode 3 under
// mainnet + pinned VK is now a successful genesis — a mismatched
// ceremony hash will still fail at the pinning check (see
// TestCompileGroth16WARollupPinned_RejectsMainnetUnpinnedVK).
func TestPrepareGenesis_MainnetAllowsMode3UnderPinnedPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles Mode 3 contract (slow)")
	}
	vkPath := gate0VKPathForPinningTest(t)
	cfg := &GenesisConfig{
		ChainID:         1,
		SP1VerifyingKey: []byte("vk"),
		Governance:      GovernanceConfig{Mode: GovernanceNone},
		Verification:    VerifyGroth16WA,
		Groth16WAVKPath: vkPath,
		// Gate0 policy matches the gate0 fixture sha256 — this succeeds.
		// Real mainnet would use VKTrustPolicyMainnet with a reviewed
		// ceremony allowlist entry.
		VKTrustPolicy: VKTrustPolicyGate0Fixture,
		Mainnet:       false,
	}
	_, err := PrepareGenesis(cfg)
	if err != nil {
		t.Fatalf("expected Mode 3 genesis to succeed under Gate0 policy, got: %v", err)
	}
}

// TestPrepareGenesis_MainnetRequiresMainnetPolicy verifies a mainnet
// shard cannot be compiled with VKTrustPolicyAllowUnpinned.
func TestPrepareGenesis_MainnetRequiresMainnetPolicy(t *testing.T) {
	vkPath := gate0VKPathForPinningTest(t)
	cfg := &GenesisConfig{
		ChainID:         1,
		SP1VerifyingKey: []byte("vk"),
		Governance:      GovernanceConfig{Mode: GovernanceNone},
		Verification:    VerifyGroth16WA,
		Groth16WAVKPath: vkPath,
		VKTrustPolicy:   VKTrustPolicyAllowUnpinned,
		Mainnet:         true,
	}
	_, err := PrepareGenesis(cfg)
	if err == nil {
		t.Fatal("expected mainnet to reject non-mainnet policy")
	}
	if !strings.Contains(err.Error(), "VKTrustPolicy=Mainnet") {
		t.Errorf("expected policy error, got: %v", err)
	}
}
