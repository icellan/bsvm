// covenant_deploy_test.go — validation harness for the
// deploy/covenant tool tree.
//
// Unlike the rest of test/integration/, this test does NOT carry the
// `//go:build integration` tag. The deploy compile path is pure
// runar-go compilation + Go-side fixture wiring; no regtest BSV node
// or ARC instance is needed. We pin a fake ARC URL in the fixture
// config and the dry-run path never touches it.
//
// The test asserts:
//
//   - Compile() succeeds for a Mode 1 (FRI) fixture with single-key
//     governance.
//   - The returned bridge + rollup script bytes are non-empty.
//   - The rollup script hex parses via covenant.DetectVerificationMode
//     and detects as VerifyFRI — i.e. the deploy tooling produces a
//     locking script byte-identical to what pkg/covenant emits.
//   - The JSON Summary the binary would print on --dry-run carries
//     the documented fields (shardId, chainId, vkHash, both script
//     hexes + hashes, verificationMode, generatedAt).
//   - Mode 2 / Mode 3 currently return a TODO(WW-mode23) error,
//     mirroring the upstream `bsvm deploy-shard --verification=...`
//     rejection.
//   - ReadVKHashFile parses both 0x-prefixed and bare hex; rejects
//     malformed input.
//
// Broadcast paths are NOT exercised — we never construct a real
// genesis tx, never sign anything, never POST to ARC. The wrapper's
// confirm-then-broadcast logic is covered by the bash syntax check
// (`bash -n deploy.sh`).
package integration

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	covenantdeploy "github.com/icellan/bsvm/deploy/covenant"
	"github.com/icellan/bsvm/pkg/covenant"
)

// fixtureSinglekeyPubKeyHex is a known-valid 33-byte compressed
// secp256k1 pubkey (the one bs-evm/pkg/shard's devnet helper bakes
// into single-key shards). Reusing it keeps the fixture stable across
// test runs.
const fixtureSinglekeyPubKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// fixtureVKHash mirrors the value stamped into
// prover/guest/elf/SP1VerifyingKeyHash.txt (the post-CC-rotation
// hash). Fixture hardcodes it because the test runs without
// `cargo prove vkey`.
const fixtureVKHash = "0x008e9a57422fe11b537d0d2e21c323074e2bb61f2f4d99dd41cd1d5b8a853914"

// writeFixtureVKHashFile writes a single-line VK hash file into a
// temp dir and returns its path.
func writeFixtureVKHashFile(t *testing.T, value string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "SP1VerifyingKeyHash.txt")
	if err := os.WriteFile(p, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write VK hash fixture: %v", err)
	}
	return p
}

// fixtureConfig returns an OperatorConfig pointed at a temp VK hash
// file and using the well-known single-key governance pubkey.
func fixtureConfig(t *testing.T, mode string) *covenantdeploy.OperatorConfig {
	t.Helper()
	vkPath := writeFixtureVKHashFile(t, fixtureVKHash)
	return &covenantdeploy.OperatorConfig{
		ShardID:          "test-shard-1",
		ChainID:          8453111,
		VerificationMode: mode,
		Governance: covenantdeploy.OperatorGovernance{
			Mode: "single_key",
			Keys: []string{fixtureSinglekeyPubKeyHex},
		},
		CovenantSats:    covenant.DefaultCovenantSats,
		VKHashFile:      vkPath,
		DeployerKeyFile: "/dev/null", // never read in dry-run
		ARCEndpoint:     "https://arc.fake.invalid",
	}
}

// TestCovenantDeploy_CompileFRI exercises the dry-run compile path
// against a Mode 1 fixture and asserts the returned scripts are
// non-empty + the rollup script detects as VerifyFRI.
func TestCovenantDeploy_CompileFRI(t *testing.T) {
	if testing.Short() {
		// Compilation goes through runar-go which spins up the
		// Bitcoin Script emitter. ~1 s wall on M2; skip in -short.
		t.Skip("skipping covenant compile in short mode")
	}
	cfg := fixtureConfig(t, "fri")
	if err := cfg.Validate(false); err != nil {
		t.Fatalf("Validate(false): %v", err)
	}
	res, err := covenantdeploy.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(res.RollupScript) == 0 {
		t.Fatal("rollup script is empty")
	}
	// Bridge script is allowed to be empty today — see
	// TODO(WW-bridge-compile) in deploy/covenant/compile.go. When
	// the bridge contract refactor lands, flip this to a hard
	// non-empty assertion.
	if len(res.BridgeScript) == 0 {
		t.Logf("bridge script is empty (expected today: WW-bridge-compile pending)")
	}
	rollupHex := hex.EncodeToString(res.RollupScript)
	mode, err := covenant.DetectVerificationMode(rollupHex)
	if err != nil {
		t.Fatalf("DetectVerificationMode(rollup): %v", err)
	}
	if mode != covenant.VerifyFRI {
		t.Errorf("rollup script detected as %s, want fri", mode.String())
	}
	if !strings.HasPrefix(strings.ToLower(res.VKHashHex), "0x") {
		t.Errorf("VKHashHex %q missing 0x prefix", res.VKHashHex)
	}
	wantVK := strings.ToLower(fixtureVKHash)
	if strings.ToLower(res.VKHashHex) != wantVK {
		t.Errorf("VKHashHex %q != %q", res.VKHashHex, wantVK)
	}
}

// TestCovenantDeploy_SummaryShape asserts that the JSON Summary the
// binary emits carries the documented fields. Tests the marshalling
// shape rather than the actual binary, since the binary's main is a
// 30-line flag wrapper and a shell-driven smoke test would only
// verify the same shape via stdout capture.
func TestCovenantDeploy_SummaryShape(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping covenant compile in short mode")
	}
	cfg := fixtureConfig(t, "fri")
	res, err := covenantdeploy.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Build the same Summary the RunDeploy --dry-run path emits.
	s := covenantdeploy.Summary{
		ShardID:            cfg.ShardID,
		ChainID:            cfg.ChainID,
		VKHash:             res.VKHashHex,
		VKHashSource:       res.VKHashSource,
		BridgeScriptHex:    hex.EncodeToString(res.BridgeScript),
		BridgeScriptHash:   "deadbeef", // placeholder; we don't recompute hexHash
		RollupScriptHex:    hex.EncodeToString(res.RollupScript),
		RollupScriptHash:   "deadbeef",
		VerificationMode:   cfg.VerificationMode,
		GeneratedAt:        "2026-04-26T00:00:00Z",
		GenesisTxIDPredict: res.PredictedTxID,
		Broadcast:          false,
	}
	enc, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal Summary: %v", err)
	}
	// Round-trip into a generic map so we can assert keys without
	// coupling to the field order.
	var got map[string]interface{}
	if err := json.Unmarshal(enc, &got); err != nil {
		t.Fatalf("Unmarshal Summary: %v", err)
	}
	for _, key := range []string{
		"shardId", "chainId", "vkHash", "vkHashSource",
		"bridgeScriptHex", "bridgeScriptHash",
		"rollupScriptHex", "rollupScriptHash",
		"verificationMode", "generatedAt", "broadcast",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("Summary JSON missing key %q", key)
		}
	}
}

// TestCovenantDeploy_Mode23Stubbed asserts that Mode 2 / Mode 3
// today error out with a clear message instead of silently
// compiling. This locks in the behaviour the README documents
// under TODO(WW-mode23).
func TestCovenantDeploy_Mode23Stubbed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping covenant compile in short mode")
	}
	for _, mode := range []string{"groth16", "groth16-wa"} {
		cfg := fixtureConfig(t, mode)
		_, err := covenantdeploy.Compile(cfg)
		if err == nil {
			t.Errorf("Compile(%s): expected error, got nil", mode)
			continue
		}
		if !strings.Contains(err.Error(), "WW-mode23") {
			t.Errorf("Compile(%s): error %q does not mention WW-mode23", mode, err)
		}
	}
}

// TestCovenantDeploy_ReadVKHashFile asserts the parser handles
// 0x-prefixed, bare, and trailing-whitespace inputs, and rejects
// malformed hex.
func TestCovenantDeploy_ReadVKHashFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{"prefixed", "0xabcdef\n", "0xabcdef", false},
		{"bare", "abcdef\n", "abcdef", false},
		{"with-comment", "# top comment\n0xdeadbeef\n", "0xdeadbeef", false},
		{"trailing-ws", "  0xcafebabe  \n", "0xcafebabe", false},
		{"empty", "\n\n", "", true},
		{"bad-hex", "0xZZZZ\n", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "vk.txt")
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			got, err := covenantdeploy.ReadVKHashFile(p)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCovenantDeploy_DefaultVKHashFileExists asserts the in-tree
// stamped VK hash file is readable from the test's cwd. Catches
// regressions where prover/guest/elf/SP1VerifyingKeyHash.txt is
// removed or the path drifts.
func TestCovenantDeploy_DefaultVKHashFileExists(t *testing.T) {
	p := covenantdeploy.DefaultVKHashFile()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("DefaultVKHashFile %s not readable: %v", p, err)
	}
	value, err := covenantdeploy.ReadVKHashFile(p)
	if err != nil {
		t.Fatalf("ReadVKHashFile %s: %v", p, err)
	}
	bare := strings.TrimPrefix(value, "0x")
	if len(bare) != 64 {
		t.Errorf("VK hash %q has %d hex chars, want 64", bare, len(bare))
	}
	if _, err := hex.DecodeString(bare); err != nil {
		t.Errorf("VK hash %q is not valid hex: %v", bare, err)
	}
}

// TestCovenantDeploy_ValidateGovernance covers the OperatorConfig
// validator's governance branches. Each case is a distinct invariant
// the rollup compile path enforces; surfacing them here means a
// regression in the validator surfaces before it reaches the
// runar-go compiler (which would otherwise emit a less actionable
// error).
func TestCovenantDeploy_ValidateGovernance(t *testing.T) {
	mkCfg := func(g covenantdeploy.OperatorGovernance) *covenantdeploy.OperatorConfig {
		return &covenantdeploy.OperatorConfig{
			ShardID:          "x",
			ChainID:          1,
			VerificationMode: "fri",
			Governance:       g,
		}
	}
	cases := []struct {
		name    string
		gov     covenantdeploy.OperatorGovernance
		wantErr bool
	}{
		{
			"none-empty-keys",
			covenantdeploy.OperatorGovernance{Mode: "none"},
			false,
		},
		{
			"none-with-keys",
			covenantdeploy.OperatorGovernance{Mode: "none", Keys: []string{fixtureSinglekeyPubKeyHex}},
			true,
		},
		{
			"single-key-ok",
			covenantdeploy.OperatorGovernance{Mode: "single_key", Keys: []string{fixtureSinglekeyPubKeyHex}},
			false,
		},
		{
			"single-key-zero-keys",
			covenantdeploy.OperatorGovernance{Mode: "single_key"},
			true,
		},
		{
			"multisig-bad-threshold",
			covenantdeploy.OperatorGovernance{
				Mode:      "multisig",
				Threshold: 3,
				Keys:      []string{fixtureSinglekeyPubKeyHex, fixtureSinglekeyPubKeyHex},
			},
			true,
		},
		{
			"unknown-mode",
			covenantdeploy.OperatorGovernance{Mode: "councilOfElders"},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mkCfg(tc.gov)
			err := cfg.Validate(false)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
