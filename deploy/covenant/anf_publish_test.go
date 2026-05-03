// anf_publish_test.go — unit tests for the ANF inscription path.
//
// Pure-Go: no BSV node, no ARC, no signing. The publish-side tests
// gate on BSVM_TESTNET=1 (see test/integration/rotate_vk_test.go for
// the integration counterpart).
package covenantdeploy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/covenant/anf"
)

// fixtureCompileResult fabricates a CompileResult that does NOT
// require running the runar-go compiler. The script bytes are
// arbitrary but stable; the test asserts on shape, not on
// cryptographic validity.
func fixtureCompileResult() *CompileResult {
	return &CompileResult{
		BridgeScript: []byte{0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef},
		RollupScript: []byte{0x76, 0xa9, 0x14, 0xca, 0xfe, 0xba, 0xbe},
		RollupANF:    json.RawMessage(`{"contractName":"R","properties":[],"methods":[]}`),
		BridgeANF:    json.RawMessage(`{"contractName":"B","properties":[],"methods":[]}`),
		VKHashHex:    "0x0089e86b40471ffbca344ddd6e02c4aade8d2d1676cbab381a6bedc726c964e7",
		VKHashSource: "/tmp/SP1VerifyingKeyHash.txt",
		GovConfig: covenant.GovernanceConfig{
			Mode: covenant.GovernanceSingleKey,
		},
		Mode: covenant.VerifyFRI,
	}
}

func fixtureOperatorConfig() *OperatorConfig {
	return &OperatorConfig{
		ShardID:          "test-shard",
		ChainID:          8453111,
		VerificationMode: "fri",
		Governance: OperatorGovernance{
			Mode: "single_key",
			Keys: []string{
				"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			},
		},
		CovenantSats: covenant.DefaultCovenantSats,
	}
}

// TestBuildANFDocument_Genesis asserts the genesis-kind document
// includes both bridge AND rollup bindings.
func TestBuildANFDocument_Genesis(t *testing.T) {
	cfg := fixtureOperatorConfig()
	res := fixtureCompileResult()
	doc, raw, err := BuildANFDocument(cfg, res, ANFOptions{
		Kind:        anf.KindGenesis,
		GeneratedAt: time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("BuildANFDocument: %v", err)
	}
	if doc.Kind != anf.KindGenesis {
		t.Errorf("kind = %s, want genesis", doc.Kind)
	}
	if doc.Bridge == nil {
		t.Fatal("bridge binding is nil for genesis kind")
	}
	if doc.Rollup.ScriptHex == "" {
		t.Fatal("rollup ScriptHex empty")
	}
	if len(raw) == 0 {
		t.Fatal("canonical JSON is empty")
	}

	// Round-trip JSON check.
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal canonical: %v", err)
	}
	for _, key := range []string{
		"schema", "kind", "shardId", "chainId",
		"verification", "governance", "rollup", "bridge",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("canonical JSON missing key %q", key)
		}
	}
}

// TestBuildANFDocument_Rotation asserts the rotation-kind document
// omits the bridge binding by default.
func TestBuildANFDocument_Rotation(t *testing.T) {
	cfg := fixtureOperatorConfig()
	res := fixtureCompileResult()
	doc, _, err := BuildANFDocument(cfg, res, ANFOptions{
		Kind: anf.KindRotation,
	})
	if err != nil {
		t.Fatalf("BuildANFDocument: %v", err)
	}
	if doc.Kind != anf.KindRotation {
		t.Errorf("kind = %s, want rotation", doc.Kind)
	}
	if doc.Bridge != nil {
		t.Errorf("bridge binding should be nil for rotation kind, got %+v", doc.Bridge)
	}
}

// TestBuildANFDocument_HashStability asserts that two builds at
// different timestamps but otherwise identical inputs yield the same
// hash IF GeneratedAt is fixed. This is the property operators rely
// on when comparing dry-run hashes against the on-chain commitment.
func TestBuildANFDocument_HashStability(t *testing.T) {
	cfg := fixtureOperatorConfig()
	res := fixtureCompileResult()

	hashA, err := ANFDocumentHash(cfg, res, ANFOptions{
		Kind:        anf.KindRotation,
		GeneratedAt: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ANFDocumentHash A: %v", err)
	}
	hashB, err := ANFDocumentHash(cfg, res, ANFOptions{
		Kind:        anf.KindRotation,
		GeneratedAt: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ANFDocumentHash B: %v", err)
	}
	if hashA != hashB {
		t.Errorf("hashA != hashB: %x vs %x", hashA, hashB)
	}

	// And changing the timestamp DOES change the hash (cosmetic field
	// is part of the canonical bytes — operators must treat the dry-run
	// hash as bound to that exact timestamp).
	hashC, err := ANFDocumentHash(cfg, res, ANFOptions{
		Kind:        anf.KindRotation,
		GeneratedAt: time.Date(2026, 5, 3, 13, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ANFDocumentHash C: %v", err)
	}
	if hashA == hashC {
		t.Error("expected different hashes for different timestamps")
	}
}

// TestBuildANFDocument_GovernanceKeyOrderAgnostic asserts that
// re-ordering the operator's governance keys does not change the
// document hash — SortedHexKeys re-orders them at build time.
func TestBuildANFDocument_GovernanceKeyOrderAgnostic(t *testing.T) {
	cfg := fixtureOperatorConfig()
	cfg.Governance.Mode = "multisig"
	cfg.Governance.Threshold = 2
	cfg.Governance.Keys = []string{
		"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
	}
	res := fixtureCompileResult()
	when := time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC)
	hAB, err := ANFDocumentHash(cfg, res, ANFOptions{Kind: anf.KindRotation, GeneratedAt: when})
	if err != nil {
		t.Fatalf("hash AB: %v", err)
	}

	cfg.Governance.Keys = []string{
		"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	}
	hBA, err := ANFDocumentHash(cfg, res, ANFOptions{Kind: anf.KindRotation, GeneratedAt: when})
	if err != nil {
		t.Fatalf("hash BA: %v", err)
	}
	if hAB != hBA {
		t.Errorf("expected key-order-agnostic hash; got %x vs %x", hAB, hBA)
	}
}

// TestBuildANFDocument_RejectsNilInputs asserts the helper validates
// its inputs.
func TestBuildANFDocument_RejectsNilInputs(t *testing.T) {
	if _, _, err := BuildANFDocument(nil, fixtureCompileResult(), ANFOptions{}); err == nil {
		t.Error("expected error on nil cfg")
	}
	if _, _, err := BuildANFDocument(fixtureOperatorConfig(), nil, ANFOptions{}); err == nil {
		t.Error("expected error on nil res")
	}
	if _, _, err := BuildANFDocument(fixtureOperatorConfig(), &CompileResult{}, ANFOptions{}); err == nil {
		t.Error("expected error on empty rollup script")
	}
}

// TestPublishANFDocument_RejectsMissingConfig asserts the publish
// helper refuses to broadcast without the required config fields.
func TestPublishANFDocument_RejectsMissingConfig(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *OperatorConfig)
		wantSub string
	}{
		{"no arc", func(c *OperatorConfig) { c.ARCEndpoint = "" }, "arcEndpoint"},
		{"no key", func(c *OperatorConfig) { c.DeployerKeyFile = "" }, "deployerKeyFile"},
		{"no funding", func(c *OperatorConfig) { c.FundingTxID = "" }, "funding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fixtureOperatorConfig()
			cfg.ARCEndpoint = "https://arc.fake.invalid"
			cfg.DeployerKeyFile = "/dev/null"
			cfg.FundingTxID = strings.Repeat("11", 32)
			cfg.FundingScriptHex = "76a914000000000000000000000000000000000000000088ac"
			cfg.FundingSats = 100000
			tc.mutate(cfg)
			_, err := PublishANFDocument(nil, cfg, []byte("{}"))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}

	// Empty canonical bytes also fail.
	cfg := fixtureOperatorConfig()
	cfg.ARCEndpoint = "https://arc.fake.invalid"
	cfg.DeployerKeyFile = "/dev/null"
	cfg.FundingTxID = strings.Repeat("11", 32)
	cfg.FundingScriptHex = "76a914000000000000000000000000000000000000000088ac"
	cfg.FundingSats = 100000
	if _, err := PublishANFDocument(nil, cfg, nil); err == nil {
		t.Error("expected error on empty canonical bytes")
	}
}

// TestANFDocument_HexHashMatchesCanonical asserts that
// covenantanf.HexHash256(canonical) == hex.EncodeToString(hash[:])
// of the value the rotate-vk path bakes into the on-chain
// UpgradeRequest. Locks down the cross-package invariant the on-chain
// observer relies on.
func TestANFDocument_HexHashMatchesCanonical(t *testing.T) {
	cfg := fixtureOperatorConfig()
	res := fixtureCompileResult()
	when := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	doc, raw, err := BuildANFDocument(cfg, res, ANFOptions{
		Kind:        anf.KindRotation,
		GeneratedAt: when,
	})
	if err != nil {
		t.Fatalf("BuildANFDocument: %v", err)
	}
	hashViaDoc, err := doc.ComputeHash()
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	hashViaRaw := anf.Hash256(raw)
	if hashViaDoc != hashViaRaw {
		t.Errorf("doc.ComputeHash != Hash256(raw): %x vs %x", hashViaDoc, hashViaRaw)
	}
	hashViaHelper, err := ANFDocumentHash(cfg, res, ANFOptions{
		Kind:        anf.KindRotation,
		GeneratedAt: when,
	})
	if err != nil {
		t.Fatalf("ANFDocumentHash: %v", err)
	}
	if hashViaHelper != hashViaDoc {
		t.Errorf("ANFDocumentHash != doc.ComputeHash: %x vs %x", hashViaHelper, hashViaDoc)
	}
	hexExpected := hex.EncodeToString(hashViaDoc[:])
	if hexExpected != anf.HexHash256(raw) {
		t.Errorf("HexHash256 mismatch: %s vs %s", hexExpected, anf.HexHash256(raw))
	}
}

// TestWriteANFDocument_AddsTrailingNewline asserts the on-disk form
// has a trailing newline (shell-tooling friendliness).
func TestWriteANFDocument_AddsTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/doc.json"
	canonical := []byte(`{"hello":"world"}`)
	if err := WriteANFDocument(path, canonical); err != nil {
		t.Fatalf("WriteANFDocument: %v", err)
	}
	got, err := readFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte("\n")) {
		t.Errorf("written file does not end in newline")
	}
	// The canonical bytes must be present unmodified.
	if !bytes.HasPrefix(got, canonical) {
		t.Errorf("written file does not start with canonical bytes; got %q", got)
	}
}

// readFile is a tiny test-only file-read helper.
func readFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path)
}
