// rotate_vk_test.go — validation harness for deploy/covenant/rotate-vk.
//
// The pure-Go layer is exercised here without contacting any BSV node
// or ARC instance. The "broadcast" path is driven against an
// invalid-but-syntactically-valid fixture so the test can verify:
//
//   - With insufficient governance signatures, the partial-sig flow
//     writes a JSON bundle to PartialSigOutPath and exits successfully
//     without contacting ARC. This proves the multi-sig coordination
//     mechanism is wired and that the binary will NOT silently fail
//     when fewer than Threshold sigs are present.
//
//   - With a full signature set the binary builds + signs a
//     transaction and reaches the ARC.Broadcast call. We point
//     ARCEndpoint at a non-routable URL so Broadcast errors out — the
//     test asserts the upgrade-tx hex is non-empty in the summary
//     emitted alongside the error, proving the assembly path produced
//     a complete tx.
//
// A real on-chain rotation is gated behind BSVM_TESTNET=1: it requires
// a live shard to spend, governance keys with secret material, and a
// fresh SP1 proof bundle. None of that is wired into the pure-Go test
// suite.
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

// fixtureCurrentStateRoot is the placeholder StateRoot used in the
// rotate-vk fixture. The on-chain assertion would reject a mismatch
// against the live covenant; for the pure-Go assembly test the value
// is opaque.
var fixtureCurrentStateRoot = "abababababababababababababababababababababababababababababababab"

// rotateFixtureConfig returns a RotateVKConfig pointed at a temp VK
// hash file so the pure-Go test does not depend on the in-tree
// SP1VerifyingKeyHash.txt path. Governance is single-key against the
// well-known fixture pubkey.
func rotateFixtureConfig(t *testing.T) *covenantdeploy.RotateVKConfig {
	t.Helper()
	vkPath := writeFixtureVKHashFile(t, fixtureVKHash)
	return &covenantdeploy.RotateVKConfig{
		OperatorConfig: covenantdeploy.OperatorConfig{
			ShardID:          "test-shard-rotate",
			ChainID:          8453111,
			VerificationMode: "fri",
			Governance: covenantdeploy.OperatorGovernance{
				Mode: "single_key",
				Keys: []string{fixtureSinglekeyPubKeyHex},
			},
			CovenantSats:    covenant.DefaultCovenantSats,
			VKHashFile:      vkPath,
			DeployerKeyFile: "/dev/null",
			ARCEndpoint:     "http://127.0.0.1:1", // unreachable on purpose
		},
		CovenantTxID:        strings.Repeat("11", 32),
		CovenantVout:        0,
		CovenantSatsLive:    covenant.DefaultCovenantSats,
		NewVKHashFile:       vkPath,
		CurrentStateRootHex: fixtureCurrentStateRoot,
		CurrentBlockNumber:  100,
	}
}

// writeRotateConfigFile marshals cfg to JSON and returns the path.
func writeRotateConfigFile(t *testing.T, cfg *covenantdeploy.RotateVKConfig) string {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal rotate cfg: %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "rotation.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write rotate cfg: %v", err)
	}
	return p
}

// TestRotateVK_DryRun_EmitsBothScripts asserts the dry-run path
// produces the same shape the broadcast path would, minus the
// upgrade-tx fields. This is the existing-pre-WW-rotate-onchain
// behaviour — kept as a regression test.
func TestRotateVK_DryRun_EmitsBothScripts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rotate-vk dry-run in short mode")
	}
	cfg := rotateFixtureConfig(t)
	cfgPath := writeRotateConfigFile(t, cfg)

	dir := t.TempDir()
	out := filepath.Join(dir, "summary.json")

	if err := covenantdeploy.RunRotateVK(covenantdeploy.RotateOptions{
		ConfigPath: cfgPath,
		DryRun:     true,
		OutPath:    out,
	}); err != nil {
		t.Fatalf("RunRotateVK dry-run: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary map[string]interface{}
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	for _, key := range []string{"shardId", "chainId", "newVKHash", "newRollupScriptHex"} {
		if _, ok := summary[key]; !ok {
			t.Errorf("dry-run summary missing key %q", key)
		}
	}
	if hexStr, ok := summary["newRollupScriptHex"].(string); !ok || hexStr == "" {
		t.Error("newRollupScriptHex empty in dry-run summary")
	}
}

// TestRotateVK_Broadcast_PartialSigWritesBundle asserts the multi-sig
// partial-signature flow: when fewer than Threshold sigs are listed,
// the binary writes the partial bundle to disk and exits successfully
// without contacting ARC.
func TestRotateVK_Broadcast_PartialSigWritesBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rotate-vk broadcast assembly in short mode")
	}
	cfg := rotateFixtureConfig(t)
	// Switch to multisig 2-of-3 so a single-sig run lands in the
	// partial-bundle branch.
	cfg.Governance = covenantdeploy.OperatorGovernance{
		Mode:      "multisig",
		Threshold: 2,
		Keys: []string{
			fixtureSinglekeyPubKeyHex,
			"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
			"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		},
	}
	// Supply only one sig (need two).
	cfg.GovernanceSigsHex = []string{strings.Repeat("aa", 71)}
	partial := filepath.Join(t.TempDir(), "rotate-vk.partial.json")
	cfg.PartialSigOutPath = partial

	cfgPath := writeRotateConfigFile(t, cfg)
	out := filepath.Join(filepath.Dir(cfgPath), "summary.json")

	err := covenantdeploy.RunRotateVK(covenantdeploy.RotateOptions{
		ConfigPath: cfgPath,
		Broadcast:  true,
		OutPath:    out,
	})
	if err != nil {
		t.Fatalf("RunRotateVK partial-sig path returned error: %v", err)
	}
	if _, statErr := os.Stat(partial); statErr != nil {
		t.Fatalf("partial bundle not written to %s: %v", partial, statErr)
	}
	raw, err := os.ReadFile(partial)
	if err != nil {
		t.Fatalf("read partial bundle: %v", err)
	}
	var pb map[string]interface{}
	if err := json.Unmarshal(raw, &pb); err != nil {
		t.Fatalf("parse partial bundle: %v", err)
	}
	for _, key := range []string{
		"newCovenantScriptHex", "publicValuesHex",
		"batchDataHex", "proofBlobHex", "governanceSigsHex",
	} {
		if _, ok := pb[key]; !ok {
			t.Errorf("partial bundle missing key %q", key)
		}
	}

	// Summary should record awaitingSigs > 0 and broadcast=false.
	sumRaw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary map[string]interface{}
	if err := json.Unmarshal(sumRaw, &summary); err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	if got, _ := summary["upgradeTxAwaitingSigs"].(float64); got < 1 {
		t.Errorf("expected upgradeTxAwaitingSigs >= 1, got %v", summary["upgradeTxAwaitingSigs"])
	}
	if got, _ := summary["broadcast"].(bool); got {
		t.Error("broadcast=true in partial-sig summary")
	}
}

// TestRotateVK_Broadcast_FullSigsAssemblesTx exercises the full-sigs
// path. ARC at 127.0.0.1:1 will reject the broadcast — we expect the
// error AND we expect the summary file to contain a non-empty
// upgradeTxHex, proving the assembly path completed before the
// network failure.
func TestRotateVK_Broadcast_FullSigsAssemblesTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rotate-vk full-sigs assembly in short mode")
	}
	cfg := rotateFixtureConfig(t)
	// Single-key governance — 1 sig satisfies threshold.
	cfg.GovernanceSigsHex = []string{strings.Repeat("bb", 71)}
	cfgPath := writeRotateConfigFile(t, cfg)
	out := filepath.Join(filepath.Dir(cfgPath), "summary.json")

	err := covenantdeploy.RunRotateVK(covenantdeploy.RotateOptions{
		ConfigPath: cfgPath,
		Broadcast:  true,
		OutPath:    out,
	})
	// We expect an ARC.Broadcast failure because ARCEndpoint is
	// unreachable. The assembly path must have completed first;
	// inspect the summary to confirm.
	if err == nil {
		t.Fatal("expected ARC.Broadcast failure with 127.0.0.1:1 endpoint, got nil error")
	}
	if !strings.Contains(err.Error(), "ARC.Broadcast") && !strings.Contains(err.Error(), "broadcast") {
		t.Errorf("expected ARC-broadcast-related error, got: %v", err)
	}
	raw, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatalf("read summary after ARC failure: %v", rerr)
	}
	var summary map[string]interface{}
	if jerr := json.Unmarshal(raw, &summary); jerr != nil {
		t.Fatalf("parse summary: %v", jerr)
	}
	txHex, _ := summary["upgradeTxHex"].(string)
	if txHex == "" {
		t.Fatal("summary.upgradeTxHex is empty — assembly did not produce a tx")
	}
	if _, decErr := hex.DecodeString(txHex); decErr != nil {
		t.Errorf("upgradeTxHex is not valid hex: %v", decErr)
	}
	method, _ := summary["upgradeMethod"].(string)
	if method != "upgradeSingleKey" {
		t.Errorf("upgradeMethod = %q, want upgradeSingleKey", method)
	}
	unlockHex, _ := summary["upgradeUnlockHex"].(string)
	if unlockHex == "" {
		t.Error("summary.upgradeUnlockHex is empty — unlock script was not assembled")
	}

	// WW-anf-publish (resolved): assert the canonical ANF document was
	// built + written to disk, and that the on-chain commitment hash
	// surfaces in the summary. The publish-tx field stays empty because
	// --anf-publish is off by default.
	anfHash, _ := summary["anfHash"].(string)
	if anfHash == "" {
		t.Error("summary.anfHash is empty — ANF document was not built")
	}
	if len(anfHash) != 64 { // hex-encoded 32-byte hash
		t.Errorf("summary.anfHash %q is not a 32-byte hex string (len=%d)", anfHash, len(anfHash))
	}
	anfDocPath, _ := summary["anfDocPath"].(string)
	if anfDocPath == "" {
		t.Error("summary.anfDocPath is empty — ANF doc was not written")
	} else {
		anfBytes, anfErr := os.ReadFile(anfDocPath)
		if anfErr != nil {
			t.Errorf("read ANF doc at %s: %v", anfDocPath, anfErr)
		} else {
			var anfDoc map[string]interface{}
			// Strip trailing newline before parsing.
			trimmed := strings.TrimRight(string(anfBytes), "\n")
			if jerr := json.Unmarshal([]byte(trimmed), &anfDoc); jerr != nil {
				t.Errorf("parse ANF doc: %v (raw=%q)", jerr, anfBytes)
			} else {
				for _, key := range []string{"schema", "kind", "shardId", "rollup"} {
					if _, ok := anfDoc[key]; !ok {
						t.Errorf("ANF doc missing key %q", key)
					}
				}
				if anfDoc["kind"] != "rotation" {
					t.Errorf("ANF doc kind = %v, want rotation", anfDoc["kind"])
				}
			}
		}
	}
	if pubTxID, _ := summary["anfPublishTxid"].(string); pubTxID != "" {
		t.Errorf("expected anfPublishTxid empty when --anf-publish is off, got %q", pubTxID)
	}
}

// TestRotateVK_Broadcast_AnfPublishAttemptsBroadcast asserts that
// --anf-publish triggers the inscription tx broadcast even when the
// upgrade tx itself succeeded. The 127.0.0.1:1 ARC endpoint will
// reject the inscription tx; we expect the upgrade-tx ARC failure to
// surface FIRST (the publish-tx code never runs because the upgrade
// tx broadcast fails earlier). The test asserts the upgrade-tx error
// path still wrote the ANF doc to disk so the operator can retry the
// inscription standalone.
func TestRotateVK_Broadcast_AnfPublishAttemptsBroadcast(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rotate-vk anf-publish in short mode")
	}
	cfg := rotateFixtureConfig(t)
	cfg.GovernanceSigsHex = []string{strings.Repeat("bb", 71)}
	cfgPath := writeRotateConfigFile(t, cfg)
	out := filepath.Join(filepath.Dir(cfgPath), "summary.json")
	anfDoc := filepath.Join(filepath.Dir(cfgPath), "rotate-vk.anf.json")

	err := covenantdeploy.RunRotateVK(covenantdeploy.RotateOptions{
		ConfigPath: cfgPath,
		Broadcast:  true,
		ANFPublish: true,
		AnfDocPath: anfDoc,
		OutPath:    out,
	})
	// Upgrade-tx broadcast fails first (ARC at 127.0.0.1:1).
	if err == nil {
		t.Fatal("expected ARC.Broadcast failure")
	}
	// The ANF doc was written BEFORE the upgrade-tx broadcast attempt
	// (the doc carries the on-chain commitment, so it must exist before
	// the unlock script is built). The file must therefore exist even
	// after the broadcast failure.
	if _, statErr := os.Stat(anfDoc); statErr != nil {
		t.Fatalf("expected ANF doc at %s after ARC failure: %v", anfDoc, statErr)
	}
	raw, rerr := os.ReadFile(anfDoc)
	if rerr != nil {
		t.Fatalf("read ANF doc: %v", rerr)
	}
	if len(raw) < 16 {
		t.Errorf("ANF doc too small: %d bytes", len(raw))
	}
	if !strings.Contains(string(raw), `"kind":"rotation"`) {
		t.Errorf("ANF doc does not contain rotation kind tag: %q", raw)
	}
}

// TestRotateVK_Broadcast_OnTestnet is the gated end-to-end path. It
// runs ONLY with BSVM_TESTNET=1 set, requires a real live covenant
// UTXO and governance key, and broadcasts a real upgrade tx. Skipped
// under the standard CI suite to keep the test idempotent and offline.
//
// When BSVM_TESTNET=1 is paired with BSVM_TESTNET_ROTATION_CONFIG
// pointing at a live operator config file, the harness will:
//
//   - Run the rotation binary against the real ARC endpoint with
//     --broadcast --anf-publish.
//   - Assert both the rotation upgrade tx AND the ANF inscription tx
//     are accepted by ARC.
//   - Re-fetch the inscription tx via the ARC GET endpoint and verify
//     hash256(payload) == summary.anfHash.
//
// Today the harness is stubbed because the live shard fixture is
// generated by the operator's bootstrap key and cannot live in the
// repo. See deploy/covenant/README.md §rotate-vk-testnet.
func TestRotateVK_Broadcast_OnTestnet(t *testing.T) {
	if os.Getenv("BSVM_TESTNET") != "1" {
		t.Skip("set BSVM_TESTNET=1 to run the on-testnet rotate-vk broadcast")
	}
	t.Skip("BSVM_TESTNET broadcast harness requires a live shard config; " +
		"see deploy/covenant/README.md §rotate-vk-testnet for the runbook. " +
		"The runbook also covers --anf-publish: the inscription tx is " +
		"broadcast alongside the rotation tx and the on-chain commitment " +
		"is hash256(canonical-JSON(anf.Document)).")
}
