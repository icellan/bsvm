package prover

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

// TestProveExecuteModeBranches_Switch verifies that the new ProverExecute
// mode dispatches to the proveExecute branch (not local / mock / network).
// This is the structural assertion that closes the
// WW-prover-mode-wiring-execute TODO: spec 16's `execute` devnet preset
// can now actually drive revm-in-SP1 instead of falling through to mock.
func TestProveExecuteModeBranches_Switch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execute test relies on a POSIX shell stub")
	}

	// Stub bridge binary that:
	//   1. reads its stdin (the bridge envelope) into a temp file so the
	//      test can inspect what the Go side actually sent,
	//   2. writes a canned execute-mode HostOutput JSON to stdout that
	//      mirrors prover/host-bridge/src/main.rs's `execute` arm.
	dir := t.TempDir()
	stubPath := filepath.Join(dir, "host-bridge-stub")
	envelopeOutPath := filepath.Join(dir, "envelope.json")

	// Real bridge emits hex with "0x" prefix; mimic that exactly so the
	// decodeHexString path is exercised end-to-end.
	stub := "#!/bin/sh\n" +
		"cat > " + envelopeOutPath + "\n" +
		"cat <<'EOF'\n" +
		`{"proof":"","public_values":"0x` + strings.Repeat("aa", PublicValuesSize) + `",` +
		`"vk_hash":"0x` + strings.Repeat("11", 32) + `","cycles":123456,` +
		`"proving_time_ms":42,"sp1_version":"v6.0.2-test"}` + "\n" +
		"EOF\n"
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	// Verify the stub is actually executable on this filesystem.
	if _, err := exec.LookPath(stubPath); err != nil {
		// Some CI runners mount /tmp noexec; use sh -c shellout.
		t.Logf("stub not directly executable (%v); wrapping via /bin/sh", err)
	}

	cfg := Config{
		Mode:             ProverExecute,
		HostBridgeBinary: stubPath,
		GuestELFPath:     filepath.Join(dir, "guest.elf"),
		ProofMode:        ProofModeFRI,
	}
	// Seed a fake ELF so the path-existence check inside proveExecute
	// (host-bridge contract) is satisfied; the stub never reads it.
	if err := os.WriteFile(cfg.GuestELFPath, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatalf("seed elf: %v", err)
	}

	p := NewSP1Prover(cfg)

	// Build a minimal but legitimate ProveInput: buildBridgeInput
	// (called by proveExecute) refuses an empty StateExport, so we ship
	// a hand-rolled one with a single account + non-empty AccountProof.
	export := &StateExport{
		PreStateRoot: types.HexToHash("0x" + strings.Repeat("aa", 32)),
		Accounts: []AccountExport{{
			Address:      types.HexToAddress("0x1111111111111111111111111111111111111111"),
			Nonce:        0,
			Balance:      uint256.NewInt(0),
			CodeHash:     types.HexToHash("0x" + strings.Repeat("00", 32)),
			StorageRoot:  types.HexToHash("0x" + strings.Repeat("00", 32)),
			AccountProof: [][]byte{{0xaa}}, // non-empty satisfies the W4-1 guard
		}},
	}
	exportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("serialize export: %v", err)
	}

	in := &ProveInput{
		PreStateRoot: export.PreStateRoot,
		StateExport:  exportJSON,
		BlockContext: BlockContext{Number: 1, Timestamp: 1000, GasLimit: 30_000_000},
	}

	out, err := p.Prove(context.Background(), in)
	if err != nil {
		t.Fatalf("Prove(execute): %v", err)
	}
	if out == nil {
		t.Fatal("Prove(execute) returned nil output")
	}

	if got, want := out.Cycles, uint64(123456); got != want {
		t.Errorf("Cycles = %d, want %d", got, want)
	}
	if len(out.PublicValues) != PublicValuesSize {
		t.Errorf("PublicValues length = %d, want %d", len(out.PublicValues), PublicValuesSize)
	}
	wantVK := types.HexToHash("0x" + strings.Repeat("11", 32))
	if out.VKHash != wantVK {
		t.Errorf("VKHash = %s, want %s", out.VKHash.Hex(), wantVK.Hex())
	}
	if out.ProvingTime != 42*time.Millisecond {
		t.Errorf("ProvingTime = %v, want 42ms", out.ProvingTime)
	}
	if len(out.Proof) != 0 {
		t.Errorf("Proof should be empty in execute mode, got %d bytes", len(out.Proof))
	}

	// Verify the bridge actually saw mode = "execute" in the envelope —
	// this proves proveExecute forces the wire-format mode regardless
	// of the caller's SP1ProofMode setting.
	envBytes, err := os.ReadFile(envelopeOutPath)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	var env struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Mode != "execute" {
		t.Errorf("bridge envelope mode = %q, want %q", env.Mode, "execute")
	}
}

// TestProveExecuteModeBranches_RequiresPaths ensures proveExecute fails
// fast when the operator forgot to point at the host-bridge binary or
// guest ELF — same contract as proveLocal.
func TestProveExecuteModeBranches_RequiresPaths(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "missing_binary",
			cfg:  Config{Mode: ProverExecute, GuestELFPath: "/some/path"},
			want: "host bridge binary",
		},
		{
			name: "missing_elf",
			cfg:  Config{Mode: ProverExecute, HostBridgeBinary: "/some/path"},
			want: "guest ELF path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewSP1Prover(tt.cfg)
			_, err := p.Prove(context.Background(), &ProveInput{
				PreStateRoot: types.Hash{},
				StateExport:  []byte(`{"pre_state_root":"0x` + strings.Repeat("00", 32) + `"}`),
				BlockContext: BlockContext{Number: 1},
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want substring %q", err, tt.want)
			}
		})
	}
}

// TestProveExecuteBridgeError surfaces a structured-error envelope from
// the bridge as a Go error rather than silently returning a zeroed
// ProveOutput.
func TestProveExecuteBridgeError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execute test relies on a POSIX shell stub")
	}

	dir := t.TempDir()
	stubPath := filepath.Join(dir, "host-bridge-stub")
	stub := "#!/bin/sh\n" +
		"cat > /dev/null\n" +
		`echo '{"proof":"","public_values":"","vk_hash":"","cycles":0,"proving_time_ms":0,"sp1_version":"","error":"guest panicked: fictional"}'` + "\n"
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	elfPath := filepath.Join(dir, "guest.elf")
	if err := os.WriteFile(elfPath, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatalf("seed elf: %v", err)
	}

	cfg := Config{
		Mode:             ProverExecute,
		HostBridgeBinary: stubPath,
		GuestELFPath:     elfPath,
		ProofMode:        ProofModeFRI,
	}
	p := NewSP1Prover(cfg)

	export := &StateExport{
		PreStateRoot: types.HexToHash("0x" + strings.Repeat("aa", 32)),
		Accounts: []AccountExport{{
			Address:      types.HexToAddress("0x1111111111111111111111111111111111111111"),
			Balance:      uint256.NewInt(0),
			AccountProof: [][]byte{{0xaa}},
		}},
	}
	exportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	_, err = p.Prove(context.Background(), &ProveInput{
		PreStateRoot: export.PreStateRoot,
		StateExport:  exportJSON,
		BlockContext: BlockContext{Number: 1},
	})
	if err == nil {
		t.Fatal("expected error from bridge stub, got nil")
	}
	if !strings.Contains(err.Error(), "guest panicked") {
		t.Errorf("err = %v, want bridge error message", err)
	}
	// Sanity-check the wrapped error type stays a plain error (no
	// custom wrapping leaks beyond fmt.Errorf), so callers can still
	// match on substring without errors.As gymnastics.
	var raw error = err
	if errors.Unwrap(raw) != nil && !strings.Contains(raw.Error(), "sp1 execute") {
		t.Errorf("expected wrapped sp1 execute error, got %v", err)
	}
}

// TestProveExecuteModeStringer pins the human-readable name for the new
// mode so log lines / metrics labels stay stable across releases.
func TestProveExecuteModeStringer(t *testing.T) {
	if got := ProverExecute.String(); got != "execute" {
		t.Errorf("ProverExecute.String() = %q, want %q", got, "execute")
	}
}
