package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyEnvOverrides_ProveModeExecuteConfiguresSP1Backend(t *testing.T) {
	dir := t.TempDir()
	bridge := filepath.Join(dir, "bsvm-host-bridge")
	elf := filepath.Join(dir, "guest.elf")
	if err := os.WriteFile(bridge, []byte("stub"), 0o755); err != nil {
		t.Fatalf("write bridge: %v", err)
	}
	if err := os.WriteFile(elf, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatalf("write elf: %v", err)
	}

	t.Setenv("BSVM_PROVE_MODE", "execute")
	t.Setenv("BSVM_HOST_BRIDGE_BINARY", bridge)
	t.Setenv("BSVM_GUEST_ELF_PATH", elf)

	cfg := DefaultNodeConfig()
	if err := ApplyEnvOverrides(cfg); err != nil {
		t.Fatalf("ApplyEnvOverrides: %v", err)
	}
	if cfg.Prover.Mode != "execute" {
		t.Fatalf("Prover.Mode = %q, want execute", cfg.Prover.Mode)
	}
	if cfg.Prover.ProofMode != "fri" {
		t.Fatalf("Prover.ProofMode = %q, want fri", cfg.Prover.ProofMode)
	}
	if cfg.Prover.SP1ProofMode != "execute" {
		t.Fatalf("Prover.SP1ProofMode = %q, want execute", cfg.Prover.SP1ProofMode)
	}
	if cfg.Prover.HostBridgeBinary != bridge {
		t.Fatalf("HostBridgeBinary = %q, want %q", cfg.Prover.HostBridgeBinary, bridge)
	}
	if cfg.Prover.GuestELFPath != elf {
		t.Fatalf("GuestELFPath = %q, want %q", cfg.Prover.GuestELFPath, elf)
	}
}

func TestShouldWireBSVBroadcast(t *testing.T) {
	urls := []string{"http://devuser:devpass@127.0.0.1:18332"}
	for _, mode := range []string{"mock", "execute", "prove"} {
		if !shouldWireBSVBroadcast("prover", mode, urls) {
			t.Fatalf("shouldWireBSVBroadcast(prover, %q, urls) = false, want true", mode)
		}
	}

	if shouldWireBSVBroadcast("follower", "mock", urls) {
		t.Fatal("shouldWireBSVBroadcast(follower, mock, urls) = true, want false")
	}
	if shouldWireBSVBroadcast("prover", "mock", nil) {
		t.Fatal("shouldWireBSVBroadcast(prover, mock, nil) = true, want false")
	}
	if shouldWireBSVBroadcast("prover", "", urls) {
		t.Fatal("shouldWireBSVBroadcast(prover, empty, urls) = true, want false")
	}
}
