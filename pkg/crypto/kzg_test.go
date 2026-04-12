package crypto

import (
	"testing"
)

func TestLoadKZGTrustedSetup(t *testing.T) {
	if err := LoadKZGTrustedSetup(""); err != nil {
		t.Fatalf("LoadKZGTrustedSetup failed: %v", err)
	}
	if !KZGReady() {
		t.Fatal("KZGReady should return true after setup")
	}
}

func TestLoadKZGTrustedSetupIdempotent(t *testing.T) {
	// Calling multiple times should not error.
	if err := LoadKZGTrustedSetup(""); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if err := LoadKZGTrustedSetup(""); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
}

func TestVerifyKZGProofNotLoaded(t *testing.T) {
	// If the context were nil this would fail. Since other tests in this
	// package will have loaded it, we only check for a non-panic.
	// The real not-loaded path is tested via the vm package tests.
	err := VerifyKZGProof(make([]byte, 48), make([]byte, 32), make([]byte, 32), make([]byte, 48))
	// We expect an error (invalid point), not a panic.
	if err == nil {
		t.Fatal("expected error for zero-value inputs")
	}
}
