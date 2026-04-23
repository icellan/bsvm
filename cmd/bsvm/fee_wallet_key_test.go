package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateFeeWalletKey_CreatesFileWith0600(t *testing.T) {
	dir := t.TempDir()

	priv, err := LoadOrCreateFeeWalletKey(dir)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if priv == nil {
		t.Fatal("expected non-nil private key")
	}

	path := filepath.Join(dir, feeWalletKeyFilename)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	// Skip the mode check on Windows: file modes don't map cleanly.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("file mode = %o, want 0600", mode)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if len(strings.TrimSpace(string(raw))) != 64 {
		t.Errorf("persisted hex key length = %d, want 64", len(strings.TrimSpace(string(raw))))
	}
}

func TestLoadOrCreateFeeWalletKey_ReloadsSameKey(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateFeeWalletKey(dir)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	second, err := LoadOrCreateFeeWalletKey(dir)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	// Compare via hex-serialised public keys — PrivateKey is a struct with
	// internal fields, so direct equality is fragile.
	firstPub := first.PubKey().Compressed()
	secondPub := second.PubKey().Compressed()
	if len(firstPub) != len(secondPub) {
		t.Fatalf("pub key length mismatch: %d vs %d", len(firstPub), len(secondPub))
	}
	for i := range firstPub {
		if firstPub[i] != secondPub[i] {
			t.Fatalf("key differs at byte %d: %x vs %x", i, firstPub[i], secondPub[i])
		}
	}
}

func TestLoadOrCreateFeeWalletKey_BadFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, feeWalletKeyFilename)

	// Not-hex content → PrivateKeyFromHex must fail with a wrapped error.
	if err := os.WriteFile(path, []byte("not-a-hex-key"), 0o600); err != nil {
		t.Fatalf("write corrupt key file: %v", err)
	}

	_, err := LoadOrCreateFeeWalletKey(dir)
	if err == nil {
		t.Fatal("expected error for corrupt key file, got nil")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("error %q does not mention parsing", err.Error())
	}
}

func TestLoadOrCreateFeeWalletKey_EmptyDirRejected(t *testing.T) {
	if _, err := LoadOrCreateFeeWalletKey(""); err == nil {
		t.Fatal("expected error for empty dir, got nil")
	}
}

func TestFeeWalletBSVAddress(t *testing.T) {
	dir := t.TempDir()
	priv, err := LoadOrCreateFeeWalletKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateFeeWalletKey: %v", err)
	}

	for _, net := range []string{"mainnet", "testnet", "regtest"} {
		addr, err := FeeWalletBSVAddress(priv, net)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", net, err)
			continue
		}
		if addr == "" {
			t.Errorf("%s: empty address", net)
		}
	}

	if _, err := FeeWalletBSVAddress(priv, "not-a-network"); err == nil {
		t.Error("expected error for unknown network")
	}
	if _, err := FeeWalletBSVAddress(nil, "regtest"); err == nil {
		t.Error("expected error for nil private key")
	}
}
