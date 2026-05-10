package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/covenant"
)

func TestResolveVerificationMode_ProveModeDefaults(t *testing.T) {
	tests := []struct {
		name         string
		proveMode    string
		wantMode     covenant.VerificationMode
		wantModeName string
	}{
		{
			name:         "unset defaults to fri",
			wantMode:     covenant.VerifyFRI,
			wantModeName: "fri",
		},
		{
			name:         "execute defaults to fri",
			proveMode:    "execute",
			wantMode:     covenant.VerifyFRI,
			wantModeName: "fri",
		},
		{
			name:         "prove defaults to fri",
			proveMode:    "prove",
			wantMode:     covenant.VerifyFRI,
			wantModeName: "fri",
		},
		{
			name:         "mock defaults to devkey",
			proveMode:    "mock",
			wantMode:     covenant.VerifyDevKey,
			wantModeName: "devkey",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMode, gotModeName, err := resolveVerificationMode(tt.proveMode, "")
			if err != nil {
				t.Fatalf("resolveVerificationMode: %v", err)
			}
			if gotMode != tt.wantMode {
				t.Errorf("mode = %v, want %v", gotMode, tt.wantMode)
			}
			if gotModeName != tt.wantModeName {
				t.Errorf("mode name = %q, want %q", gotModeName, tt.wantModeName)
			}
		})
	}
}

func TestResolveVerificationMode_ExplicitUnsupportedModes(t *testing.T) {
	for _, verification := range []string{"groth16", "groth16-wa"} {
		t.Run(verification, func(t *testing.T) {
			_, _, err := resolveVerificationMode("prove", verification)
			if err == nil {
				t.Fatalf("expected error for --verification=%s", verification)
			}
			if !strings.Contains(err.Error(), "not yet wired") && !strings.Contains(err.Error(), "real SP1 prover") {
				t.Errorf("error = %q, want unsupported-mode guidance", err.Error())
			}
		})
	}
}

func TestReadDeploySP1VKFile_HexText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vk.hex")
	want := []byte{0x01, 0x23, 0xab, 0xcd}
	if err := os.WriteFile(path, []byte("  0x0123abcd\n"), 0o644); err != nil {
		t.Fatalf("write vk file: %v", err)
	}
	got, err := readDeploySP1VKFile(path)
	if err != nil {
		t.Fatalf("readDeploySP1VKFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("vk bytes = %x, want %x", got, want)
	}
}

func TestReadDeploySP1VKFile_RawBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vk.bin")
	want := []byte{0x00, 0x01, 0xff, 0x10, 0x20}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatalf("write vk file: %v", err)
	}
	got, err := readDeploySP1VKFile(path)
	if err != nil {
		t.Fatalf("readDeploySP1VKFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("vk bytes = %x, want %x", got, want)
	}
}
