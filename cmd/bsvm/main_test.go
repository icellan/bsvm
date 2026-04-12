package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCmdVersion(t *testing.T) {
	// Capture the output of cmdVersion by redirecting stdout.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	_ = cmdVersion(nil)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	expected := fmt.Sprintf("bsvm version %s\n", version)
	if output != expected {
		t.Errorf("cmdVersion output = %q, want %q", output, expected)
	}
}

func TestSetupLogging(t *testing.T) {
	// Verify setupLogging does not panic with various configurations.
	tests := []struct {
		level  string
		format string
	}{
		{"debug", "text"},
		{"info", "json"},
		{"warn", "text"},
		{"error", "json"},
		{"", ""},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.level+"_"+tt.format, func(t *testing.T) {
			setupLogging(tt.level, tt.format) // Should not panic.
		})
	}
}

func TestVersionConstant(t *testing.T) {
	if version == "" {
		t.Error("version constant must not be empty")
	}
	if !strings.Contains(version, ".") {
		t.Error("version should be in semver format (contain a dot)")
	}
}
