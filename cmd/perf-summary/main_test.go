package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// formatThousands renders 0, 1-2-3-digit, and >3-digit values with the
// expected `_` separators. Pin the contract here so a regression in the
// formatter doesn't silently produce baselines the readBaseline parser
// can no longer round-trip (it strips `_` before parsing, but only if
// the format matches `\d+(_\d{3})*`).
func TestFormatThousands(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{999, "999"},
		{1_000, "1_000"},
		{1_234_567, "1_234_567"},
		{12_345_678, "12_345_678"},
	}
	for _, c := range cases {
		got := formatThousands(c.in)
		if got != c.want {
			t.Errorf("formatThousands(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// readBench round-trips a known-good bench output JSON file. Mirrors
// the shape bsvm-host-bench produces; if the field names ever drift,
// this test surfaces it before the summary tool silently emits zeros.
func TestReadBench(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	body := `{
		"cycles": 1234,
		"segments": 0,
		"instructions": 1234,
		"public_values_hash": "0xabcd",
		"public_values": "0xdeadbeef",
		"exit_code": 0,
		"wall_ms": 7,
		"proof_gen_ms": 0,
		"proof_bytes": 0,
		"vk_hash": "0xfeed",
		"sp1_version": ""
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out, err := readBench(path)
	if err != nil {
		t.Fatalf("readBench: %v", err)
	}
	if out.Cycles != 1234 || out.WallMs != 7 || out.VKHash != "0xfeed" {
		t.Fatalf("readBench mismatch: %+v", out)
	}
}

// readBench surfaces an error envelope as a Go-side error rather than
// silently producing a zeroed entry. The summary tool exits non-zero
// on this so a failing bench run can't pollute the perf baseline.
func TestReadBenchPropagatesError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "err.json")
	body := `{"cycles":0,"segments":0,"instructions":0,"public_values_hash":"","public_values":"","exit_code":1,"wall_ms":0,"proof_gen_ms":0,"proof_bytes":0,"vk_hash":"","sp1_version":"","error":"guest panicked"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := readBench(path); err == nil {
		t.Fatal("readBench must propagate envelope error")
	}
}

// writeMarkdown emits the table header even when no entries are
// provided. Pin the column count for the no-baseline case (5 columns)
// so a future change that shifts column order doesn't silently break
// the readBaseline parser.
func TestWriteMarkdownHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := writeMarkdown(&buf, nil, nil); err != nil {
		t.Fatalf("writeMarkdown: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "| Fixture | Cycles | Wall ms | Proof ms | Proof bytes |") {
		t.Errorf("missing header columns:\n%s", got)
	}
	if strings.Contains(got, "Δ vs baseline") {
		t.Errorf("delta column must be absent without baseline:\n%s", got)
	}
}

// writeMarkdown adds the Δ column when a baseline is supplied and
// computes signed deltas correctly.
func TestWriteMarkdownDelta(t *testing.T) {
	entries := []summaryEntry{
		{Name: "LegacyTransfer", Out: benchOutput{Cycles: 1500}},
		{Name: "BlobTx", Out: benchOutput{Cycles: 800}},
	}
	baseline := map[string]uint64{
		"LegacyTransfer": 1000,
		"BlobTx":         900,
	}
	var buf bytes.Buffer
	if err := writeMarkdown(&buf, entries, baseline); err != nil {
		t.Fatalf("writeMarkdown: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "Δ vs baseline") {
		t.Errorf("delta column must be present with baseline:\n%s", got)
	}
	if !strings.Contains(got, "+500") {
		t.Errorf("expected +500 for LegacyTransfer:\n%s", got)
	}
	if !strings.Contains(got, "-100") {
		t.Errorf("expected -100 for BlobTx:\n%s", got)
	}
}

// readBaseline survives a hand-edited markdown summary with `_` and
// `,` thousand separators in the cycle column. Both forms are stripped
// before parsing.
func TestReadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.md")
	body := `# SP1 host-bench summary

| Fixture | Cycles | Wall ms | Proof ms | Proof bytes |
|---|---|---|---|---|
| LegacyTransfer | 1_234_567 | 50 | 0 | 0 |
| BlobTx | 2,000,000 | 60 | 0 | 0 |
| ContractCreate | 4500000 | 120 | 0 | 0 |
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := readBaseline(path)
	if got["LegacyTransfer"] != 1_234_567 {
		t.Errorf("LegacyTransfer baseline = %d, want 1234567", got["LegacyTransfer"])
	}
	if got["BlobTx"] != 2_000_000 {
		t.Errorf("BlobTx baseline = %d, want 2000000", got["BlobTx"])
	}
	if got["ContractCreate"] != 4_500_000 {
		t.Errorf("ContractCreate baseline = %d, want 4500000", got["ContractCreate"])
	}
}

// nameFlag accepts repeated `-name <label>=<path>` pairs and rejects
// malformed inputs with a clear error.
func TestNameFlag(t *testing.T) {
	var n nameFlag
	if err := n.Set("LegacyTransfer=/tmp/a.json"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := n.Set("BlobTx=/tmp/b.json"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(n.pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(n.pairs))
	}
	if n.pairs[0].Label != "LegacyTransfer" || n.pairs[0].Path != "/tmp/a.json" {
		t.Errorf("first pair mismatch: %+v", n.pairs[0])
	}
	if err := n.Set("malformed"); err == nil {
		t.Error("malformed input must be rejected")
	}
	if err := n.Set("="); err == nil {
		t.Error("empty label/path must be rejected")
	}
	if err := n.Set("trailing="); err == nil {
		t.Error("empty path must be rejected")
	}
}
