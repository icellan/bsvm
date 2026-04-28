// Command perf-summary aggregates bsvm-host-bench JSON outputs into a
// markdown summary table.
//
// Usage:
//
//	bsvm-host-bench < input1.json > out1.json
//	bsvm-host-bench < input2.json > out2.json
//	perf-summary -name LegacyTransfer=out1.json -name BlobTx=out2.json
//
// With -baseline pointing at a previously-saved summary, the tool emits
// a delta column showing the cycle change from the baseline. Absent a
// baseline, the delta column is omitted.
//
// The aggregator is deliberately small — it doesn't reach into the
// bench harness, doesn't link against pkg/prover, and only reads JSON
// files. Operators run it manually after a `go test ./pkg/prover/ -run
// TestSP1Bench` capture to produce a checked-in perf-baseline.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// benchOutput mirrors prover/host-bench/src/lib.rs::BenchOutput. Kept
// in sync with pkg/prover/bench_test.go::benchOutput; drift here would
// only break the summary tool, never the bench itself.
type benchOutput struct {
	Cycles           uint64  `json:"cycles"`
	Segments         uint64  `json:"segments"`
	Instructions     uint64  `json:"instructions"`
	PublicValuesHash string  `json:"public_values_hash"`
	ExitCode         int     `json:"exit_code"`
	WallMs           uint64  `json:"wall_ms"`
	ProofGenMs       uint64  `json:"proof_gen_ms"`
	ProofBytes       uint64  `json:"proof_bytes"`
	VKHash           string  `json:"vk_hash"`
	SP1Version       string  `json:"sp1_version"`
	Error            *string `json:"error,omitempty"`
}

// summaryEntry pairs a fixture name with its parsed bench output.
// Sorted by name in the final markdown table for stable diffs.
type summaryEntry struct {
	Name string
	Out  benchOutput
}

// nameFlag accumulates `-name <label>=<path>` repeated arguments.
// Implements flag.Value so the user can pass multiple bench files in a
// single command line.
type nameFlag struct {
	pairs []nameFlagPair
}

type nameFlagPair struct {
	Label string
	Path  string
}

func (n *nameFlag) String() string {
	parts := make([]string, 0, len(n.pairs))
	for _, p := range n.pairs {
		parts = append(parts, p.Label+"="+p.Path)
	}
	return strings.Join(parts, ",")
}

func (n *nameFlag) Set(value string) error {
	idx := strings.Index(value, "=")
	if idx <= 0 || idx == len(value)-1 {
		return fmt.Errorf("expected -name <label>=<path>, got %q", value)
	}
	n.pairs = append(n.pairs, nameFlagPair{
		Label: value[:idx],
		Path:  value[idx+1:],
	})
	return nil
}

// readBench reads and parses a single bench output JSON file. The file
// must be a single line / single envelope (the bench binary's output
// shape).
func readBench(path string) (benchOutput, error) {
	f, err := os.Open(path)
	if err != nil {
		return benchOutput{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return benchOutput{}, err
	}
	var out benchOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return benchOutput{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if out.Error != nil {
		return benchOutput{}, fmt.Errorf("%s: bench error: %s", path, *out.Error)
	}
	return out, nil
}

// readBaseline parses a previously-saved markdown summary into a
// label-keyed cycle map. Best-effort — unrecognised lines are skipped
// silently. The table format below is the one writeMarkdown emits;
// hand-edited baselines must keep the column structure intact.
//
// Format expectation:
//
//	| Fixture | Cycles | ... |
//	|---|---|---|
//	| LegacyTransfer | 1234 | ... |
func readBaseline(path string) map[string]uint64 {
	out := map[string]uint64{}
	if path == "" {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "perf-summary: baseline %s not readable: %v\n", path, err)
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || strings.Contains(line, "Fixture") || strings.Contains(line, "---") {
			continue
		}
		// Expected:  | <name> | <cycles> | ...
		fields := strings.Split(line, "|")
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSpace(fields[1])
		cyclesStr := strings.TrimSpace(fields[2])
		// Strip Markdown formatting and underscore separators if any
		// (e.g. `2_345_678`).
		cyclesStr = strings.ReplaceAll(cyclesStr, "_", "")
		cyclesStr = strings.ReplaceAll(cyclesStr, ",", "")
		var c uint64
		if _, err := fmt.Sscanf(cyclesStr, "%d", &c); err != nil {
			continue
		}
		out[name] = c
	}
	return out
}

// writeMarkdown emits the perf summary table to the writer. Columns:
//
//	| Fixture | Cycles | Wall ms | Proof ms | Proof bytes | Δ vs baseline |
//
// The Δ column is omitted when no baseline is supplied. Cycle numbers
// are rendered with `_` thousands separators per the budget annotation
// convention used in bench_test.go's log lines.
func writeMarkdown(w io.Writer, entries []summaryEntry, baseline map[string]uint64) error {
	hasDelta := len(baseline) > 0
	var hdr strings.Builder
	hdr.WriteString("# SP1 host-bench summary\n\n")
	fmt.Fprintf(&hdr, "_Generated: %s_\n\n", time.Now().UTC().Format(time.RFC3339))
	if hasDelta {
		hdr.WriteString("| Fixture | Cycles | Wall ms | Proof ms | Proof bytes | Δ vs baseline |\n")
		hdr.WriteString("|---|---:|---:|---:|---:|---:|\n")
	} else {
		hdr.WriteString("| Fixture | Cycles | Wall ms | Proof ms | Proof bytes |\n")
		hdr.WriteString("|---|---:|---:|---:|---:|\n")
	}

	if _, err := io.WriteString(w, hdr.String()); err != nil {
		return err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, e := range entries {
		cyclesFmt := formatThousands(e.Out.Cycles)
		row := fmt.Sprintf("| %s | %s | %d | %d | %d",
			e.Name, cyclesFmt, e.Out.WallMs, e.Out.ProofGenMs, e.Out.ProofBytes,
		)
		if hasDelta {
			prev, ok := baseline[e.Name]
			delta := "-"
			if ok {
				diff := int64(e.Out.Cycles) - int64(prev)
				sign := "+"
				if diff < 0 {
					sign = "-"
					diff = -diff
				}
				delta = fmt.Sprintf("%s%s", sign, formatThousands(uint64(diff)))
			}
			row += fmt.Sprintf(" | %s", delta)
		}
		row += " |\n"
		if _, err := io.WriteString(w, row); err != nil {
			return err
		}
	}
	return nil
}

// formatThousands renders a uint64 with `_` separators (e.g.
// `2_345_678`) — the same convention the bench logs use for budget
// comparisons. Underscores survive copy-paste better than commas.
func formatThousands(v uint64) string {
	if v == 0 {
		return "0"
	}
	s := fmt.Sprintf("%d", v)
	// Walk back from the right inserting `_` every 3 digits.
	var out strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		out.WriteString(s[:pre])
		if len(s) > pre {
			out.WriteString("_")
		}
	}
	for i := pre; i < len(s); i += 3 {
		out.WriteString(s[i : i+3])
		if i+3 < len(s) {
			out.WriteString("_")
		}
	}
	return out.String()
}

func main() {
	var names nameFlag
	var baseline string
	var output string
	flag.Var(&names, "name", "label=path entries (repeatable)")
	flag.StringVar(&baseline, "baseline", "", "previous markdown summary to diff against")
	flag.StringVar(&output, "out", "-", "output path; '-' writes to stdout")
	flag.Parse()

	if len(names.pairs) == 0 {
		fmt.Fprintln(os.Stderr, "perf-summary: no -name pairs provided; use -name <label>=<path>")
		os.Exit(1)
	}

	entries := make([]summaryEntry, 0, len(names.pairs))
	for _, p := range names.pairs {
		out, err := readBench(p.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "perf-summary: %v\n", err)
			os.Exit(1)
		}
		entries = append(entries, summaryEntry{Name: p.Label, Out: out})
	}

	base := readBaseline(baseline)

	var w io.Writer
	if output == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "perf-summary: open %s: %v\n", output, err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	if err := writeMarkdown(w, entries, base); err != nil {
		fmt.Fprintf(os.Stderr, "perf-summary: write: %v\n", err)
		os.Exit(1)
	}
}
