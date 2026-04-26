// Cross-implementation conformance test: runs every JSON fixture in this
// directory against the in-tree Go MPT (`pkg/mpt`) AND the Rust runner under
// `rust_runner/`, comparing the trie root after every operation. Any
// disagreement is a critical bug — the Go EVM (overlay) and Rust EVM (SP1
// guest, which uses alloy-trie) MUST produce identical state roots for the
// same state, otherwise the prover will reject blocks the overlay accepts.
//
// Skipped under `go test -short`. Skipped (with a clear message) when `cargo`
// is not on PATH so contributors without a Rust toolchain can still run the
// rest of the test suite.
package mpt_conformance

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/mpt"
)

// rustReport mirrors the JSON written by `rust_runner/src/main.rs`.
type rustReport struct {
	Fixture string           `json:"fixture"`
	Cases   []rustCaseReport `json:"cases"`
	Pass    bool             `json:"pass"`
}

type rustCaseReport struct {
	Name         string           `json:"name"`
	ExpectedRoot string           `json:"expected_root"`
	FinalRoot    string           `json:"final_root"`
	FinalMatch   bool             `json:"final_match"`
	Steps        []rustStepReport `json:"steps"`
	Error        *string          `json:"error"`
}

type rustStepReport struct {
	Index  int    `json:"index"`
	Action string `json:"action"`
	Actual string `json:"actual"`
}

// rustRunnerOnce holds the build-once state for the Rust binary. We only build
// the release binary one time per `go test` invocation (across all subtests).
var (
	rustRunnerOnce  sync.Once
	rustRunnerPath  string
	rustRunnerBuild error
)

// buildRustRunner compiles the Rust release binary and caches the path. It
// returns ("", err) if cargo is unavailable or the build fails.
func buildRustRunner(t *testing.T) (string, error) {
	t.Helper()
	rustRunnerOnce.Do(func() {
		if _, err := exec.LookPath("cargo"); err != nil {
			rustRunnerBuild = fmt.Errorf("cargo not on PATH: %w", err)
			return
		}
		runnerDir, err := filepath.Abs("rust_runner")
		if err != nil {
			rustRunnerBuild = err
			return
		}
		cmd := exec.Command("cargo", "build", "--release", "--quiet")
		cmd.Dir = runnerDir
		if out, err := cmd.CombinedOutput(); err != nil {
			rustRunnerBuild = fmt.Errorf("cargo build failed: %v\n%s", err, out)
			return
		}
		rustRunnerPath = filepath.Join(runnerDir, "target", "release", "rust_runner")
		if _, err := os.Stat(rustRunnerPath); err != nil {
			rustRunnerBuild = fmt.Errorf("rust_runner binary missing at %s: %w", rustRunnerPath, err)
			rustRunnerPath = ""
			return
		}
	})
	return rustRunnerPath, rustRunnerBuild
}

// goRootsForOperations replays the operation sequence against the Go MPT and
// returns the canonical 0x-prefixed root hex after every step.
func goRootsForOperations(t *testing.T, ops []MPTOperation) []string {
	t.Helper()
	memdb := db.NewMemoryDB()
	trieDB := mpt.NewDatabase(memdb)
	trie := mpt.NewEmpty(trieDB)

	roots := make([]string, len(ops))
	for i, op := range ops {
		key, err := hex.DecodeString(strip0x(op.Key))
		if err != nil {
			t.Fatalf("op %d: invalid key hex %q: %v", i, op.Key, err)
		}
		switch op.Action {
		case "put":
			val, err := hex.DecodeString(strip0x(op.Value))
			if err != nil {
				t.Fatalf("op %d: invalid value hex %q: %v", i, op.Value, err)
			}
			if err := trie.Update(key, val); err != nil {
				t.Fatalf("op %d: trie update failed: %v", i, err)
			}
		case "delete":
			if err := trie.Delete(key); err != nil {
				t.Fatalf("op %d: trie delete failed: %v", i, err)
			}
		default:
			t.Fatalf("op %d: unknown action %q", i, op.Action)
		}
		roots[i] = "0x" + hex.EncodeToString(trie.Hash().Bytes())
	}
	return roots
}

// listFixtures discovers every *.json fixture in the current directory.
// Excluding any that don't parse as a fixture array is the responsibility of
// the test loop; we let bad files surface as a parse error.
func listFixtures(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read fixture dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		out = append(out, name)
	}
	return out
}

func strip0x(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s[2:]
	}
	return s
}

// TestCrossRunnerAgreement is the headline conformance check: for every
// fixture, the Go MPT and alloy-trie must produce byte-identical roots after
// every operation. A divergence here is a P0 bug — the prover would reject
// blocks the overlay accepts.
func TestCrossRunnerAgreement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-runner conformance in -short mode")
	}

	rustBin, err := buildRustRunner(t)
	if err != nil {
		t.Skipf("rust runner unavailable (build prerequisite: cargo build --release in test/mpt_conformance/rust_runner): %v", err)
	}

	fixtures := listFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found in test/mpt_conformance")
	}

	for _, fname := range fixtures {
		fname := fname
		t.Run(fname, func(t *testing.T) {
			// 1. Run Rust runner, capture its JSON report.
			tmpReport, err := os.CreateTemp("", "rust_report_*.json")
			if err != nil {
				t.Fatalf("temp report: %v", err)
			}
			tmpPath := tmpReport.Name()
			_ = tmpReport.Close()
			defer os.Remove(tmpPath)

			cmd := exec.Command(rustBin, "--fixture", fname, "--report", tmpPath)
			cmd.Dir, _ = filepath.Abs(".")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("rust runner failed on %s: %v\n%s", fname, err, out)
			}

			raw, err := os.ReadFile(tmpPath)
			if err != nil {
				t.Fatalf("read rust report: %v", err)
			}
			var report rustReport
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatalf("parse rust report: %v\n%s", err, raw)
			}

			// 2. Run Go MPT on the same fixture.
			cases := loadFixture(t, fname)
			if len(cases) != len(report.Cases) {
				t.Fatalf("case count mismatch: go=%d rust=%d", len(cases), len(report.Cases))
			}

			// 3. Compare per-case, per-step roots.
			for i, gc := range cases {
				rc := report.Cases[i]
				if rc.Name != gc.Name {
					t.Errorf("case %d: name mismatch go=%q rust=%q", i, gc.Name, rc.Name)
				}
				if rc.Error != nil && *rc.Error != "" {
					t.Errorf("case %q: rust runner reported error: %s", gc.Name, *rc.Error)
					continue
				}

				goRoots := goRootsForOperations(t, gc.Operations)
				if len(goRoots) != len(rc.Steps) {
					t.Errorf("case %q: step count mismatch go=%d rust=%d", gc.Name, len(goRoots), len(rc.Steps))
					continue
				}

				for j, gr := range goRoots {
					rr := strings.ToLower(rc.Steps[j].Actual)
					if gr != rr {
						t.Errorf("case %q step %d (action=%s): root divergence\n  go  : %s\n  rust: %s",
							gc.Name, j, rc.Steps[j].Action, gr, rr)
					}
				}

				// Also verify the fixture's expectedRoot (when present) is
				// satisfied by both runners.
				if gc.ExpectedRoot != "" {
					expected := "0x" + strings.ToLower(strip0x(gc.ExpectedRoot))
					var goFinal string
					if len(goRoots) == 0 {
						// No operations -> empty trie root.
						goFinal = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
					} else {
						goFinal = goRoots[len(goRoots)-1]
					}
					if goFinal != expected {
						t.Errorf("case %q: go final root %s != expectedRoot %s", gc.Name, goFinal, expected)
					}
					if strings.ToLower(rc.FinalRoot) != expected {
						t.Errorf("case %q: rust final root %s != expectedRoot %s", gc.Name, rc.FinalRoot, expected)
					}
				}
			}
		})
	}
}
