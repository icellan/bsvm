// Package cross_evm_diff is a differential test harness that runs every
// ethereum/tests fixture through both the Go EVM (extracted from geth)
// and the SP1 prover, then asserts identical post-state roots.
//
// State-root agreement between the two EVMs is the single most critical
// correctness property of the system (spec 12, "Cross-EVM Differential
// Testing"). Any divergence is a P0 blocker.
//
// Today the SP1 leg is driven via the mock prover, which echoes the
// Go EVM's results back through PublicValues. The diff is therefore
// structural — it exercises fixture parsing, prover wiring, public-
// values encoding, and the comparator. When the production revm guest
// lands (parallel agent), swapping ProverMock for ProverLocal produces
// a true differential check with no code changes here.
package cross_evm_diff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/test/evmtest"
)

// DefaultFork is the fork the harness checks. We pin to Cancun to match
// test/evmtest/vm_test.go (the L2's primary target).
const DefaultFork = "Cancun"

// Mismatch describes a single (fixture, fork, post-index) that
// produced different post-state roots between the Go EVM and the SP1
// prover output. The JSON tags are stable so external triage tools
// can consume diffs.json without depending on this package.
type Mismatch struct {
	Fixture     string `json:"fixture"`
	TestName    string `json:"test_name"`
	Fork        string `json:"fork"`
	PostIndex   int    `json:"post_index"`
	GoRoot      string `json:"go_root"`
	SP1Root     string `json:"sp1_root"`
	FixtureRoot string `json:"fixture_root"`
	GasUsed     uint64 `json:"gas_used"`
	GoExecErr   string `json:"go_exec_err,omitempty"`
	FirstDiff   string `json:"first_diff"`
}

// Report is the structured output of a harness run. Pass/Fail counts
// plus a list of mismatches. Skipped is for fixtures that didn't apply
// to the requested fork (no post entry).
type Report struct {
	Fork       string     `json:"fork"`
	Total      int        `json:"total"`
	Pass       int        `json:"pass"`
	Fail       int        `json:"fail"`
	Skipped    int        `json:"skipped"`
	ParseError int        `json:"parse_error"`
	Mismatches []Mismatch `json:"mismatches"`
}

// FixtureWalk walks dir recursively and returns the absolute paths of
// every JSON state-test fixture. Excludes the EIP-4844 blob-tx tests
// for the same reason test/evmtest does — Type 3 blob txs aren't
// supported on this L2 by design.
func FixtureWalk(dir string) ([]string, error) {
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		if strings.Contains(path, "stEIP4844") || strings.Contains(path, "blobtransactions") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// LoadFixture parses a state-test JSON file into a map of test name to
// StateTest. The parser is the existing one in test/evmtest, exposed
// via re-use rather than duplication.
func LoadFixture(path string) (map[string]*evmtest.StateTest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var tests map[string]*evmtest.StateTest
	if err := json.Unmarshal(data, &tests); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return tests, nil
}

// Runner drives the differential comparison. The prover is held as a
// field so tests can swap mock/local/network without refactoring.
type Runner struct {
	prover *prover.SP1Prover
	fork   string
}

// NewRunner constructs a Runner with the default mock prover. The
// caller can override the fork via WithFork.
func NewRunner() *Runner {
	cfg := prover.DefaultConfig()
	cfg.Mode = prover.ProverMock
	return &Runner{
		prover: prover.NewSP1Prover(cfg),
		fork:   DefaultFork,
	}
}

// WithFork changes the fork the runner targets. Returns the receiver
// for chaining.
func (r *Runner) WithFork(fork string) *Runner {
	r.fork = fork
	return r
}

// RunFixture executes every (test, post-index) tuple in the fixture
// and returns one Mismatch per disagreement plus the number of
// successful matches and the total number of post-state comparisons
// performed. fixtureLabel is a human-readable identifier (typically
// the path relative to the testdata root). total - passed -
// len(mismatches) is always zero.
func (r *Runner) RunFixture(ctx context.Context, fixtureLabel string, tests map[string]*evmtest.StateTest) (passed, total int, mismatches []Mismatch, err error) {
	for testName, test := range tests {
		if _, ok := test.Post[r.fork]; !ok {
			continue
		}
		results, runErr := evmtest.ExecuteStateTest(test, r.fork)
		if runErr != nil {
			return passed, total, mismatches, fmt.Errorf("%s/%s: go-evm execution: %w", fixtureLabel, testName, runErr)
		}
		for _, res := range results {
			total++
			ok, mm, mmErr := r.compareOne(ctx, fixtureLabel, testName, test, res)
			if mmErr != nil {
				return passed, total, mismatches, mmErr
			}
			if ok {
				passed++
				continue
			}
			mismatches = append(mismatches, mm)
		}
	}
	return passed, total, mismatches, nil
}

// compareOne drives the prover with the same pre-state inputs the Go
// EVM saw and compares the post-state root committed in PublicValues
// against the Go EVM's computed root. Returns (true, _, nil) on match.
func (r *Runner) compareOne(
	ctx context.Context,
	fixtureLabel, testName string,
	test *evmtest.StateTest,
	res evmtest.PostStateResult,
) (bool, Mismatch, error) {
	preRoot, err := computePreRoot(test)
	if err != nil {
		return false, Mismatch{}, fmt.Errorf("%s/%s: compute pre-root: %w", fixtureLabel, testName, err)
	}

	// Drive the prover with the Go EVM's computed result. In mock mode
	// the prover echoes ExpectedResults straight into PublicValues; in
	// local/network mode it ignores ExpectedResults and recomputes via
	// revm — which is the real differential check.
	input := &prover.ProveInput{
		PreStateRoot: preRoot,
		BlockContext: prover.BlockContext{
			Number:   1,
			GasLimit: 30_000_000,
		},
		ExpectedResults: &prover.ExpectedResults{
			PostStateRoot: res.PostStateRoot,
			GasUsed:       res.GasUsed,
		},
	}

	out, err := r.prover.Prove(ctx, input)
	if err != nil {
		return false, Mismatch{}, fmt.Errorf("%s/%s: prove: %w", fixtureLabel, testName, err)
	}
	pv, err := prover.ParsePublicValues(out.PublicValues)
	if err != nil {
		return false, Mismatch{}, fmt.Errorf("%s/%s: parse public values: %w", fixtureLabel, testName, err)
	}

	if pv.PostStateRoot == res.PostStateRoot {
		return true, Mismatch{}, nil
	}

	mm := Mismatch{
		Fixture:     fixtureLabel,
		TestName:    testName,
		Fork:        res.Fork,
		PostIndex:   res.Index,
		GoRoot:      res.PostStateRoot.Hex(),
		SP1Root:     pv.PostStateRoot.Hex(),
		FixtureRoot: res.ExpectedRoot.Hex(),
		GasUsed:     res.GasUsed,
		FirstDiff:   firstDiff(res.PostStateRoot, pv.PostStateRoot),
	}
	if res.ExecErr != nil {
		mm.GoExecErr = res.ExecErr.Error()
	}
	return false, mm, nil
}

// computePreRoot reproduces the pre-state root the Go EVM driver
// commits before executing the transaction. We re-import the same
// helper used by the existing evmtest runner via SetupTriePreState
// so there's no parallel implementation to maintain.
func computePreRoot(test *evmtest.StateTest) (types.Hash, error) {
	sdb, err := evmtest.SetupTriePreStateExported(test.Pre)
	if err != nil {
		return types.Hash{}, err
	}
	return sdb.IntermediateRoot(true), nil
}

// firstDiff returns a short human-readable indicator of where two
// 32-byte hashes first diverge. Used in JSON reports to make triage
// fast — operators can spot whether the difference is in a high or
// low byte without diffing the full hex string by hand.
func firstDiff(a, b types.Hash) string {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("byte %d: 0x%02x vs 0x%02x", i, a[i], b[i])
		}
	}
	return "equal"
}

// WriteReport serialises a Report as indented JSON to path. The parent
// directory must exist.
func WriteReport(path string, rep *Report) error {
	if rep == nil {
		return errors.New("nil report")
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
