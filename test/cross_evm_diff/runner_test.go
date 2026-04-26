package cross_evm_diff

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/icellan/bsvm/test/evmtest"
)

// requireTestdata skips when the ethereum/tests submodule isn't
// checked out. The submodule has no entry in .gitmodules, so CI jobs
// that don't pre-clone ethereum/tests separately can't access it; the
// nightly cross-EVM workflow restores it explicitly.
func requireTestdata(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(testdataRoot); os.IsNotExist(err) {
		t.Skipf("ethereum/tests testdata absent at %s; clone https://github.com/ethereum/tests into test/evmtest/testdata to run", testdataRoot)
	}
}

// testdataRoot is the GeneralStateTests directory. Resolved relative
// to this test file so go test ./test/cross_evm_diff/... finds it
// regardless of where the runner is invoked from.
const testdataRoot = "../evmtest/testdata/GeneralStateTests"

// reportPath is where TestCrossEVMDiff writes its JSON mismatch report
// when the full suite turns up divergences.
const reportPath = "diffs.json"

// smokeFixtures are five small, well-known fixtures chosen for the
// short-mode smoke test. Each exercises a different cross-EVM concern:
// pure transfer (balance accounting), sstore (storage trie),
// sload (storage read accounting), self-balance (BALANCE opcode),
// and sha3 (KECCAK256 inside the EVM). All five run in well under
// 60 seconds even on a constrained CI runner.
var smokeFixtures = []string{
	"VMTests/vmTests/sha3.json",
	"stSLoadTest/sloadGasCost.json",
	"stSelfBalance/selfBalance.json",
	"stSStoreTest/sstore_0to0.json",
	"stSystemOperationsTest/currentAccountBalance.json",
}

// TestCrossEVMDiff_Smoke runs the cross-EVM differential harness over
// a five-fixture subset chosen to exercise transfers, storage,
// balance, and hashing. Designed to complete in seconds so it can run
// on every CI push.
func TestCrossEVMDiff_Smoke(t *testing.T) {
	requireTestdata(t)
	runner := NewRunner()
	rep := &Report{Fork: runner.fork}

	for _, rel := range smokeFixtures {
		path := filepath.Join(testdataRoot, rel)
		tests, err := LoadFixture(path)
		if err != nil {
			t.Fatalf("load %s: %v", rel, err)
		}
		passed, total, mismatches, err := runner.RunFixture(context.Background(), rel, tests)
		if err != nil {
			t.Fatalf("run %s: %v", rel, err)
		}
		if total == 0 {
			t.Logf("smoke fixture %s has no %s post-state, skipping", rel, runner.fork)
			rep.Skipped++
			continue
		}
		rep.Total += total
		rep.Pass += passed
		rep.Fail += len(mismatches)
		rep.Mismatches = append(rep.Mismatches, mismatches...)
	}

	if rep.Fail > 0 {
		for _, mm := range rep.Mismatches {
			t.Errorf("MISMATCH %s :: %s [%s post=%d] go=%s sp1=%s (%s)",
				mm.Fixture, mm.TestName, mm.Fork, mm.PostIndex,
				mm.GoRoot, mm.SP1Root, mm.FirstDiff)
		}
		t.Fatalf("smoke run: %d/%d mismatches", rep.Fail, rep.Total)
	}
	if rep.Total == 0 {
		t.Fatalf("smoke run: no fixtures executed (testdata missing?)")
	}
	t.Logf("smoke run PASS: %d/%d (skipped %d files)", rep.Pass, rep.Total, rep.Skipped)
}

// TestCrossEVMDiff walks the full GeneralStateTests tree and compares
// Go-EVM execution against SP1 prover output. Skipped under -short
// because it runs on the order of thousands of fixtures. When
// mismatches occur, a diffs.json report is written next to this file
// for triage.
func TestCrossEVMDiff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full cross-EVM diff suite in short mode")
	}
	requireTestdata(t)

	fixtures, err := FixtureWalk(testdataRoot)
	if err != nil {
		t.Fatalf("walk testdata: %v", err)
	}
	if len(fixtures) == 0 {
		t.Skipf("no fixtures found under %s", testdataRoot)
	}

	runner := NewRunner()
	rep := &Report{Fork: runner.fork}
	ctx := context.Background()

	for _, path := range fixtures {
		rel, _ := filepath.Rel(testdataRoot, path)
		tests, err := LoadFixture(path)
		if err != nil {
			rep.ParseError++
			t.Logf("parse error %s: %v", rel, err)
			continue
		}
		passed, total, mismatches, err := runner.RunFixture(ctx, rel, tests)
		if err != nil {
			t.Errorf("run %s: %v", rel, err)
			continue
		}
		if total == 0 {
			rep.Skipped++
			continue
		}
		rep.Total += total
		rep.Pass += passed
		rep.Fail += len(mismatches)
		rep.Mismatches = append(rep.Mismatches, mismatches...)
	}

	if rep.Fail > 0 {
		if err := WriteReport(reportPath, rep); err != nil {
			t.Errorf("write report: %v", err)
		} else {
			t.Logf("wrote %d mismatches to %s", rep.Fail, reportPath)
		}
		t.Fatalf("cross-EVM diff: %d mismatches in %d fixtures (%d skipped, %d parse-errors)",
			rep.Fail, rep.Total, rep.Skipped, rep.ParseError)
	}
	t.Logf("cross-EVM diff PASS: %d fixtures (%d skipped, %d parse-errors)",
		rep.Total, rep.Skipped, rep.ParseError)
}

// TestSmokeFixturesExist guards against a misconfigured smoke list.
// Without this, a missing fixture would silently inflate the pass
// count to zero and the smoke test would pass trivially.
func TestSmokeFixturesExist(t *testing.T) {
	requireTestdata(t)
	for _, rel := range smokeFixtures {
		path := filepath.Join(testdataRoot, rel)
		tests, err := LoadFixture(path)
		if err != nil {
			t.Errorf("smoke fixture %s: %v", rel, err)
			continue
		}
		if len(tests) == 0 {
			t.Errorf("smoke fixture %s contains no tests", rel)
		}
	}
}

// TestExecuteStateTestRoot is a sanity check that the harness's view
// of the Go-EVM post-state matches the existing evmtest runner's
// assertion (the fixture's declared root). If this drifts, the
// differential harness will spuriously flag every fixture as a
// mismatch.
func TestExecuteStateTestRoot(t *testing.T) {
	requireTestdata(t)
	path := filepath.Join(testdataRoot, smokeFixtures[0])
	tests, err := LoadFixture(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for name, test := range tests {
		if _, ok := test.Post[DefaultFork]; !ok {
			continue
		}
		results, err := evmtest.ExecuteStateTest(test, DefaultFork)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, r := range results {
			if r.PostStateRoot != r.ExpectedRoot {
				t.Errorf("%s post[%d]: go-evm root %s != fixture root %s",
					name, r.Index, r.PostStateRoot.Hex(), r.ExpectedRoot.Hex())
			}
		}
	}
}
