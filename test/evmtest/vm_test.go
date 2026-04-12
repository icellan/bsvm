package evmtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testdataDir = "testdata"

// TestVMArithmetic runs the VMTests/vmArithmeticTest tests from the
// ethereum/tests suite. These are now in GeneralStateTest format.
func TestVMArithmetic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping VM tests in short mode")
	}
	runStateTestDir(t, filepath.Join(testdataDir, "GeneralStateTests", "VMTests", "vmArithmeticTest"))
}

// TestVMBitwiseLogic runs the VMTests/vmBitwiseLogicOperation tests.
func TestVMBitwiseLogic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping VM tests in short mode")
	}
	runStateTestDir(t, filepath.Join(testdataDir, "GeneralStateTests", "VMTests", "vmBitwiseLogicOperation"))
}

// TestVMIOAndFlow runs the VMTests/vmIOandFlowOperations tests.
func TestVMIOAndFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping VM tests in short mode")
	}
	runStateTestDir(t, filepath.Join(testdataDir, "GeneralStateTests", "VMTests", "vmIOandFlowOperations"))
}

// TestVMLog runs the VMTests/vmLogTest tests.
func TestVMLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping VM tests in short mode")
	}
	runStateTestDir(t, filepath.Join(testdataDir, "GeneralStateTests", "VMTests", "vmLogTest"))
}

// TestVMTests runs the VMTests/vmTests tests.
func TestVMTests(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping VM tests in short mode")
	}
	runStateTestDir(t, filepath.Join(testdataDir, "GeneralStateTests", "VMTests", "vmTests"))
}

// TestGeneralStateTests runs all GeneralStateTests against the Cancun fork.
func TestGeneralStateTests(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping general state tests in short mode")
	}
	runStateTestDir(t, filepath.Join(testdataDir, "GeneralStateTests"))
}

// runStateTestDir walks a directory of JSON state test files and runs each.
func runStateTestDir(t *testing.T, dir string) {
	t.Helper()

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skipf("test data not found at %s", dir)
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Skip EIP-4844 blob transaction tests — we don't support Type 3
		// blob txs on this L2 by design.
		if strings.Contains(path, "stEIP4844") || strings.Contains(path, "blobtransactions") {
			return nil
		}

		// Make the test name relative to the base dir for readability.
		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = filepath.Base(path)
		}

		t.Run(relPath, func(t *testing.T) {
			runStateTestFile(t, path)
		})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk test directory: %v", err)
	}
}

// runStateTestFile parses and runs all tests in a single JSON file.
func runStateTestFile(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	var tests map[string]*StateTest
	if err := json.Unmarshal(data, &tests); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}

	for name, test := range tests {
		t.Run(sanitizeTestName(name), func(t *testing.T) {
			// Run against Cancun fork (our primary target).
			forks := []string{"Cancun"}

			for _, fork := range forks {
				if !isSupportedFork(fork) {
					continue
				}
				posts, ok := test.Post[fork]
				if !ok || len(posts) == 0 {
					continue
				}

				t.Run(fork, func(t *testing.T) {
					errs := RunStateTest(test, fork)
					for _, err := range errs {
						t.Error(err)
					}
				})
			}
		})
	}
}

// sanitizeTestName removes characters that are problematic in test names.
func sanitizeTestName(name string) string {
	// Replace path separators and colons.
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "::", "__")
	// Truncate very long names.
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}
