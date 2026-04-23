//go:build devnet_sim

package devnet

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestSimSmoke runs bsvm-sim headlessly for a short window and asserts
// the output shows traffic flowing. Requires a live devnet — BSVM_SIM_NODES
// must be set (or we default to the compose ports).
func TestSimSmoke(t *testing.T) {
	nodes := "http://localhost:8545,http://localhost:8546,http://localhost:8547"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The test binary runs from test/devnet — point `go run` at the
	// sim package via the module-relative path.
	cmd := exec.CommandContext(ctx, "go", "run", "github.com/icellan/bsvm/cmd/bsvm-sim",
		"--nodes", nodes,
		"--headless",
		"--tps", "2",
		"--duration", "45s",
		"--workloads", "value-transfer,erc20-transfer,storage-set",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("bsvm-sim failed: %v\noutput:\n%s", err, out.String())
	}

	s := out.String()
	t.Logf("bsvm-sim output (tail):\n%s", tail(s, 2000))

	if !strings.Contains(s, "deploying contract suite") {
		t.Fatalf("expected deploy log line, got: %s", tail(s, 400))
	}
	if !strings.Contains(s, "value-transfer=") {
		t.Fatalf("expected value-transfer stats line")
	}
	// At the default rate the 45s run should produce at least a few
	// successful txs across the three easy workloads.
	if !hasAtLeastOneNonZeroSuccess(s, []string{"value-transfer", "erc20-transfer", "storage-set"}) {
		t.Fatalf("no successful txs across all 3 workloads. output:\n%s", tail(s, 1500))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// hasAtLeastOneNonZeroSuccess scans for "<name>=<succ>/<fail>@<rate>" in
// the last stat line and returns true if every name has succ > 0.
func hasAtLeastOneNonZeroSuccess(output string, names []string) bool {
	lines := strings.Split(output, "\n")
	// Walk from newest to oldest; we only need ONE line where all names
	// show non-zero.
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !strings.Contains(line, "tps5=") {
			continue
		}
		ok := true
		for _, name := range names {
			idx := strings.Index(line, name+"=")
			if idx < 0 {
				ok = false
				break
			}
			// expected shape "<name>=<succ>/<fail>@..."
			rest := line[idx+len(name)+1:]
			slash := strings.Index(rest, "/")
			if slash <= 0 {
				ok = false
				break
			}
			succStr := rest[:slash]
			if succStr == "0" {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
