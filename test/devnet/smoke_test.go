//go:build devnet_smoke

// Package devnet contains end-to-end smoke tests that drive the
// developer-facing `docker-compose.yml` at the repo root.
//
// These tests are gated behind the `devnet_smoke` build tag because
// they spin up a 5-container cluster (BSV regtest + auto-miner + three
// BSVM nodes) and take ~30 seconds to go healthy. The default
// `go test ./...` invocation skips them; CI runs them explicitly via
// `go test -tags devnet_smoke ./test/devnet/...`.
//
// Assumptions:
//   - `docker` and `docker compose` are on PATH.
//   - The `bsvm:devnet` image has been built (e.g. via
//     `scripts/docker-build.sh`). The test does NOT rebuild the image.
//   - Host ports 8545-8547, 18335, 18546/18548/18550, 9945-9947 are free.
//
// Each test owns a `docker compose up -d` / `docker compose down -v`
// cycle via t.Cleanup, so tests can run in series on a single shared
// machine without leaving state behind.
package devnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// composeBinary is the binary + subcommand used to drive compose. The
// new `docker compose` plugin is preferred; legacy `docker-compose`
// would require a second code path and is out of scope.
var composeBinary = []string{"docker", "compose"}

// repoRoot walks up from this test file until it finds docker-compose.yml.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "docker-compose.yml")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate docker-compose.yml walking up from test file")
	return ""
}

func runCompose(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(composeBinary[0], append(composeBinary[1:], args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func waitHealthy(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "ps",
			"--filter", "label=com.docker.compose.project=bsv-evm",
			"--filter", "health=healthy",
			"--format", "{{.Names}}",
		).Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			healthy := 0
			for _, l := range lines {
				if strings.TrimSpace(l) != "" {
					healthy++
				}
			}
			if healthy >= 4 {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	// Dump diagnostics BEFORE Fatalf so the t.Cleanup tear-down doesn't
	// race us to remove the containers (CI captures only `t.Log` /
	// `t.Errorf` output that was emitted before the test exits).
	dumpClusterDiagnostics(t)
	t.Fatalf("cluster did not become healthy within %s", timeout)
}

// dumpClusterDiagnostics writes `docker compose ps` and the tail of each
// service's logs to the test log. Called from waitHealthy on timeout.
func dumpClusterDiagnostics(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("docker", "compose", "ps").CombinedOutput(); err == nil {
		t.Logf("docker compose ps:\n%s", out)
	} else {
		t.Logf("docker compose ps failed: %v", err)
	}
	for _, svc := range []string{"bsv-regtest", "bsv-miner", "node1", "node2", "node3"} {
		container := "bsvm-" + svc
		out, err := exec.Command("docker", "logs", "--tail", "120", container).CombinedOutput()
		if err != nil {
			t.Logf("docker logs %s failed: %v", container, err)
			continue
		}
		t.Logf("==== %s logs (tail 120) ====\n%s", svc, out)
	}
}

func postRPC(t *testing.T, url, method string, params interface{}) json.RawMessage {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", method, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: HTTP %d: %s", method, resp.StatusCode, raw)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("parsing %s response: %v: %s", method, err, raw)
	}
	if envelope.Error != nil {
		t.Fatalf("%s RPC error: code=%d %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	return envelope.Result
}

func TestDevnet_MockMode_SmokePath(t *testing.T) {
	root := repoRoot(t)

	// Clean slate before and after.
	runCompose(t, root, "down", "-v")
	t.Cleanup(func() { runCompose(t, root, "down", "-v") })

	runCompose(t, root, "up", "-d")
	waitHealthy(t, 90*time.Second)

	// 1. Every node returns chain ID 31337 (0x7a69).
	for _, port := range []int{8545, 8546, 8547} {
		url := fmt.Sprintf("http://localhost:%d", port)
		res := postRPC(t, url, "eth_chainId", []interface{}{})
		var chainIDHex string
		if err := json.Unmarshal(res, &chainIDHex); err != nil {
			t.Fatalf(":%d eth_chainId: %v", port, err)
		}
		if chainIDHex != "0x7a69" {
			t.Errorf(":%d eth_chainId: expected 0x7a69, got %s", port, chainIDHex)
		}
	}

	// 2. Hardhat #0 is pre-funded with 1000 wBSV on every node.
	const hardhat0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	const thousandWBSV = "0x3635c9adc5dea00000" // 1000 * 10^18
	for _, port := range []int{8545, 8546, 8547} {
		url := fmt.Sprintf("http://localhost:%d", port)
		res := postRPC(t, url, "eth_getBalance", []interface{}{hardhat0, "latest"})
		var bal string
		_ = json.Unmarshal(res, &bal)
		if bal != thousandWBSV {
			t.Errorf(":%d hardhat#0 balance: expected %s, got %s", port, thousandWBSV, bal)
		}
	}

	// 3. New bsv_* surface from spec 15 responds on every node.
	for _, m := range []string{"bsv_shardInfo", "bsv_networkHealth", "bsv_provingStatus", "bsv_bridgeStatus"} {
		res := postRPC(t, "http://localhost:8545", m, []interface{}{})
		if len(res) == 0 || string(res) == "null" {
			t.Errorf("%s: expected non-null result", m)
		}
	}

	// 4. /metrics endpoint exposes BSVM-prefixed Prometheus series with
	//    labels that distinguish nodes.
	assertMetricsHasSeries(t, "http://localhost:8545/metrics", `node_name="node1"`)
	assertMetricsHasSeries(t, "http://localhost:8546/metrics", `node_name="node2"`)

	// 5. GET / returns the embedded SPA (spec 15 placeholder or real build).
	assertGetHTML(t, "http://localhost:8545/")
}

func assertMetricsHasSeries(t *testing.T, url, labelFragment string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	if !strings.Contains(string(body), "bsvm_prover_workers") {
		t.Errorf("%s: missing bsvm_prover_workers series", url)
	}
	if !strings.Contains(string(body), labelFragment) {
		t.Errorf("%s: missing label fragment %q; first 400 bytes:\n%s",
			url, labelFragment, truncate(string(body), 400))
	}
}

func assertGetHTML(t *testing.T, url string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET %s: expected text/html, got %q", url, ct)
	}
	if !strings.Contains(string(body), "<title>") {
		t.Errorf("GET %s: response missing <title>; body:\n%s", url, truncate(string(body), 400))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
