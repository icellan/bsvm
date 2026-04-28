package prover

// SP1 circuit performance bench harness.
//
// After Cancun + state proofs (W4-1) + sender recovery (W4-2) +
// EIP-4844 + inbox drain (W4-3) all merged, no one had measured the
// guest's cycle count or proof generation time. This file is the cheap-
// perf-bench harness — it drives the bsvm-host-bench Rust binary
// (prover/host-bench/) over the same fixture set the dual-EVM
// comparator (equivalence_test.go) uses, captures cycle counts in
// EXECUTE mode (no proof — fast), and optionally captures proof time +
// proof size when BSVM_HOST_BENCH_PROVE=1 is set.
//
// # Output, not a gate
//
// The bench is a baseline tool. The OUTPUT (cycle counts, proof time)
// is the value, not a pass/fail signal. Mainnet go/no-go decisions on
// the SP1 budget are taken off this data, NOT in this test. We log
// budget targets alongside the actual numbers for context, but never
// hard-fail on a missed budget — that's a separate operator decision.
//
// # Budget targets (informational only)
//
// Per-tx execute cycles:
//   - simple txs (Legacy/AccessList/DynamicFee transfers, BlobTx without
//     blob-gas-heavy storage):  target < 5_000_000 cycles
//   - contract creation:        target < 50_000_000 cycles
//
// Full-batch proof time on a beefy single GPU (RTX 4090 class):
//   - target < 60s wall-clock
//   - measured only when --prove is set; the bench logs the number,
//     never asserts on it. CI boxes are CPU-only and would always
//     "fail" a wall-clock target so even a soft assertion would
//     produce useless red.
//
// # Skip behaviour
//
//   - testing.Short(): always skipped (the bench forks a Rust subprocess
//     that can take seconds-to-minutes per fixture).
//   - bsvm-host-bench binary missing: skipped with a clear message that
//     points the operator at the right cargo command. The test does NOT
//     auto-build because cargo can take >2 minutes from cold and should
//     never block `go test ./...`.
//   - BSVM_HOST_BENCH_PROVE=1 enables --prove for the FIRST fixture
//     only (proof generation is slow; measuring all fixtures with proofs
//     would blow up CI wall-time without adding signal — proof time
//     scales monotonically with cycles, so one data point per run is
//     enough to trip a regression alarm).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// benchOutput mirrors prover/host-bench/src/lib.rs::BenchOutput. Field
// shape MUST stay in sync; mismatches surface as JSON unmarshal errors
// at the harness boundary. Adding fields on the Rust side is fine (Go
// json.Unmarshal silently drops unknown keys); renames or removals
// break the bench loudly.
type benchOutput struct {
	Cycles           uint64  `json:"cycles"`
	Segments         uint64  `json:"segments"`
	Instructions     uint64  `json:"instructions"`
	PublicValuesHash string  `json:"public_values_hash"`
	PublicValues     string  `json:"public_values"`
	ExitCode         int     `json:"exit_code"`
	WallMs           uint64  `json:"wall_ms"`
	ProofGenMs       uint64  `json:"proof_gen_ms"`
	ProofBytes       uint64  `json:"proof_bytes"`
	VKHash           string  `json:"vk_hash"`
	SP1Version       string  `json:"sp1_version"`
	Error            *string `json:"error,omitempty"`
}

// budgetCycles returns the documented per-fixture cycle budget. Used
// only for log output; never asserted on. A missed budget surfaces as
// an obvious "(budget: 5M, MISSED)" string in the test log so an
// operator scanning CI output catches the regression immediately.
func budgetCycles(name string) uint64 {
	switch name {
	case "ContractCreate":
		return 50_000_000
	default:
		return 5_000_000
	}
}

// findHostBenchBinary locates the bsvm-host-bench binary. Mirrors
// findHostRevmBinary in equivalence_test.go so the lookup behaviour is
// consistent across bench and equivalence harnesses. Walks upwards
// from the cwd looking for prover/host-bench/target/{release,debug}/
// bsvm-host-bench. Returns ("", "<msg>") when not found so callers can
// t.Skip cleanly.
func findHostBenchBinary() (string, string) {
	exe := "bsvm-host-bench"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if env := os.Getenv("BSVM_HOST_BENCH_BINARY"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, ""
		}
		return "", fmt.Sprintf("BSVM_HOST_BENCH_BINARY=%s does not exist", env)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Sprintf("os.Getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		release := filepath.Join(dir, "prover", "host-bench", "target", "release", exe)
		if _, err := os.Stat(release); err == nil {
			return release, ""
		}
		debug := filepath.Join(dir, "prover", "host-bench", "target", "debug", exe)
		if _, err := os.Stat(debug); err == nil {
			return debug, ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", "bsvm-host-bench binary not found; build it once with " +
		"`cargo build --release --manifest-path prover/host-bench/Cargo.toml`"
}

// runHostBench invokes the bsvm-host-bench binary as a subprocess.
// Returns the parsed BenchOutput, or a fatal-test error on subprocess
// crash / non-zero exit / structured error envelope. The arg list is
// the bench binary's own CLI (e.g. ["--prove"]).
func runHostBench(t *testing.T, binary string, args []string, envelope []byte) *benchOutput {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Stdin = bytes.NewReader(envelope)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	out := &benchOutput{}
	if jerr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), out); jerr != nil {
		t.Fatalf("host-bench: unmarshal stdout: %v\nstdout: %s\nstderr: %s",
			jerr, stdout.String(), stderr.String())
	}
	if out.Error != nil {
		t.Fatalf("host-bench reported error: %s\nstderr: %s", *out.Error, stderr.String())
	}
	if runErr != nil {
		t.Fatalf("host-bench exited non-zero: %v\nstderr: %s", runErr, stderr.String())
	}
	return out
}

// buildBenchEnvelopeForFixture drives one equivalenceFixture through
// the Go EVM end-to-end (genesis → ProcessBatch → ExportStateForProving
// → buildBridgeInput) and returns the JSON envelope the bench binary
// expects. This is a thin wrapper over the existing prover plumbing so
// the bench measures cycles for the SAME inputs the dual-EVM
// equivalence test compares against.
//
// Returning the JSON envelope (not the ProveInput) keeps the bench
// driver decoupled from any future ProveInput shape changes — only
// buildBridgeInput needs to stay in sync with the Rust bridge / bench.
func buildBenchEnvelopeForFixture(t *testing.T, fx equivalenceFixture) []byte {
	t.Helper()

	database := db.NewMemoryDB()
	chainConfig := vm.DefaultL2Config(equivalenceChainID)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	// Pre-fund 1000 ETH so any fixture has gas + value headroom. Same
	// allocation the equivalence test uses; keeps cycle counts
	// comparable between bench and equivalence runs.
	genesis := block.DefaultGenesis(equivalenceChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(
		big.NewInt(1000),
		new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
	))
	genesis.Alloc = map[types.Address]block.GenesisAccount{
		senderAddr: {Balance: balance},
	}
	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	preStateRoot := genesisHeader.StateRoot

	signer := types.NewLondonSigner(big.NewInt(equivalenceChainID))
	tx := fx.build(t, key, signer)
	var encBuf bytes.Buffer
	if err := tx.EncodeRLP(&encBuf); err != nil {
		t.Fatalf("%s: EncodeRLP: %v", fx.name, err)
	}
	txBytes := encBuf.Bytes()

	preStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("%s: pre-state open: %v", fx.name, err)
	}
	execStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("%s: exec state open: %v", fx.name, err)
	}
	execStateDB.StartAccessRecording()

	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	chainCtx := &testChainContext{}

	l2Block, receipts, err := executor.ProcessBatch(
		genesisHeader, coinbaseAddr, 1000,
		[]*types.Transaction{tx},
		execStateDB, chainCtx,
	)
	if err != nil {
		t.Fatalf("%s: ProcessBatch: %v", fx.name, err)
	}
	if len(receipts) != 1 {
		t.Fatalf("%s: expected 1 receipt, got %d", fx.name, len(receipts))
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("%s: tx reverted, receipt status %d", fx.name, receipts[0].Status)
	}

	postStateRoot := l2Block.StateRoot()
	gasUsed := l2Block.GasUsed()
	receiptsHash := mpt.DeriveSha(types.Receipts(receipts))

	// Export the state for the SP1 guest. The bench needs the same
	// W4-1 Merkle witnesses production proving uses — without them the
	// host-bench binary rejects the envelope at the convert step.
	recording := execStateDB.StopAccessRecording()
	export, err := ExportStateForProving(preStateDB, recording.Accounts, recording.Slots)
	if err != nil {
		t.Fatalf("%s: ExportStateForProving: %v", fx.name, err)
	}
	stateExportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("%s: SerializeExport: %v", fx.name, err)
	}

	proveInput := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  stateExportJSON,
		Transactions: [][]byte{txBytes},
		BlockContext: BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  coinbaseAddr,
			GasLimit:  l2Block.GasLimit(),
			BaseFee:   0,
		},
		ExpectedResults: &ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  receiptsHash,
			GasUsed:       gasUsed,
			ChainID:       equivalenceChainID,
		},
	}

	envelopeJSON, err := buildBridgeInput(proveInput, "execute")
	if err != nil {
		t.Fatalf("%s: buildBridgeInput: %v", fx.name, err)
	}
	return envelopeJSON
}

// runBenchCase drives one fixture through the bench binary and logs
// the result. NEVER fails on cycle / wall-time budgets — those are
// informational. The only fatal conditions are subprocess crashes,
// JSON shape mismatches, or guest-reported errors (which are bugs in
// the wire format, not budget overruns).
func runBenchCase(t *testing.T, binary string, fx equivalenceFixture, prove bool) {
	t.Helper()
	envelope := buildBenchEnvelopeForFixture(t, fx)

	var args []string
	if prove {
		args = append(args, "--prove")
	}
	out := runHostBench(t, binary, args, envelope)

	budget := budgetCycles(fx.name)
	hit := "OK"
	if out.Cycles > budget {
		hit = "OVER"
	}
	// In --prove mode the cycle field is intentionally zero (SP1's
	// proof object doesn't carry a cycle count); we report the proof-
	// time and proof-size numbers instead, which are the value of a
	// --prove run.
	if prove {
		t.Logf("[bench] %s prove proof_gen_ms=%d proof_bytes=%d wall_ms=%d vk_hash=%s",
			fx.name, out.ProofGenMs, out.ProofBytes, out.WallMs, out.VKHash)
		// Document the wall-clock budget for context. We don't assert
		// on it — CI runs CPU-only and would always fail the GPU
		// target.
		const proofTimeBudgetMs = 60_000
		state := "OK"
		if out.ProofGenMs > proofTimeBudgetMs {
			state = "OVER (CI is CPU-only — GPU target is informational)"
		}
		t.Logf("[bench] %s prove time vs 60s GPU budget: %s", fx.name, state)
	} else {
		t.Logf("[bench] %s cycles=%d (budget: %d) wall_ms=%d %s",
			fx.name, out.Cycles, budget, out.WallMs, hit)
		// Also log instructions + segments + public-values shape so a
		// regression in any of these is visible in CI output.
		t.Logf("[bench] %s instructions=%d segments=%d pv_bytes=%d pv_hash=%s",
			fx.name, out.Instructions, out.Segments,
			(len(out.PublicValues)-2)/2, // strip "0x", divide by 2
			out.PublicValuesHash)
	}
}

// TestSP1Bench runs the bench harness over every equivalenceFixture.
// Logs cycle counts and budget comparisons; never fails on budget.
//
// To run end-to-end:
//
//	cargo build --release --manifest-path prover/host-bench/Cargo.toml
//	go test ./pkg/prover/ -run TestSP1Bench -v -count=1
//
// To also collect a proof-time data point on the first fixture:
//
//	BSVM_HOST_BENCH_PROVE=1 go test ./pkg/prover/ -run TestSP1Bench -v -count=1
//
// Skips cleanly when the binary isn't built so `go test ./...` stays
// green on hosts without a Rust toolchain.
func TestSP1Bench(t *testing.T) {
	if testing.Short() {
		t.Skip("SP1 bench harness forks a Rust subprocess; skipped under -short")
	}
	binary, skipMsg := findHostBenchBinary()
	if binary == "" {
		t.Skipf("%s", skipMsg)
	}

	prove := os.Getenv("BSVM_HOST_BENCH_PROVE") == "1"

	for i, fx := range equivalenceFixtures {
		fx := fx
		// Only the first fixture runs --prove (when enabled); the rest
		// stay execute-only. Proof generation is slow and scales with
		// cycles, so one --prove data point per run is enough signal
		// to flag a regression. Operators who want a full --prove
		// sweep can run the test multiple times pinning the fixture
		// via -run TestSP1Bench/<name>.
		isProveCase := prove && i == 0
		t.Run(fx.name, func(t *testing.T) {
			runBenchCase(t, binary, fx, isProveCase)
		})
	}
}
