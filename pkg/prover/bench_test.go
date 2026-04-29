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
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// benchChainID matches the SP1 guest's hardcoded `CHAIN_ID` constant
// (`prover/guest/src/main.rs::CHAIN_ID = 8453111`). The guest binds
// every signed user-tx's recovered sender to this chain via
// EIP-155, and commits the chain id at public-values offset
// [136..144]. Using any other chain id here causes
// `tx::decode_and_recover` to fail and the guest to commit
// `commit_error(0x20, …)` instead of running revm — masking real
// cycle counts. The dual-EVM equivalence test (`equivalence_test.go`)
// uses a different chain id (1337) because it compares against
// host-side revm directly, never going through the SP1 guest.
const benchChainID = 8453111

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
	chainConfig := vm.DefaultL2Config(benchChainID)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	// Pre-fund 1000 ETH so any fixture has gas + value headroom. Same
	// allocation the equivalence test uses; keeps cycle counts
	// comparable between bench and equivalence runs.
	genesis := block.DefaultGenesis(benchChainID)
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

	signer := types.NewLondonSigner(big.NewInt(benchChainID))
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

	emptyInbox := covenant.EmptyInboxState().TxQueueHash

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
		InboxRootBefore: emptyInbox,
		InboxRootAfter:  emptyInbox,
		ExpectedResults: &ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  receiptsHash,
			GasUsed:       gasUsed,
			ChainID:       benchChainID,
		},
	}

	envelopeJSON, err := buildBridgeInput(proveInput, "execute")
	if err != nil {
		t.Fatalf("%s: buildBridgeInput: %v", fx.name, err)
	}
	if dir := os.Getenv("BSVM_BENCH_DUMP_ENVELOPE_DIR"); dir != "" {
		path := filepath.Join(dir, fx.name+".json")
		if err := os.WriteFile(path, envelopeJSON, 0o644); err != nil {
			t.Fatalf("%s: write envelope dump: %v", fx.name, err)
		}
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
		// Log format matches the bench spec example exactly:
		//   [bench] LegacyTransfer cycles=2_345_678 (budget: 5M) wall_ms=42
		t.Logf("[bench] %s cycles=%s (budget: %s) wall_ms=%d %s",
			fx.name, formatThousands(out.Cycles), formatBudget(budget),
			out.WallMs, hit)
		// Also log instructions + segments + public-values shape so a
		// regression in any of these is visible in CI output.
		pvBytes := (len(out.PublicValues) - 2) / 2 // strip "0x", divide by 2
		t.Logf("[bench] %s instructions=%s segments=%d pv_bytes=%d pv_hash=%s",
			fx.name, formatThousands(out.Instructions), out.Segments,
			pvBytes, out.PublicValuesHash)
		if os.Getenv("BSVM_BENCH_DUMP_PV") == "1" {
			t.Logf("[bench] %s pv=%s", fx.name, out.PublicValues)
		}
		// Wire-format canary: the production guest commits exactly 280
		// bytes of public values (spec 12 — preStateRoot, postStateRoot,
		// receiptsHash, gasUsed, batchDataHash, chainId,
		// withdrawalRoot, inboxBefore, inboxAfter, migrateHash,
		// blockNumber). A short-circuited guest (e.g., bincode wire-
		// format mismatch panicking before the first commit) returns 0
		// pv bytes with `pv_hash = SHA256("")`. Asserting the size here
		// turns silent guest-side failures into test-time failures.
		// See `prover/guest/src/wire_format.rs` and
		// `docs/decisions/vk-rotation-wire-format-2026-04.md`.
		if pvBytes != 280 {
			t.Fatalf("[bench] %s short-pv (%d bytes); expected 280 — likely a "+
				"wire-format regression between host-bench and the guest. "+
				"Compare prover/host-bench/src/main.rs::GuestBatchInput "+
				"with prover/guest/src/main.rs::BatchInput field-by-field, "+
				"and run `cargo test --lib --release wire_format` in "+
				"prover/guest/", fx.name, pvBytes)
		}
		emptyPVHash := "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if out.PublicValuesHash == emptyPVHash {
			t.Fatalf("[bench] %s pv_hash = SHA256(\"\") — guest committed "+
				"nothing, almost certainly a wire-format regression. See "+
				"docs/decisions/vk-rotation-wire-format-2026-04.md", fx.name)
		}
		// VK pin diagnostic: SP1 ELF compilation is non-deterministic
		// across rebuilds (each `sp1_build::build_program` invocation
		// produces a fresh ELF even from byte-identical source — the
		// rebuilt ELF carries a different verifying-key hash). That
		// makes `prover/guest/elf/SP1VerifyingKeyHash.txt` a snapshot
		// of one specific reference build the operator chose, NOT a
		// gate that test runs can enforce. We log the drift so a CI
		// run can still surface it for review, but don't fail — a
		// fresh local rebuild always disagrees with the pin until the
		// operator restamps. See
		// docs/decisions/vk-rotation-wire-format-2026-04.md for the
		// reproducible-build follow-up.
		pinned := loadPinnedVKHash(t)
		if pinned != "" && !strings.EqualFold(out.VKHash, pinned) {
			t.Logf("[bench] %s vk_hash drift (informational): bench=%s pinned=%s",
				fx.name, out.VKHash, pinned)
		}
	}
}

// loadPinnedVKHash reads `prover/guest/elf/SP1VerifyingKeyHash.txt`
// (relative to the repo root) and returns the trimmed hash string. Walks
// upward from cwd to find the file so the helper works regardless of
// which package directory `go test` runs from. Returns "" if the file
// can't be located — the caller skips the pin check in that case so
// out-of-tree consumers don't see a confusing failure.
func loadPinnedVKHash(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 6; i++ {
		path := filepath.Join(dir, "prover", "guest", "elf", "SP1VerifyingKeyHash.txt")
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// formatThousands renders a uint64 with `_` thousand separators, e.g.
// `2_345_678`. Mirrors cmd/perf-summary's identically-named helper —
// duplicated here rather than imported because pkg/prover doesn't link
// against cmd/.
func formatThousands(v uint64) string {
	if v == 0 {
		return "0"
	}
	s := fmt.Sprintf("%d", v)
	pre := len(s) % 3
	var out []byte
	if pre > 0 {
		out = append(out, s[:pre]...)
		if len(s) > pre {
			out = append(out, '_')
		}
	}
	for i := pre; i < len(s); i += 3 {
		out = append(out, s[i:i+3]...)
		if i+3 < len(s) {
			out = append(out, '_')
		}
	}
	return string(out)
}

// formatBudget renders a budget cycle count compactly: 5_000_000 ⇒
// `5M`, 50_000_000 ⇒ `50M`. Falls back to formatThousands for values
// that aren't a whole number of millions, so a future budget like
// `7_500_000` still renders informatively.
func formatBudget(v uint64) string {
	if v >= 1_000_000 && v%1_000_000 == 0 {
		return fmt.Sprintf("%dM", v/1_000_000)
	}
	return formatThousands(v)
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
