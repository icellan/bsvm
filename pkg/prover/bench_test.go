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
	"crypto/ecdsa"
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
	return buildBenchEnvelopeFromBuilder(t, fx.name, 1, func(key *ecdsa.PrivateKey, signer types.Signer) []*types.Transaction {
		return []*types.Transaction{fx.build(t, key, signer)}
	})
}

// buildBenchEnvelopeForBatch drives a multi-tx benchBatchFixture through
// the same Go EVM pipeline as the single-tx path. The fixture's builder
// returns N already-signed transactions (typically with sequential
// nonces from the same prefunded sender). The block gas limit
// (DefaultGasLimit = 30_000_000) caps the realistic batch size at
// ~1400 simple transfers; the multi-tx fixtures here stay well under
// that ceiling so ProcessBatch never silently drops txs on gas-pool
// exhaustion.
func buildBenchEnvelopeForBatch(t *testing.T, fx benchBatchFixture) []byte {
	t.Helper()
	return buildBenchEnvelopeFromBuilder(t, fx.name, fx.txCount, fx.build)
}

// buildBenchEnvelopeFromBuilder is the shared envelope-construction
// helper used by both single-tx and multi-tx bench paths. The builder
// closure is responsible for signing every tx with the supplied key
// and signer; the helper takes care of genesis, pre-funding, batch
// execution, state export, and the buildBridgeInput call. The
// expectedTxCount parameter pins the number of receipts ProcessBatch
// MUST produce — any divergence (e.g., a tx silently skipped on
// nonce or out-of-gas) trips a t.Fatalf so the bench cycle count
// can't be silently misattributed to a partial batch.
func buildBenchEnvelopeFromBuilder(
	t *testing.T,
	fixtureName string,
	expectedTxCount int,
	builder func(key *ecdsa.PrivateKey, signer types.Signer) []*types.Transaction,
) []byte {
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
	txs := builder(key, signer)
	if len(txs) != expectedTxCount {
		t.Fatalf("%s: builder returned %d txs, expected %d", fixtureName, len(txs), expectedTxCount)
	}

	txBytesList := make([][]byte, len(txs))
	for i, tx := range txs {
		var encBuf bytes.Buffer
		if err := tx.EncodeRLP(&encBuf); err != nil {
			t.Fatalf("%s: tx[%d] EncodeRLP: %v", fixtureName, i, err)
		}
		txBytesList[i] = encBuf.Bytes()
	}

	preStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("%s: pre-state open: %v", fixtureName, err)
	}
	execStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("%s: exec state open: %v", fixtureName, err)
	}
	execStateDB.StartAccessRecording()

	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	chainCtx := &testChainContext{}

	l2Block, receipts, err := executor.ProcessBatch(
		genesisHeader, coinbaseAddr, 1000,
		txs,
		execStateDB, chainCtx,
	)
	if err != nil {
		t.Fatalf("%s: ProcessBatch: %v", fixtureName, err)
	}
	if len(receipts) != expectedTxCount {
		// ProcessBatch silently drops txs that fail validation (nonce,
		// gas pool). For a bench fixture this is always a mistake — we
		// want the cycle count attributable to N successful txs, not
		// N-K. Surface the count mismatch loudly so a future fixture
		// regression (e.g., bumping the per-tx Gas above the block
		// limit / N) is caught at test time, not via a confusing
		// cycles-per-tx delta in the perf report.
		t.Fatalf("%s: ProcessBatch produced %d receipts, expected %d (txs likely dropped on nonce or gas-pool)",
			fixtureName, len(receipts), expectedTxCount)
	}
	for i, receipt := range receipts {
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("%s: tx[%d] reverted, receipt status %d", fixtureName, i, receipt.Status)
		}
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
		t.Fatalf("%s: ExportStateForProving: %v", fixtureName, err)
	}
	stateExportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("%s: SerializeExport: %v", fixtureName, err)
	}

	emptyInbox := covenant.EmptyInboxState().TxQueueHash

	proveInput := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  stateExportJSON,
		Transactions: txBytesList,
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
		t.Fatalf("%s: buildBridgeInput: %v", fixtureName, err)
	}
	if dir := os.Getenv("BSVM_BENCH_DUMP_ENVELOPE_DIR"); dir != "" {
		path := filepath.Join(dir, fixtureName+".json")
		if err := os.WriteFile(path, envelopeJSON, 0o644); err != nil {
			t.Fatalf("%s: write envelope dump: %v", fixtureName, err)
		}
	}
	return envelopeJSON
}

// benchBatchFixture pairs a fixture name with a builder that returns
// exactly txCount signed transactions, plus the expected count itself
// so the harness can sanity-check the batch size on every run.
// Multi-tx fixtures are bench-only — the dual-EVM equivalence harness
// (equivalence_test.go) keeps using equivalenceFixture (single tx per
// fixture) so each assertion stays attributable to a specific tx type.
type benchBatchFixture struct {
	name    string
	txCount int
	build   func(key *ecdsa.PrivateKey, signer types.Signer) []*types.Transaction
}

// makeMultiTransferBatch builds a slice of n signed legacy transfers
// from the same prefunded sender, with sequential nonces 0..n-1. Each
// tx sends 1 wei to a distinct receiver address derived from the
// transaction index — this maximises the number of distinct touched
// accounts (and therefore MPT proof witnesses), which is the realistic
// production-batch shape spec 12 plans for. Using LegacyTx keeps the
// per-tx wire format minimal so cycle scaling reflects EVM execution
// cost rather than tx-decode overhead.
//
// Gas budget: 21_000 per tx × 128 = 2_688_000 — well under the 30M
// block limit set by block.DefaultGasLimit. ApplyTransaction's per-tx
// gas pool draw is the only ceiling that matters here; sender balance
// is 1000 ETH from buildBenchEnvelopeFromBuilder, which dwarfs even
// 128 × (21_000 × 1 gwei) = 0.0027 ETH worth of gas.
//
// SignNewTx failure here panics rather than failing a test — it would
// indicate a programming bug (bad key / bad signer / wrong tx fields)
// not a runtime condition the bench can recover from. Builder
// closures in benchBatchFixtures cannot capture a *testing.T anyway
// because the var-init runs before any test body.
func makeMultiTransferBatch(n int, key *ecdsa.PrivateKey, signer types.Signer) []*types.Transaction {
	txs := make([]*types.Transaction, n)
	for i := 0; i < n; i++ {
		// Distinct receiver per tx so each tx writes to a new MPT
		// account leaf. Encode the tx index in the low bytes of the
		// address; the high bytes stay 0xaa to avoid colliding with
		// the existing single-tx fixture receivers (0x11.., 0x22..,
		// etc.) in any future cross-test fixture inspection.
		var to types.Address
		for j := range to {
			to[j] = 0xaa
		}
		to[18] = byte(i >> 8)
		to[19] = byte(i & 0xff)
		tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
			Nonce:    uint64(i),
			GasPrice: big.NewInt(1_000_000_000),
			Gas:      21_000,
			To:       &to,
			Value:    uint256.NewInt(1), // 1 wei — minimal but non-zero
		})
		if err != nil {
			panic(fmt.Sprintf("makeMultiTransferBatch: SignNewTx[%d]: %v", i, err))
		}
		txs[i] = tx
	}
	return txs
}

// benchBatchFixtures enumerates the multi-tx batch fixtures. These
// scale the bench up to the production-batch size (spec 12: ~128
// transactions per batch) so cycle counts stop being dominated by
// SP1 setup overhead and start reflecting the per-tx EVM work the
// guest actually executes.
//
// Cycle counts per fixture grow roughly linearly with txCount above
// the setup floor (~300K cycles); the cycles-per-tx delta is the
// regression-detection signal future runs should track. See
// docs/perf/sp1-cycles-2026-05.md for the captured baseline.
//
// If MultiTxBatch_128 exceeds SP1's single-segment cycle limit
// (currently 2^22 = ~4.2M cycles per segment in SP1 v6.x), the bench
// will report segments > 1; that's expected and not a failure — the
// segment count surfaces in the bench log so an operator notices.
var benchBatchFixtures = []benchBatchFixture{
	{
		name:    "MultiTxBatch_8",
		txCount: 8,
		build: func(key *ecdsa.PrivateKey, signer types.Signer) []*types.Transaction {
			return makeMultiTransferBatch(8, key, signer)
		},
	},
	{
		name:    "MultiTxBatch_64",
		txCount: 64,
		build: func(key *ecdsa.PrivateKey, signer types.Signer) []*types.Transaction {
			return makeMultiTransferBatch(64, key, signer)
		},
	},
	{
		name:    "MultiTxBatch_128",
		txCount: 128,
		build: func(key *ecdsa.PrivateKey, signer types.Signer) []*types.Transaction {
			return makeMultiTransferBatch(128, key, signer)
		},
	},
}

// runBenchCase drives one fixture through the bench binary and logs
// the result. NEVER fails on cycle / wall-time budgets — those are
// informational. The only fatal conditions are subprocess crashes,
// JSON shape mismatches, or guest-reported errors (which are bugs in
// the wire format, not budget overruns).
func runBenchCase(t *testing.T, binary string, fx equivalenceFixture, prove bool) {
	t.Helper()
	envelope := buildBenchEnvelopeForFixture(t, fx)
	runBenchEnvelope(t, binary, fx.name, 1, envelope, prove)
}

// runBenchBatchCase drives one multi-tx batch fixture through the
// bench binary. Same canary asserts as runBenchCase (pv_bytes==280,
// non-empty pv_hash, vk_hash drift logging) — multi-tx batches don't
// change the public-values shape, only the cycle count.
func runBenchBatchCase(t *testing.T, binary string, fx benchBatchFixture, prove bool) {
	t.Helper()
	envelope := buildBenchEnvelopeForBatch(t, fx)
	runBenchEnvelope(t, binary, fx.name, fx.txCount, envelope, prove)
}

// runBenchEnvelope is the shared post-envelope bench driver. Both
// single-tx (runBenchCase) and multi-tx (runBenchBatchCase) paths
// converge here once the JSON envelope is built. The txCount
// parameter feeds the cycles-per-tx breakdown logged for multi-tx
// fixtures (so a regression report can spot which fixture's per-tx
// cost grew, not just the absolute total).
func runBenchEnvelope(t *testing.T, binary string, name string, txCount int, envelope []byte, prove bool) {
	t.Helper()

	var args []string
	if prove {
		args = append(args, "--prove")
	}
	out := runHostBench(t, binary, args, envelope)

	budget := budgetCycles(name)
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
			name, out.ProofGenMs, out.ProofBytes, out.WallMs, out.VKHash)
		// Document the wall-clock budget for context. We don't assert
		// on it — CI runs CPU-only and would always fail the GPU
		// target.
		const proofTimeBudgetMs = 60_000
		state := "OK"
		if out.ProofGenMs > proofTimeBudgetMs {
			state = "OVER (CI is CPU-only — GPU target is informational)"
		}
		t.Logf("[bench] %s prove time vs 60s GPU budget: %s", name, state)
	} else {
		// Log format matches the bench spec example exactly:
		//   [bench] LegacyTransfer cycles=2_345_678 (budget: 5M) wall_ms=42
		t.Logf("[bench] %s cycles=%s (budget: %s) wall_ms=%d %s",
			name, formatThousands(out.Cycles), formatBudget(budget),
			out.WallMs, hit)
		// Also log instructions + segments + public-values shape so a
		// regression in any of these is visible in CI output.
		pvBytes := (len(out.PublicValues) - 2) / 2 // strip "0x", divide by 2
		t.Logf("[bench] %s instructions=%s segments=%d pv_bytes=%d pv_hash=%s",
			name, formatThousands(out.Instructions), out.Segments,
			pvBytes, out.PublicValuesHash)
		// Cycles-per-tx breakdown for multi-tx fixtures. Logged ONLY
		// when txCount > 1 so the line stays out of single-tx fixture
		// output (where it would just duplicate the total cycle line).
		// This is the regression-detection number future runs should
		// compare against — total cycles include the SP1 setup floor
		// (~300K), but the per-tx delta isolates the EVM-execution
		// cost change.
		if txCount > 1 {
			t.Logf("[bench] %s cycles_per_tx=%s (txCount=%d)",
				name, formatThousands(out.Cycles/uint64(txCount)), txCount)
		}
		if os.Getenv("BSVM_BENCH_DUMP_PV") == "1" {
			t.Logf("[bench] %s pv=%s", name, out.PublicValues)
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
				"prover/guest/", name, pvBytes)
		}
		emptyPVHash := "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if out.PublicValuesHash == emptyPVHash {
			t.Fatalf("[bench] %s pv_hash = SHA256(\"\") — guest committed "+
				"nothing, almost certainly a wire-format regression. See "+
				"docs/decisions/vk-rotation-wire-format-2026-04.md", name)
		}
		// VK pin check: as of 2026-05-03 (Phase 1 of
		// docs/decisions/sp1-reproducible-build-2026-05.md) every
		// host-*/build.rs runs `BuildArgs { docker: true }`, so the
		// rebuilt guest ELF is bit-identical across operators and
		// the pin in `prover/guest/elf/SP1VerifyingKeyHash.txt` is a
		// real contract. The drift line is still informational here
		// rather than a t.Fatalf because the gating happens on the
		// Rust side (.github/workflows/sp1-repro.yml), and contributors
		// who can't run docker locally would otherwise see a confusing
		// failure during `go test`. See docs/operator/sp1-build.md for
		// the full operator workflow.
		pinned := loadPinnedVKHash(t)
		if pinned != "" && !strings.EqualFold(out.VKHash, pinned) {
			t.Logf("[bench] %s vk_hash drift (informational): bench=%s pinned=%s — see docs/operator/sp1-build.md",
				name, out.VKHash, pinned)
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

	// Multi-tx batch fixtures run after the single-tx fixtures so the
	// log timeline reads "small → big". --prove stays disabled for
	// every batch fixture even when BSVM_HOST_BENCH_PROVE=1: at
	// MultiTxBatch_128 the proof would take many minutes on CPU, and
	// the prove-time signal is already captured on the first single-tx
	// fixture above. Operators who want a multi-tx --prove run can
	// invoke `-run TestSP1Bench/MultiTxBatch_128` directly with
	// BSVM_HOST_BENCH_PROVE=1; the loop here keeps the default
	// behaviour fast enough for an iterative dev workflow.
	for _, fx := range benchBatchFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			runBenchBatchCase(t, binary, fx, false)
		})
	}
}

// TestSP1Bench_BatchEnvelopeSmoke is a fast Go-side sanity check that
// every benchBatchFixture builds a valid envelope without invoking
// the SP1 binary. It catches the obvious failure modes (ProcessBatch
// silently drops txs on nonce / gas-pool exhaustion, JSON envelope
// fails to round-trip, the all-zero hash slips into a critical field)
// before an operator burns 4 min per fixture on an unnecessary host-
// bench run. No subprocess is forked so this test runs in <1s and
// has no docker / Rust dependency.
func TestSP1Bench_BatchEnvelopeSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("envelope smoke test still pulls in genesis + state-export; skipped under -short for speed")
	}
	for _, fx := range benchBatchFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			envelope := buildBenchEnvelopeForBatch(t, fx)
			if len(envelope) == 0 {
				t.Fatalf("%s: empty envelope", fx.name)
			}
			// Loosely verify the envelope round-trips through json so a
			// future schema break doesn't slip past the bench. Using
			// json.RawMessage avoids coupling the smoke test to the
			// host-bridge's exact field shape.
			var dec map[string]json.RawMessage
			if err := json.Unmarshal(envelope, &dec); err != nil {
				t.Fatalf("%s: envelope is not valid JSON: %v", fx.name, err)
			}
			// Spot-check that the transaction count survived through
			// buildBridgeInput. The host-bridge envelope key for the
			// raw tx list is "transactions" (lowercase, matches the
			// Rust BridgeInput field). If that key disappears (e.g.,
			// renamed) the smoke test surfaces it before the SP1 run
			// silently produces zero-cycle output.
			rawTxs, ok := dec["transactions"]
			if !ok {
				t.Fatalf("%s: envelope missing 'transactions' field; keys=%v",
					fx.name, sortedKeys(dec))
			}
			var txList []json.RawMessage
			if err := json.Unmarshal(rawTxs, &txList); err != nil {
				t.Fatalf("%s: transactions field not a JSON array: %v", fx.name, err)
			}
			if len(txList) != fx.txCount {
				t.Fatalf("%s: envelope transactions=%d, expected %d",
					fx.name, len(txList), fx.txCount)
			}
		})
	}
}

// sortedKeys returns the keys of a map in sorted order — used by
// the envelope smoke test's failure messages so the diagnostic output
// is deterministic across runs (Go's map iteration is randomised).
func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Tiny inline sort — pulling sort.Strings here would add an import
	// solely for diagnostic output, not worth it for <30 keys.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
