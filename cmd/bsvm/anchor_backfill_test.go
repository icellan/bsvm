package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	cli "github.com/urfave/cli/v2"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// fakeStatusSource is a hand-rolled covenant.TransactionStatusSource for
// the runAnchorBackfill unit tests. It records every txid the backfill
// asks about and returns canned responses keyed by Hash.
type fakeStatusSource struct {
	mu       sync.Mutex
	statuses map[types.Hash]covenant.TxStatus
	errs     map[types.Hash]error
	calls    []types.Hash
}

func newFakeStatusSource() *fakeStatusSource {
	return &fakeStatusSource{
		statuses: make(map[types.Hash]covenant.TxStatus),
		errs:     make(map[types.Hash]error),
	}
}

func (f *fakeStatusSource) GetTransactionStatus(_ context.Context, txid types.Hash) (covenant.TxStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, txid)
	if e, ok := f.errs[txid]; ok {
		return covenant.TxStatus{}, e
	}
	return f.statuses[txid], nil
}

func (f *fakeStatusSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// makeAnchor returns a fresh AnchorRecord pointer.
func makeAnchor(blockNum uint64, txidHex string, height uint64, confirmed bool) *block.AnchorRecord {
	return &block.AnchorRecord{
		L2BlockNum:     blockNum,
		BSVTxID:        types.HexToHash(txidHex),
		BSVBlockHeight: height,
		Confirmed:      confirmed,
	}
}

// TestRunAnchorBackfill_MixedAnchors covers the headline case: a DB
// holding a mix of confirmed, unconfirmed-but-now-mined, and still-
// unmined anchors. The backfill should update only the unconfirmed-now-
// mined rows and leave the other two untouched.
func TestRunAnchorBackfill_MixedAnchors(t *testing.T) {
	chainDB := block.NewChainDB(db.NewMemoryDB())

	// Seed three anchors:
	//   block 1: already Confirmed=true with non-zero height — must be SKIPPED.
	//   block 2: Confirmed=false, BSV node says "now mined at height 1234" — must UPDATE.
	//   block 3: Confirmed=false, BSV node says "still in mempool" — must SKIP.
	a1 := makeAnchor(1, "0x11", 100, true)
	a2 := makeAnchor(2, "0x22", 0, false)
	a3 := makeAnchor(3, "0x33", 0, false)
	for _, a := range []*block.AnchorRecord{a1, a2, a3} {
		if err := chainDB.WriteAnchorRecord(a); err != nil {
			t.Fatalf("WriteAnchorRecord(%d): %v", a.L2BlockNum, err)
		}
	}

	src := newFakeStatusSource()
	src.statuses[a2.BSVTxID] = covenant.TxStatus{Confirmations: 5, BlockHeight: 1234}
	src.statuses[a3.BSVTxID] = covenant.TxStatus{Confirmations: 0, BlockHeight: 0}

	report, err := runAnchorBackfill(context.Background(), chainDB, src, anchorBackfillOpts{})
	if err != nil {
		t.Fatalf("runAnchorBackfill: %v", err)
	}

	if report.Processed != 3 {
		t.Errorf("Processed = %d, want 3", report.Processed)
	}
	if report.Updated != 1 {
		t.Errorf("Updated = %d, want 1", report.Updated)
	}
	if report.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", report.Skipped)
	}
	if report.Errored != 0 {
		t.Errorf("Errored = %d, want 0", report.Errored)
	}

	// Already-confirmed anchor should not have been re-RPC'd.
	if src.callCount() != 2 {
		t.Errorf("RPC calls = %d, want 2 (one per unconfirmed)", src.callCount())
	}

	// Verify a2 was updated, a1 unchanged, a3 unchanged.
	got1 := chainDB.ReadAnchorRecord(1)
	if !got1.Confirmed || got1.BSVBlockHeight != 100 {
		t.Errorf("anchor 1 mutated: %+v", got1)
	}
	got2 := chainDB.ReadAnchorRecord(2)
	if !got2.Confirmed || got2.BSVBlockHeight != 1234 {
		t.Errorf("anchor 2 = %+v, want Confirmed=true height=1234", got2)
	}
	got3 := chainDB.ReadAnchorRecord(3)
	if got3.Confirmed || got3.BSVBlockHeight != 0 {
		t.Errorf("anchor 3 should still be unconfirmed: %+v", got3)
	}
}

// TestRunAnchorBackfill_DryRun verifies --dry-run reports the same
// numbers as a live run but does NOT mutate ChainDB.
func TestRunAnchorBackfill_DryRun(t *testing.T) {
	chainDB := block.NewChainDB(db.NewMemoryDB())

	a := makeAnchor(7, "0x77", 0, false)
	if err := chainDB.WriteAnchorRecord(a); err != nil {
		t.Fatalf("WriteAnchorRecord: %v", err)
	}

	src := newFakeStatusSource()
	src.statuses[a.BSVTxID] = covenant.TxStatus{Confirmations: 9, BlockHeight: 999}

	report, err := runAnchorBackfill(context.Background(), chainDB, src, anchorBackfillOpts{
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("runAnchorBackfill (dry-run): %v", err)
	}
	if report.Updated != 1 {
		t.Errorf("dry-run Updated = %d, want 1", report.Updated)
	}

	got := chainDB.ReadAnchorRecord(7)
	if got.Confirmed {
		t.Errorf("dry-run mutated DB: anchor 7 = %+v", got)
	}
	if got.BSVBlockHeight != 0 {
		t.Errorf("dry-run mutated DB: anchor 7 height = %d, want 0", got.BSVBlockHeight)
	}
}

// TestRunAnchorBackfill_Idempotent verifies a second run on a freshly-
// updated DB is a no-op (every anchor flips to Skipped).
func TestRunAnchorBackfill_Idempotent(t *testing.T) {
	chainDB := block.NewChainDB(db.NewMemoryDB())

	a := makeAnchor(11, "0xaa", 0, false)
	if err := chainDB.WriteAnchorRecord(a); err != nil {
		t.Fatalf("WriteAnchorRecord: %v", err)
	}
	src := newFakeStatusSource()
	src.statuses[a.BSVTxID] = covenant.TxStatus{Confirmations: 2, BlockHeight: 42}

	if _, err := runAnchorBackfill(context.Background(), chainDB, src, anchorBackfillOpts{}); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Second run.
	src2 := newFakeStatusSource()
	// Don't seed any responses — second run must NOT issue any RPCs
	// because the anchor is already Confirmed=true with height>0.
	report, err := runAnchorBackfill(context.Background(), chainDB, src2, anchorBackfillOpts{})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if report.Updated != 0 {
		t.Errorf("idempotent run Updated = %d, want 0", report.Updated)
	}
	if report.Skipped != 1 {
		t.Errorf("idempotent run Skipped = %d, want 1", report.Skipped)
	}
	if src2.callCount() != 0 {
		t.Errorf("idempotent run made %d RPC calls; want 0", src2.callCount())
	}
}

// TestRunAnchorBackfill_RPCError counts RPC errors as Errored, not
// Updated or Skipped. The DB must remain unchanged for the failed row.
func TestRunAnchorBackfill_RPCError(t *testing.T) {
	chainDB := block.NewChainDB(db.NewMemoryDB())

	a := makeAnchor(5, "0x55", 0, false)
	if err := chainDB.WriteAnchorRecord(a); err != nil {
		t.Fatalf("WriteAnchorRecord: %v", err)
	}

	src := newFakeStatusSource()
	src.errs[a.BSVTxID] = errors.New("rpc unreachable")

	report, err := runAnchorBackfill(context.Background(), chainDB, src, anchorBackfillOpts{})
	if err != nil {
		t.Fatalf("runAnchorBackfill: %v", err)
	}
	if report.Errored != 1 {
		t.Errorf("Errored = %d, want 1", report.Errored)
	}
	if report.Updated != 0 {
		t.Errorf("Updated = %d, want 0", report.Updated)
	}

	got := chainDB.ReadAnchorRecord(5)
	if got.Confirmed {
		t.Errorf("RPC-failed anchor mutated: %+v", got)
	}
}

// TestRunAnchorBackfill_Limit asserts the --limit flag bounds the
// number of UNCONFIRMED rows processed.
func TestRunAnchorBackfill_Limit(t *testing.T) {
	chainDB := block.NewChainDB(db.NewMemoryDB())

	for i := uint64(1); i <= 10; i++ {
		// All unconfirmed.
		a := makeAnchor(i, "0xff", 0, false)
		// vary txid so each gets its own RPC slot
		txid := types.Hash{}
		txid[0] = byte(i)
		a.BSVTxID = txid
		if err := chainDB.WriteAnchorRecord(a); err != nil {
			t.Fatalf("WriteAnchorRecord(%d): %v", i, err)
		}
	}

	src := newFakeStatusSource()
	// All seeded as confirmed-now-mined so each row would update if not capped.
	for i := uint64(1); i <= 10; i++ {
		txid := types.Hash{}
		txid[0] = byte(i)
		src.statuses[txid] = covenant.TxStatus{Confirmations: 1, BlockHeight: 100 + i}
	}

	report, err := runAnchorBackfill(context.Background(), chainDB, src, anchorBackfillOpts{
		Limit: 3,
	})
	if err != nil {
		t.Fatalf("runAnchorBackfill: %v", err)
	}

	if report.Updated != 3 {
		t.Errorf("Updated = %d, want 3 (limit cap)", report.Updated)
	}
	if src.callCount() != 3 {
		t.Errorf("RPC calls = %d, want 3 (limit cap)", src.callCount())
	}
}

// TestRunAnchorBackfill_Empty walks an empty DB. No RPCs, no updates,
// no error.
func TestRunAnchorBackfill_Empty(t *testing.T) {
	chainDB := block.NewChainDB(db.NewMemoryDB())
	src := newFakeStatusSource()
	report, err := runAnchorBackfill(context.Background(), chainDB, src, anchorBackfillOpts{})
	if err != nil {
		t.Fatalf("runAnchorBackfill: %v", err)
	}
	if report.Processed != 0 || report.Updated != 0 || report.Errored != 0 {
		t.Errorf("empty DB report = %+v, want zero", report)
	}
}

// TestRunAnchorBackfill_NilArgs verifies the function rejects bad inputs
// loudly rather than panicking.
func TestRunAnchorBackfill_NilArgs(t *testing.T) {
	src := newFakeStatusSource()
	if _, err := runAnchorBackfill(context.Background(), nil, src, anchorBackfillOpts{}); err == nil {
		t.Error("expected error for nil ChainDB")
	}
	chainDB := block.NewChainDB(db.NewMemoryDB())
	if _, err := runAnchorBackfill(context.Background(), chainDB, nil, anchorBackfillOpts{}); err == nil {
		t.Error("expected error for nil status source")
	}
}

// TestAnchorBackfillCommand_RegistrationSmoke is the urfave/cli surface
// check: the subcommand must be visible at the top-level App so `bsvm
// anchor-backfill --help` resolves. Mirrors the smoke pattern used by
// the existing admin/dev subcommand surfaces.
func TestAnchorBackfillCommand_RegistrationSmoke(t *testing.T) {
	cmd := anchorBackfillCommand()
	if cmd == nil {
		t.Fatal("anchorBackfillCommand returned nil")
	}
	if cmd.Name != "anchor-backfill" {
		t.Errorf("subcommand name = %q, want %q", cmd.Name, "anchor-backfill")
	}
	// Sanity: check the flag set we documented in the task.
	flagNames := make(map[string]bool)
	for _, f := range cmd.Flags {
		for _, n := range f.Names() {
			flagNames[n] = true
		}
	}
	for _, want := range []string{"datadir", "bsv-rpc", "bsv-network", "dry-run", "limit"} {
		if !flagNames[want] {
			t.Errorf("missing --%s flag", want)
		}
	}

	// And confirm it integrates with a top-level App without panicking
	// (urfave/cli would panic on duplicate names / bad action signature).
	app := &cli.App{
		Name:     "bsvm-test",
		Commands: []*cli.Command{cmd},
	}
	if err := app.Run([]string{"bsvm-test", "anchor-backfill", "--help"}); err != nil {
		t.Errorf("--help on subcommand failed: %v", err)
	}
}
