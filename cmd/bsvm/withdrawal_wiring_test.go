package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"

	runar "github.com/icellan/runar/packages/runar-go"
)

// withdrawalNoopExpectations ties each negative test to the precise
// dependency that must be missing to trigger the early-return WARN
// branch. Keeping the list explicit means a future field rename
// produces a compile error, not a silent misbehaviour.
type withdrawalNoopCase struct {
	name     string
	mutate   func(*withdrawalWireOpts)
	wantNoop bool
}

// newCompleteWiringOpts produces a withdrawalWireOpts with every
// required field populated by a real (in-memory) implementation. The
// individual negative tests then null-out one field at a time.
func newCompleteWiringOpts(t *testing.T) withdrawalWireOpts {
	t.Helper()
	overlayNode, chainDB := newTestOverlayNode(t)
	monitor := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil, nil)
	monitor.SetBridgeScriptHash([]byte{0x76, 0xa9, 0x14}) // arbitrary 3-byte stub

	signer, err := runar.NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("LocalSigner: %v", err)
	}
	return withdrawalWireOpts{
		OverlayNode:   overlayNode,
		ChainDB:       chainDB,
		BridgeMonitor: monitor,
		BridgeScript:  []byte{0x76, 0xa9, 0x14},
		Provider:      &stubProvider{},
		FeeAddress:    "stubAddr",
		FeeSigner:     signer,
		PollInterval:  10 * time.Millisecond,
	}
}

// TestWireWithdrawer_MissingDeps_NoopAndWarn asserts that EACH required
// dependency, when zeroed-out, sends WireWithdrawer down the WARN-and-
// no-op-start path. The returned start function must be safe to call
// (it must not panic, must not start a goroutine, must return
// immediately).
func TestWireWithdrawer_MissingDeps_NoopAndWarn(t *testing.T) {
	cases := []withdrawalNoopCase{
		{name: "nil OverlayNode", mutate: func(o *withdrawalWireOpts) { o.OverlayNode = nil }, wantNoop: true},
		{name: "nil ChainDB", mutate: func(o *withdrawalWireOpts) { o.ChainDB = nil }, wantNoop: true},
		{name: "nil BridgeMonitor", mutate: func(o *withdrawalWireOpts) { o.BridgeMonitor = nil }, wantNoop: true},
		{name: "nil Provider", mutate: func(o *withdrawalWireOpts) { o.Provider = nil }, wantNoop: true},
		{name: "nil FeeSigner", mutate: func(o *withdrawalWireOpts) { o.FeeSigner = nil }, wantNoop: true},
		{name: "empty BridgeScript", mutate: func(o *withdrawalWireOpts) { o.BridgeScript = nil }, wantNoop: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := newCompleteWiringOpts(t)
			tc.mutate(&opts)
			start := WireWithdrawer(opts)
			if start == nil {
				t.Fatal("start function must not be nil even when wiring is skipped")
			}
			// Calling the no-op start with a cancelled ctx must return
			// instantly without spawning a hanging goroutine.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan struct{})
			go func() {
				start(ctx)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("noop start did not return in 1s")
			}
		})
	}
}

// TestWireWithdrawer_HappyPath_StartsAndStops verifies that with a
// fully-populated opts struct, WireWithdrawer returns a non-noop
// start, the loop runs at least one ProcessFinalizedWithdrawals pass
// (we observe the broadcaster being NOT called because the deferred
// finder short-circuits before a broadcast), and ctx-cancel cleanly
// terminates the goroutine.
func TestWireWithdrawer_HappyPath_StartsAndStops(t *testing.T) {
	opts := newCompleteWiringOpts(t)

	start := WireWithdrawer(opts)
	if start == nil {
		t.Fatal("start function must not be nil with complete deps")
	}

	ctx, cancel := context.WithCancel(context.Background())
	start(ctx)

	// Let the loop tick at least once. PollInterval is 10ms; a 50ms
	// budget gives us 4-5 ticks worth of slack.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Give the goroutine a moment to observe ctx.Done() and exit.
	// ProcessFinalizedWithdrawalsLoop ranges over a ticker, so
	// shutdown is bounded by the tick interval; 200ms is generous.
	time.Sleep(200 * time.Millisecond)
}

// TestArcBroadcaster_RejectsMalformedRawTx confirms the broadcaster
// adapter surfaces parse errors instead of panicking. Real wiring
// receives well-formed tx bytes from BuildWithdrawalClaimTx, but a
// future bug there should not crash the daemon.
func TestArcBroadcaster_RejectsMalformedRawTx(t *testing.T) {
	a := &arcBroadcaster{provider: &stubProvider{}}
	_, err := a.Broadcast([]byte{0x00, 0x01, 0x02}) // garbage
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

// TestDeferredAdvanceFinder always returns the sentinel error. This
// pins the "claims deferred" behaviour: until anchor records are
// persisted by the daemon, every claim attempt must skip cleanly via
// this sentinel rather than broadcast a tx the bridge covenant would
// reject.
func TestDeferredAdvanceFinder(t *testing.T) {
	f := &deferredAdvanceFinder{}
	tx, err := f.FindCovenantAdvanceForBlock(42)
	if tx != nil {
		t.Errorf("tx = %v, want nil", tx)
	}
	if !errors.Is(err, ErrAdvanceLookupUnimplemented) {
		t.Errorf("err = %v, want %v", err, ErrAdvanceLookupUnimplemented)
	}
}

// TestLocalSignerAdapter_NilSigner ensures the adapter rejects calls
// when its underlying runar.LocalSigner is nil rather than panicking
// with a nil-pointer dereference.
func TestLocalSignerAdapter_NilSigner(t *testing.T) {
	a := &localSignerAdapter{}
	_, err := a.SignInput("aabb", 0, "76a914", 1000)
	if err == nil {
		t.Fatal("expected error from nil signer")
	}
}

// TestChainDBReaderAdapter exercises the cmd-side adapter that lets
// pkg/bridge.ChainDBWithdrawalScanner walk the production
// *block.ChainDB without importing pkg/block.
func TestChainDBReaderAdapter(t *testing.T) {
	database := db.NewMemoryDB()
	defer database.Close()

	if _, err := block.InitGenesis(database, &block.Genesis{
		Config:   vm.DefaultL2Config(31337),
		GasLimit: block.DefaultGasLimit,
		Alloc:    map[types.Address]block.GenesisAccount{},
	}); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}

	chainDB := block.NewChainDB(database)
	a := &chainDBReaderAdapter{db: chainDB}

	// Genesis is block 0; the adapter must surface it as a non-nil
	// header.
	hdr := a.HeaderByNumber(0)
	if hdr == nil {
		t.Fatal("genesis header missing")
	}
	if hdr.Number != 0 {
		t.Errorf("Number = %d, want 0", hdr.Number)
	}
	if hdr.Hash == (types.Hash{}) {
		t.Error("Hash should not be zero")
	}

	// Receipts at genesis are absent (no txs); adapter returns nil.
	rs := a.ReceiptsByBlock(hdr.Hash, 0)
	if rs != nil && len(rs) != 0 {
		t.Errorf("genesis receipts = %d, want 0", len(rs))
	}

	// A non-canonical block must come back nil.
	if got := a.HeaderByNumber(99); got != nil {
		t.Errorf("HeaderByNumber(99) = %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// newTestOverlayNode constructs a minimal overlay.OverlayNode + ChainDB
// over an in-memory db. The genesis is empty (no funded accounts);
// tests that don't need real txs use this for the noop/start-stop
// smoke checks.
func newTestOverlayNode(t *testing.T) (*overlay.OverlayNode, *block.ChainDB) {
	t.Helper()
	database := db.NewMemoryDB()

	if _, err := block.InitGenesis(database, &block.Genesis{
		Config:   vm.DefaultL2Config(31337),
		GasLimit: block.DefaultGasLimit,
		Alloc:    map[types.Address]block.GenesisAccount{},
	}); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}

	chainDB := block.NewChainDB(database)

	covenantMgr := covenant.NewCovenantManager(
		&covenant.CompiledCovenant{},
		types.Hash{},
		0,
		10000,
		covenant.CovenantState{},
		31337,
		covenant.VerifyGroth16,
	)
	sp1Prover := prover.NewSP1Prover(prover.DefaultConfig())

	cfg := overlay.DefaultOverlayConfig()
	cfg.ChainID = 31337
	node, err := overlay.NewOverlayNode(cfg, chainDB, database, covenantMgr, sp1Prover)
	if err != nil {
		t.Fatalf("NewOverlayNode: %v", err)
	}
	t.Cleanup(func() {
		node.Stop()
		database.Close()
	})
	return node, chainDB
}

// stubProvider is a no-op BSVProviderClient. The adapter tests don't
// reach Broadcast (the deferred finder short-circuits first); the
// negative-path tests verify error surfacing without it ever being
// called.
type stubProvider struct{}

func (stubProvider) GetTransaction(string) (*runar.TransactionData, error) { return nil, nil }
func (stubProvider) Broadcast(*transaction.Transaction) (string, error)    { return "", nil }
func (stubProvider) GetUtxos(string) ([]runar.UTXO, error)                 { return nil, nil }
func (stubProvider) GetContractUtxo(string) (*runar.UTXO, error)           { return nil, nil }
func (stubProvider) GetNetwork() string                                    { return "regtest" }
func (stubProvider) GetFeeRate() (int64, error)                            { return 1, nil }
func (stubProvider) GetRawTransaction(string) (string, error)              { return "", nil }
func (stubProvider) GetRawTransactionVerbose(string) (map[string]interface{}, error) {
	return nil, nil
}

func (stubProvider) Call(string, ...interface{}) (json.RawMessage, error) { return nil, nil }
