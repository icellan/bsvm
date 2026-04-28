package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/types"
)

// fakeRecoveryBlockClient is the in-memory bridgeRecoveryBlockClient
// the recovery tests drive. blocks maps height → tx slice; missing
// heights return (nil, nil) (a real RPC node would too — we don't
// distinguish "block exists, empty" from "block missing" here because
// the recovery walks past either case identically).
type fakeRecoveryBlockClient struct {
	mu     sync.Mutex
	blocks map[uint64][]*bridge.BSVTransaction
	calls  int32
	err    error // when non-nil, every GetBlockTransactions returns it
}

func (f *fakeRecoveryBlockClient) GetBlockTransactions(height uint64) ([]*bridge.BSVTransaction, error) {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.blocks[height], nil
}

// fakeRecoveryHeaderOracle returns a fixed tip height. Used as the
// chaintracks subset the recovery actually consumes.
type fakeRecoveryHeaderOracle struct {
	tip uint64
	err error
}

func (f *fakeRecoveryHeaderOracle) Tip(_ context.Context) (*chaintracks.BlockHeader, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &chaintracks.BlockHeader{Height: f.tip}, nil
}

// silentLogger is the default logger for tests — a discard handler so
// the test output stays clean. Tests that want to assert on log lines
// override this with a buffer-backed logger.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// hashAt is a small helper for synthetic txid construction. The byte
// pattern is irrelevant; we just need distinct values across tests.
func hashAt(b byte) types.Hash {
	var h types.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// makeBridgeOutputTx builds a BSVTransaction with one output at vout=0
// paying to bridgeScript. Used to plant a "matching" tx in the chain
// fake.
func makeBridgeOutputTx(txid types.Hash, bridgeScript []byte, balanceSat uint64) *bridge.BSVTransaction {
	return &bridge.BSVTransaction{
		TxID: txid,
		Outputs: []bridge.BSVOutput{
			{Script: bridgeScript, Value: balanceSat},
		},
	}
}

// makeUnrelatedTx builds a BSV tx with no bridge-script output. Used
// to populate blocks that should NOT match.
func makeUnrelatedTx(txid types.Hash) *bridge.BSVTransaction {
	return &bridge.BSVTransaction{
		TxID: txid,
		Outputs: []bridge.BSVOutput{
			{Script: []byte{0x76, 0xa9}, Value: 1000}, // garbage script
		},
	}
}

func newRecoveryMonitor(t *testing.T) *bridge.BridgeMonitor {
	t.Helper()
	return bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil)
}

// TestRecoverBridgeUTXOFromChain_ChainMatchNoHint pins the
// "no operator hint, found on chain" branch: the monitor is seeded
// from the chain-discovered UTXO and the snapshot reflects that tx.
func TestRecoverBridgeUTXOFromChain_ChainMatchNoHint(t *testing.T) {
	bridgeScript := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	chainTxID := hashAt(0x01)

	chainClient := &fakeRecoveryHeaderOracle{tip: 100}
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{
			98: {makeUnrelatedTx(hashAt(0x99))},
			99: {makeBridgeOutputTx(chainTxID, bridgeScript, 5_000_000_000)},
			// Block 100 is the tip — no bridge tx there, so the recovery
			// should keep walking back.
			100: {makeUnrelatedTx(hashAt(0xaa))},
		},
	}

	monitor := newRecoveryMonitor(t)

	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		nil, // no hint
		bridgeScript,
		10, // small walk bound; tip-99 is within range
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil {
		t.Fatal("CurrentBridgeUTXO is nil; expected chain-discovered seed")
	}
	if got.TxID != chainTxID {
		t.Errorf("TxID = %x, want %x", got.TxID, chainTxID)
	}
	if got.Vout != 0 {
		t.Errorf("Vout = %d, want 0", got.Vout)
	}
	if got.Balance != 5_000_000_000 {
		t.Errorf("Balance = %d, want 5_000_000_000", got.Balance)
	}
}

// TestRecoverBridgeUTXOFromChain_HintAgreesWithChain pins the
// "hint matches chain" branch — chain still wins, but the operator's
// LastClaimedNonce is preserved (the chain walk has no view of it).
func TestRecoverBridgeUTXOFromChain_HintAgreesWithChain(t *testing.T) {
	bridgeScript := []byte{0xde, 0xad, 0xbe, 0xef}
	chainTxID := hashAt(0x42)

	chainClient := &fakeRecoveryHeaderOracle{tip: 50}
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{
			50: {makeBridgeOutputTx(chainTxID, bridgeScript, 1_234_567)},
		},
	}

	hint := &bridge.BridgeUTXO{
		TxID:             chainTxID,
		Vout:             0,
		Balance:          1_234_567,
		LastClaimedNonce: 7, // operator's nonce, NOT recoverable from chain alone
		Script:           bridgeScript,
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		hint,
		bridgeScript,
		10,
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil {
		t.Fatal("CurrentBridgeUTXO is nil")
	}
	if got.TxID != chainTxID || got.Vout != 0 || got.Balance != 1_234_567 {
		t.Errorf("outpoint mismatch: txid=%x vout=%d balance=%d",
			got.TxID, got.Vout, got.Balance)
	}
	if got.LastClaimedNonce != 7 {
		t.Errorf("LastClaimedNonce = %d, want 7 (preserved from hint)", got.LastClaimedNonce)
	}
}

// TestRecoverBridgeUTXOFromChain_HintContradictsChain pins the WARN
// branch: chain wins, but the operator's LastClaimedNonce is preserved
// (the only field the chain walk can't determine).
func TestRecoverBridgeUTXOFromChain_HintContradictsChain(t *testing.T) {
	bridgeScript := []byte{0x11, 0x22, 0x33}
	chainTxID := hashAt(0x77)
	staleHintTxID := hashAt(0x55)

	chainClient := &fakeRecoveryHeaderOracle{tip: 200}
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{
			199: {makeBridgeOutputTx(chainTxID, bridgeScript, 9_000_000_000)},
		},
	}

	hint := &bridge.BridgeUTXO{
		TxID:             staleHintTxID,
		Vout:             3,
		Balance:          1_000, // way off
		LastClaimedNonce: 12,
		Script:           bridgeScript,
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		hint,
		bridgeScript,
		10,
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil {
		t.Fatal("CurrentBridgeUTXO is nil; expected chain to win")
	}
	if got.TxID != chainTxID {
		t.Errorf("TxID = %x, want %x (chain wins)", got.TxID, chainTxID)
	}
	if got.Balance != 9_000_000_000 {
		t.Errorf("Balance = %d, want 9_000_000_000 (chain wins)", got.Balance)
	}
	// LastClaimedNonce comes from the operator hint, not the chain.
	if got.LastClaimedNonce != 12 {
		t.Errorf("LastClaimedNonce = %d, want 12 (preserved from hint)", got.LastClaimedNonce)
	}
}

// TestRecoverBridgeUTXOFromChain_NoMatchFallsBackToHint pins the
// "fresh shard or paused bridge" branch. With no on-chain match within
// the walk bound the recovery uses the operator hint verbatim.
func TestRecoverBridgeUTXOFromChain_NoMatchFallsBackToHint(t *testing.T) {
	bridgeScript := []byte{0xff, 0xee}
	hintTxID := hashAt(0xab)

	chainClient := &fakeRecoveryHeaderOracle{tip: 1000}
	// No bridge-output tx anywhere in the searchable range.
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{
			999: {makeUnrelatedTx(hashAt(0x01))},
			998: {makeUnrelatedTx(hashAt(0x02))},
			997: {makeUnrelatedTx(hashAt(0x03))},
		},
	}

	hint := &bridge.BridgeUTXO{
		TxID:             hintTxID,
		Vout:             1,
		Balance:          42,
		LastClaimedNonce: 0,
		Script:           bridgeScript,
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		hint,
		bridgeScript,
		5, // small bound; chain has no matches
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil {
		t.Fatal("CurrentBridgeUTXO is nil; expected hint fallback")
	}
	if got.TxID != hintTxID || got.Vout != 1 || got.Balance != 42 {
		t.Errorf("outpoint mismatch (expected hint): txid=%x vout=%d balance=%d",
			got.TxID, got.Vout, got.Balance)
	}
}

// TestRecoverBridgeUTXOFromChain_NoMatchNoHintLeavesNil pins the
// "fresh deployment with no operator hint" branch. The snapshot stays
// nil and the daemon stays bootable.
func TestRecoverBridgeUTXOFromChain_NoMatchNoHintLeavesNil(t *testing.T) {
	bridgeScript := []byte{0x42}

	chainClient := &fakeRecoveryHeaderOracle{tip: 5}
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{},
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		nil, // no hint
		bridgeScript,
		3,
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	if got := monitor.CurrentBridgeUTXO(); got != nil {
		t.Errorf("CurrentBridgeUTXO = %+v, want nil", got)
	}
}

// TestRecoverBridgeUTXOFromChain_StopsAtFirstMatch pins the "stop at
// the most recent advance" semantic. Two bridge-output txs in the
// chain — the recovery must take the higher (more recent) block.
func TestRecoverBridgeUTXOFromChain_StopsAtFirstMatch(t *testing.T) {
	bridgeScript := []byte{0x99}
	recentTxID := hashAt(0xa1)
	olderTxID := hashAt(0xa2)

	chainClient := &fakeRecoveryHeaderOracle{tip: 50}
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{
			48: {makeBridgeOutputTx(olderTxID, bridgeScript, 1)},
			49: {makeBridgeOutputTx(recentTxID, bridgeScript, 2)},
			// Tip itself has no match, but the walk should stop at 49.
		},
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		nil,
		bridgeScript,
		10,
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil {
		t.Fatal("CurrentBridgeUTXO is nil")
	}
	if got.TxID != recentTxID {
		t.Errorf("TxID = %x, want %x (most recent must win)", got.TxID, recentTxID)
	}
	if got.Balance != 2 {
		t.Errorf("Balance = %d, want 2 (most recent must win)", got.Balance)
	}
}

// TestRecoverBridgeUTXOFromChain_CtxCancelMidWalk pins clean exit on
// context cancellation. We arrange a chain that requires multiple
// blocks to scan and cancel before any match.
func TestRecoverBridgeUTXOFromChain_CtxCancelMidWalk(t *testing.T) {
	bridgeScript := []byte{0x33}

	chainClient := &fakeRecoveryHeaderOracle{tip: 10000}
	blockClient := &fakeRecoveryBlockClient{
		// No matches anywhere, but the walk bound is big — without
		// cancellation it'd churn through 1000 calls.
		blocks: map[uint64][]*bridge.BSVTransaction{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	monitor := newRecoveryMonitor(t)
	err := recoverBridgeUTXOFromChain(
		ctx,
		chainClient,
		blockClient,
		monitor,
		nil,
		bridgeScript,
		1000,
		silentLogger(),
	)
	if err == nil {
		t.Fatal("expected ctx cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if got := monitor.CurrentBridgeUTXO(); got != nil {
		t.Errorf("CurrentBridgeUTXO = %+v, want nil (cancelled before any seed)", got)
	}
}

// TestRecoverBridgeUTXOFromChain_BlockFetchUnsupported pins the
// chaintracks-only deployment branch: when the block client cannot
// fetch verbose blocks (no RPC, no WoC) the recovery aborts the walk
// gracefully and falls through to the hint.
func TestRecoverBridgeUTXOFromChain_BlockFetchUnsupported(t *testing.T) {
	bridgeScript := []byte{0xab}
	hintTxID := hashAt(0x55)

	chainClient := &fakeRecoveryHeaderOracle{tip: 100}
	blockClient := &fakeRecoveryBlockClient{err: ErrBlockFetchUnsupported}

	hint := &bridge.BridgeUTXO{
		TxID:             hintTxID,
		Vout:             0,
		Balance:          1_000_000,
		LastClaimedNonce: 0,
		Script:           bridgeScript,
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		hint,
		bridgeScript,
		10,
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil || got.TxID != hintTxID {
		t.Errorf("expected hint fallback (txid=%x), got %+v", hintTxID, got)
	}
}

// TestRecoverBridgeUTXOFromChain_NilMonitorIsNoOp confirms the
// recovery is safe to call when the bridge isn't wired for this shard.
func TestRecoverBridgeUTXOFromChain_NilMonitorIsNoOp(t *testing.T) {
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		&fakeRecoveryHeaderOracle{tip: 1},
		&fakeRecoveryBlockClient{},
		nil, // monitor
		nil, // hint
		[]byte{0x01},
		10,
		silentLogger(),
	); err != nil {
		t.Errorf("recoverBridgeUTXOFromChain with nil monitor: %v", err)
	}
}

// TestRecoverBridgeUTXOFromChain_DefaultWalkBound pins that walkBound=0
// resolves to defaultBridgeRecoveryWalkBound. We swap the default to a
// small value so the test runs in deterministic time.
func TestRecoverBridgeUTXOFromChain_DefaultWalkBound(t *testing.T) {
	prev := defaultBridgeRecoveryWalkBound
	defaultBridgeRecoveryWalkBound = 3
	t.Cleanup(func() { defaultBridgeRecoveryWalkBound = prev })

	bridgeScript := []byte{0x44}
	chainTxID := hashAt(0x10)

	chainClient := &fakeRecoveryHeaderOracle{tip: 100}
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{
			98: {makeBridgeOutputTx(chainTxID, bridgeScript, 50)},
			// 95 has a match too but it's out of the 3-block window.
			95: {makeBridgeOutputTx(hashAt(0x99), bridgeScript, 999)},
		},
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		nil,
		bridgeScript,
		0, // 0 = use default
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil || got.TxID != chainTxID {
		t.Errorf("expected chain match at height 98 (within default bound), got %+v", got)
	}
}

// TestRecoverBridgeUTXOFromChain_ChaintracksTipError falls through to
// the hint when chaintracks cannot serve the tip (cold cache, etc.).
func TestRecoverBridgeUTXOFromChain_ChaintracksTipError(t *testing.T) {
	bridgeScript := []byte{0xcd}
	hintTxID := hashAt(0x77)

	chainClient := &fakeRecoveryHeaderOracle{err: errors.New("chaintracks: cold cache")}
	blockClient := &fakeRecoveryBlockClient{}

	hint := &bridge.BridgeUTXO{
		TxID:    hintTxID,
		Vout:    2,
		Balance: 100,
		Script:  bridgeScript,
	}

	monitor := newRecoveryMonitor(t)
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		hint,
		bridgeScript,
		10,
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	got := monitor.CurrentBridgeUTXO()
	if got == nil || got.TxID != hintTxID {
		t.Errorf("expected hint fallback, got %+v", got)
	}
}

// TestBootPath_BuildBridgeMonitorThenRecover is the boot-path
// integration check the task calls for: BuildBridgeMonitor seeds the
// monitor from the operator hint, then recoverBridgeUTXOFromChain
// runs against a chain that holds a fresher UTXO. The end-to-end
// invariant is that CurrentBridgeUTXO() reflects the chain-discovered
// outpoint by the time the (would-be) block scanner is started.
func TestBootPath_BuildBridgeMonitorThenRecover(t *testing.T) {
	// 1. Build the monitor with an operator hint that's stale.
	const scriptHex = "76a914aabbccddeeff00112233445566778899aabbccdd88ac"
	staleTxIDHex := "1111111111111111111111111111111111111111111111111111111111111111"

	memDB := db.NewMemoryDB()
	monitor, scriptHashOut, err := BuildBridgeMonitor(
		BridgeSection{
			MinDepositSatoshis:         1000,
			BSVConfirmations:           3,
			BridgeUTXOTxIDHex:          staleTxIDHex,
			BridgeUTXOVout:             7,
			BridgeUTXOBalanceSat:       42,
			BridgeUTXOLastClaimedNonce: 5,
		},
		scriptHex,
		31337,
		memDB,
		nil,
	)
	if err != nil {
		t.Fatalf("BuildBridgeMonitor: %v", err)
	}
	if monitor == nil {
		t.Fatal("expected non-nil monitor")
	}
	// Sanity: the hint seeded the snapshot.
	if got := monitor.CurrentBridgeUTXO(); got == nil || got.Vout != 7 || got.Balance != 42 {
		t.Fatalf("post-Build seed: got %+v, want hint with vout=7 balance=42", got)
	}

	// 2. Plant a fresher UTXO on chain.
	freshTxID := hashAt(0xfa)
	chainClient := &fakeRecoveryHeaderOracle{tip: 100}
	blockClient := &fakeRecoveryBlockClient{
		blocks: map[uint64][]*bridge.BSVTransaction{
			99: {makeBridgeOutputTx(freshTxID, scriptHashOut, 9999)},
		},
	}

	// 3. Run recovery — this is the step that would happen between
	// BuildBridgeMonitor and startBridgeBlockScanner in main.go.
	hint := monitor.CurrentBridgeUTXO()
	if err := recoverBridgeUTXOFromChain(
		context.Background(),
		chainClient,
		blockClient,
		monitor,
		hint,
		scriptHashOut,
		10,
		silentLogger(),
	); err != nil {
		t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
	}

	// 4. By the time startBridgeBlockScanner would be called, the
	// snapshot must reflect the chain-discovered outpoint, with the
	// operator's LastClaimedNonce preserved.
	got := monitor.CurrentBridgeUTXO()
	if got == nil {
		t.Fatal("CurrentBridgeUTXO is nil after recovery")
	}
	if got.TxID != freshTxID {
		t.Errorf("TxID = %x, want %x (chain-discovered)", got.TxID, freshTxID)
	}
	if got.Vout != 0 {
		t.Errorf("Vout = %d, want 0 (chain-discovered)", got.Vout)
	}
	if got.Balance != 9999 {
		t.Errorf("Balance = %d, want 9999 (chain-discovered)", got.Balance)
	}
	if got.LastClaimedNonce != 5 {
		t.Errorf("LastClaimedNonce = %d, want 5 (preserved from operator hint)", got.LastClaimedNonce)
	}
}

// TestRecoverBridgeUTXOFromChain_TransientBlockErrorSkips pins that a
// per-block GetBlockTransactions error doesn't fail the recovery —
// the walk skips the bad height and keeps going.
func TestRecoverBridgeUTXOFromChain_TransientBlockErrorSkips(t *testing.T) {
	bridgeScript := []byte{0xe0}
	chainTxID := hashAt(0x20)

	chainClient := &fakeRecoveryHeaderOracle{tip: 50}
	// Inject an error on EVERY call. The recovery should keep skipping
	// down past walkBound without crashing, and end up returning
	// (nil, nil) → hint fallback.
	blockClient := &fakeRecoveryBlockClient{err: errors.New("rpc: 500 internal")}

	hint := &bridge.BridgeUTXO{
		TxID:    chainTxID,
		Vout:    0,
		Balance: 1,
		Script:  bridgeScript,
	}

	monitor := newRecoveryMonitor(t)
	deadline := time.After(2 * time.Second)
	done := make(chan error, 1)
	go func() {
		done <- recoverBridgeUTXOFromChain(
			context.Background(),
			chainClient,
			blockClient,
			monitor,
			hint,
			bridgeScript,
			5,
			silentLogger(),
		)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("recoverBridgeUTXOFromChain: %v", err)
		}
	case <-deadline:
		t.Fatal("recoverBridgeUTXOFromChain did not return within 2s")
	}

	// The hint should have been applied since the chain walk failed.
	if got := monitor.CurrentBridgeUTXO(); got == nil || got.TxID != chainTxID {
		t.Errorf("expected hint fallback after walk errors, got %+v", got)
	}
}
