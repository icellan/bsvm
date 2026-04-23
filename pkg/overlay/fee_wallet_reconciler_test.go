package overlay

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"

	runar "github.com/icellan/runar/packages/runar-go"
)

// stubUtxoSource is a minimal UtxoSource for reconciler tests. The
// response set is mutable (under a mutex) so individual subtests can
// swap it out between ReconcileOnce calls to simulate the BSV node
// view changing.
type stubUtxoSource struct {
	mu    sync.Mutex
	utxos []runar.UTXO
	err   error
	calls int32
}

func (s *stubUtxoSource) GetUtxos(address string) ([]runar.UTXO, error) {
	atomic.AddInt32(&s.calls, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	// Return a copy so the reconciler can't mutate our backing slice.
	cp := make([]runar.UTXO, len(s.utxos))
	copy(cp, s.utxos)
	return cp, nil
}

func (s *stubUtxoSource) set(utxos []runar.UTXO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.utxos = utxos
}

func (s *stubUtxoSource) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Deterministic 32-byte txid hex from an index so tests can build
// runar.UTXOs whose Txid string matches the FeeUTXO.TxID produced by
// types.HexToHash.
func txidHex(i int) string {
	var h types.Hash
	h[0] = byte(i)
	h[1] = byte(i >> 8)
	return hex.EncodeToString(h[:])
}

func runarUTXO(i int, vout int, sats int64) runar.UTXO {
	return runar.UTXO{
		Txid:        txidHex(i),
		OutputIndex: vout,
		Satoshis:    sats,
		// 76 a9 14 = OP_DUP OP_HASH160 <push 20>; padded to 25 bytes
		// for realism even though the reconciler treats it as opaque.
		Script: "76a914000000000000000000000000000000000000000088ac",
	}
}

func TestReconcileOnce_AddOnlyFromEmptyWallet(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	src := &stubUtxoSource{utxos: []runar.UTXO{
		runarUTXO(1, 0, 10000),
		runarUTXO(2, 0, 5000),
	}}

	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)
	added, removed, err := r.ReconcileOnce()
	if err != nil {
		t.Fatalf("ReconcileOnce err: %v", err)
	}
	if added != 2 || removed != 0 {
		t.Fatalf("added=%d removed=%d, want 2,0", added, removed)
	}
	if fw.UTXOCount() != 2 {
		t.Fatalf("UTXOCount=%d, want 2", fw.UTXOCount())
	}
	if fw.Balance() != 15000 {
		t.Fatalf("Balance=%d, want 15000", fw.Balance())
	}
}

func TestReconcileOnce_RemovesSpentUTXOs(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	// Pre-populate wallet with 2 UTXOs.
	if err := fw.AddUTXO(makeUTXO(1, 3000)); err != nil {
		t.Fatalf("AddUTXO 1: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(2, 4000)); err != nil {
		t.Fatalf("AddUTXO 2: %v", err)
	}

	// Network only reports the first UTXO — the second has been spent.
	src := &stubUtxoSource{utxos: []runar.UTXO{runarUTXO(1, 1, 3000)}}

	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)
	added, removed, err := r.ReconcileOnce()
	if err != nil {
		t.Fatalf("ReconcileOnce err: %v", err)
	}
	if added != 0 || removed != 1 {
		t.Fatalf("added=%d removed=%d, want 0,1", added, removed)
	}
	if fw.UTXOCount() != 1 {
		t.Fatalf("UTXOCount=%d, want 1", fw.UTXOCount())
	}
	if fw.Balance() != 3000 {
		t.Fatalf("Balance=%d, want 3000", fw.Balance())
	}
}

func TestReconcileOnce_AddAndRemoveTogether(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	// Pre-populate wallet with 2 UTXOs that the network won't report.
	if err := fw.AddUTXO(makeUTXO(10, 1000)); err != nil {
		t.Fatalf("AddUTXO: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(11, 2000)); err != nil {
		t.Fatalf("AddUTXO: %v", err)
	}

	// Network reports 2 brand-new UTXOs — e.g. after a consolidation
	// replaced the two originals with a fresh pair of outputs.
	src := &stubUtxoSource{utxos: []runar.UTXO{
		runarUTXO(20, 0, 500),
		runarUTXO(21, 0, 2500),
	}}

	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)
	added, removed, err := r.ReconcileOnce()
	if err != nil {
		t.Fatalf("ReconcileOnce err: %v", err)
	}
	if added != 2 || removed != 2 {
		t.Fatalf("added=%d removed=%d, want 2,2", added, removed)
	}
	if fw.UTXOCount() != 2 {
		t.Fatalf("UTXOCount=%d, want 2", fw.UTXOCount())
	}
	if fw.Balance() != 3000 {
		t.Fatalf("Balance=%d, want 3000", fw.Balance())
	}
}

func TestReconcileOnce_NoOpWhenFullyInSync(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	// makeUTXO(vout, sats) uses vout both for Vout and as TxID seed, so
	// runarUTXO must use the same int for both txid seed and output
	// index to land on the same utxoKey.
	if err := fw.AddUTXO(makeUTXO(5, 1000)); err != nil {
		t.Fatalf("AddUTXO: %v", err)
	}

	src := &stubUtxoSource{utxos: []runar.UTXO{runarUTXO(5, 5, 1000)}}
	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)
	added, removed, err := r.ReconcileOnce()
	if err != nil {
		t.Fatalf("ReconcileOnce err: %v", err)
	}
	if added != 0 || removed != 0 {
		t.Fatalf("added=%d removed=%d, want 0,0", added, removed)
	}
}

func TestReconcileOnce_SourceErrorPropagates(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	src := &stubUtxoSource{err: errors.New("rpc down")}

	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)
	added, removed, err := r.ReconcileOnce()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if added != 0 || removed != 0 {
		t.Fatalf("added=%d removed=%d, want 0,0 on error", added, removed)
	}
}

func TestReconcileOnce_SkipsMalformedNetworkUTXO(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	src := &stubUtxoSource{utxos: []runar.UTXO{
		{Txid: txidHex(1), OutputIndex: 0, Satoshis: 5000, Script: "not-hex"},
		runarUTXO(2, 0, 7000),
	}}
	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)
	added, removed, err := r.ReconcileOnce()
	if err != nil {
		t.Fatalf("ReconcileOnce err: %v", err)
	}
	if added != 1 || removed != 0 {
		t.Fatalf("added=%d removed=%d, want 1,0", added, removed)
	}
	if fw.Balance() != 7000 {
		t.Fatalf("Balance=%d, want 7000", fw.Balance())
	}
}

func TestReconcileOnce_SkipsNegativeFields(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	src := &stubUtxoSource{utxos: []runar.UTXO{
		{Txid: txidHex(1), OutputIndex: -1, Satoshis: 5000, Script: "00"},
		{Txid: txidHex(2), OutputIndex: 0, Satoshis: -1, Script: "00"},
		runarUTXO(3, 0, 4000),
	}}
	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)
	added, _, err := r.ReconcileOnce()
	if err != nil {
		t.Fatalf("ReconcileOnce err: %v", err)
	}
	if added != 1 {
		t.Fatalf("added=%d, want 1", added)
	}
}

func TestReconciler_StartStopLifecycle(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	src := &stubUtxoSource{utxos: []runar.UTXO{runarUTXO(1, 0, 1000)}}

	// Very short interval so the goroutine actually runs a reconcile
	// within the test's timeout.
	r := NewFeeWalletReconciler(fw, src, "mrAddr", 20*time.Millisecond)
	r.Start(context.Background())

	// Starting again must be a no-op (no second goroutine). We can't
	// directly observe goroutine count portably; instead we verify the
	// stop/done channels have not been replaced, so Stop() still works.
	r.Start(context.Background())

	// Wait for at least one reconcile pass.
	deadline := time.Now().Add(1 * time.Second)
	for fw.UTXOCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fw.UTXOCount() != 1 {
		t.Fatalf("reconciler never synced a UTXO: count=%d", fw.UTXOCount())
	}

	// Stop must return promptly.
	stopCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		r.Stop(stopCtx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Stop did not return within 2s")
	}

	// Stop called a second time must be a no-op (no panic, returns
	// immediately even with a very short context).
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer shortCancel()
	r.Stop(shortCtx)
}

func TestReconciler_StopWithoutStartIsNoOp(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	src := &stubUtxoSource{}
	r := NewFeeWalletReconciler(fw, src, "mrAddr", 0)

	// Must not block or panic when Stop is called without Start.
	r.Stop(context.Background())
}

func TestReconciler_ContextCancelStops(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())
	src := &stubUtxoSource{}
	r := NewFeeWalletReconciler(fw, src, "mrAddr", 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	cancel()

	// doneCh should close shortly after ctx cancels.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer stopCancel()
	done := make(chan struct{})
	go func() {
		r.Stop(stopCtx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("reconciler did not exit after context cancel")
	}
}

func TestReconciler_NilWalletOrSourceReturnsError(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	rNilSrc := NewFeeWalletReconciler(fw, nil, "mrAddr", 0)
	if _, _, err := rNilSrc.ReconcileOnce(); err == nil {
		t.Fatalf("expected error with nil source")
	}

	rNilWallet := NewFeeWalletReconciler(nil, &stubUtxoSource{}, "mrAddr", 0)
	if _, _, err := rNilWallet.ReconcileOnce(); err == nil {
		t.Fatalf("expected error with nil wallet")
	}
}
