package covenant

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// stubBSVClient is a minimal in-memory BSVClient for FeeWallet tests.
type stubBSVClient struct {
	mu        sync.Mutex
	utxos     []UTXO
	listErr   error
	broadcast func(rawHex string) (string, error)
}

func (s *stubBSVClient) ListUTXOs(_ context.Context, _ string) ([]UTXO, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]UTXO, len(s.utxos))
	copy(out, s.utxos)
	return out, nil
}

func (s *stubBSVClient) BroadcastTx(_ context.Context, rawHex string) (string, error) {
	if s.broadcast != nil {
		return s.broadcast(rawHex)
	}
	// Default: synthesize a deterministic txid hex (32 bytes of 0xAA).
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}

// stubKey implements PrivateKey with a hex pubkey-hash address. The
// SignInput callback returns a fixed dummy unlocking script — the
// FeeWallet test exercise only verifies that the broadcast path is
// called with the expected number of inputs, not that the resulting
// transaction is consensus-valid.
type stubKey struct {
	addr    string // 40-hex pubkey hash
	signErr error
}

func newStubKey() *stubKey {
	return &stubKey{addr: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
}

func (k *stubKey) Address() string { return k.addr }

func (k *stubKey) SignInput(_ string, _ int, _ string, _ uint64) (string, error) {
	if k.signErr != nil {
		return "", k.signErr
	}
	// 4 bytes of dummy script — len-prefix friendly, doesn't need to
	// be valid Bitcoin Script for the unit tests in this file.
	return "01020304", nil
}

// makeUTXO builds a UTXO with a deterministic txid derived from vout
// so the test's chosen orderings match what utxoKey produces.
func makeUTXO(vout uint32, sats uint64) UTXO {
	var txid types.Hash
	txid[0] = byte(vout)
	txid[1] = byte(vout >> 8)
	return UTXO{TxID: txid, Vout: vout, Satoshis: sats, Script: []byte{0x76, 0xa9, 0x14}}
}

// ---------------------------------------------------------------------------
// SelectUTXOs
// ---------------------------------------------------------------------------

func TestFeeWallet_SelectUTXOs_GreedyLargestFirst(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	for i, sats := range []uint64{1000, 5000, 2000, 7000} {
		fw.AddUTXO(makeUTXO(uint32(i), sats))
	}

	got, err := fw.SelectUTXOs(context.Background(), 4000)
	if err != nil {
		t.Fatalf("SelectUTXOs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 UTXO (largest >= target), got %d", len(got))
	}
	if got[0].Satoshis != 7000 {
		t.Errorf("expected 7000-sat largest UTXO, got %d", got[0].Satoshis)
	}
}

func TestFeeWallet_SelectUTXOs_FewestUTXOs(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	// Available: 1000, 2000, 3000 → sorted desc: 3000, 2000, 1000.
	for i, sats := range []uint64{1000, 2000, 3000} {
		fw.AddUTXO(makeUTXO(uint32(i), sats))
	}

	// Target 4500: need 3000 + 2000 = 5000 ≥ 4500, two UTXOs.
	got, err := fw.SelectUTXOs(context.Background(), 4500)
	if err != nil {
		t.Fatalf("SelectUTXOs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 UTXOs, got %d", len(got))
	}
	var sum uint64
	for _, u := range got {
		sum += u.Satoshis
	}
	if sum < 4500 {
		t.Errorf("selected sum %d < target 4500", sum)
	}
}

func TestFeeWallet_SelectUTXOs_InsufficientFunds(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 100))
	fw.AddUTXO(makeUTXO(1, 200))

	_, err := fw.SelectUTXOs(context.Background(), 1000)
	if !errors.Is(err, ErrFeeWalletEmpty) {
		t.Fatalf("expected ErrFeeWalletEmpty, got %v", err)
	}
}

func TestFeeWallet_SelectUTXOs_Empty(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	_, err := fw.SelectUTXOs(context.Background(), 1000)
	if !errors.Is(err, ErrFeeWalletEmpty) {
		t.Fatalf("expected ErrFeeWalletEmpty on empty wallet, got %v", err)
	}
}

func TestFeeWallet_SelectUTXOs_ZeroFeeRejected(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 1000))
	_, err := fw.SelectUTXOs(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error for zero-fee selection")
	}
}

func TestFeeWallet_SelectUTXOs_ParallelDisjoint(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	// 10 equal-sized UTXOs: any single one covers a 500-sat target.
	for i := uint32(0); i < 10; i++ {
		fw.AddUTXO(makeUTXO(i, 1000))
	}

	const goroutines = 5
	results := make([][]UTXO, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i], errs[i] = fw.SelectUTXOs(context.Background(), 500)
		}()
	}
	wg.Wait()

	seen := make(map[string]int)
	for i, sel := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		for _, u := range sel {
			k := utxoKey(u.TxID, u.Vout)
			seen[k]++
		}
	}
	for k, count := range seen {
		if count != 1 {
			t.Errorf("UTXO %s reserved by %d goroutines (want 1)", k, count)
		}
	}
}

func TestFeeWallet_SelectUTXOs_CtxCancel(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 1000))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fw.SelectUTXOs(ctx, 100)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Release / MarkSpent
// ---------------------------------------------------------------------------

func TestFeeWallet_Release_ReturnsToPool(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 5000))

	sel, err := fw.SelectUTXOs(context.Background(), 1000)
	if err != nil {
		t.Fatalf("SelectUTXOs: %v", err)
	}
	if got := fw.Balance(); got != 0 {
		t.Errorf("balance after select = %d, want 0", got)
	}

	fw.Release(sel)
	if got := fw.Balance(); got != 5000 {
		t.Errorf("balance after release = %d, want 5000", got)
	}

	// Reservation should be available again.
	sel2, err := fw.SelectUTXOs(context.Background(), 1000)
	if err != nil {
		t.Fatalf("re-SelectUTXOs after Release: %v", err)
	}
	if len(sel2) != 1 || sel2[0].Vout != 0 {
		t.Errorf("expected released UTXO to come back, got %+v", sel2)
	}
}

func TestFeeWallet_Release_Idempotent(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 5000))
	sel, _ := fw.SelectUTXOs(context.Background(), 1000)
	fw.Release(sel)
	fw.Release(sel) // second release is a no-op
	if got := fw.Balance(); got != 5000 {
		t.Errorf("balance after double-release = %d, want 5000", got)
	}
}

func TestFeeWallet_MarkSpent_RemovesFromPool(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 5000))

	sel, _ := fw.SelectUTXOs(context.Background(), 1000)
	fw.MarkSpent(sel)

	if got := fw.UTXOCount(); got != 0 {
		t.Errorf("UTXOCount after MarkSpent = %d, want 0", got)
	}

	// Re-adding the same UTXO must be a no-op now that it's spent.
	fw.AddUTXO(makeUTXO(0, 5000))
	if got := fw.UTXOCount(); got != 0 {
		t.Errorf("AddUTXO after MarkSpent should be ignored, got count %d", got)
	}
}

func TestFeeWallet_MarkSpent_BlocksReSelect(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 5000))
	fw.AddUTXO(makeUTXO(1, 5000))

	sel, err := fw.SelectUTXOs(context.Background(), 1000)
	if err != nil {
		t.Fatalf("SelectUTXOs: %v", err)
	}
	fw.MarkSpent(sel)

	// Even with the BSV node still reporting the UTXO as unspent,
	// Refresh must not put it back into the pool.
	client := fw.client.(*stubBSVClient)
	client.mu.Lock()
	client.utxos = []UTXO{makeUTXO(0, 5000), makeUTXO(1, 5000)}
	client.mu.Unlock()
	if err := fw.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Only the unspent UTXO should be back.
	if got := fw.UTXOCount(); got != 1 {
		t.Errorf("UTXOCount after Refresh = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Balance / FloatHealth
// ---------------------------------------------------------------------------

func TestFeeWallet_Balance(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	fw.AddUTXO(makeUTXO(0, 1000))
	fw.AddUTXO(makeUTXO(1, 2000))
	fw.AddUTXO(makeUTXO(2, 3000))
	if got := fw.Balance(); got != 6000 {
		t.Errorf("Balance = %d, want 6000", got)
	}
}

func TestFeeWallet_FloatHealth(t *testing.T) {
	tests := []struct {
		name     string
		minFloat uint64
		balance  uint64
		wantOK   bool
	}{
		{"disabled", 0, 0, true},
		{"disabled with funds", 0, 100, true},
		{"healthy", 1000, 5000, true},
		{"exact match", 1000, 1000, true},
		{"starved", 10_000, 5000, false},
		{"starved empty", 1000, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), tt.minFloat)
			if tt.balance > 0 {
				fw.AddUTXO(makeUTXO(0, tt.balance))
			}
			ok, balance, minFloat := fw.FloatHealth()
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if balance != tt.balance {
				t.Errorf("balance = %d, want %d", balance, tt.balance)
			}
			if minFloat != tt.minFloat {
				t.Errorf("minFloat = %d, want %d", minFloat, tt.minFloat)
			}
			if fw.IsStarved() == tt.wantOK {
				t.Errorf("IsStarved = %v, FloatHealth.ok = %v (should be inverse)", fw.IsStarved(), ok)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Consolidate
// ---------------------------------------------------------------------------

func TestFeeWallet_Consolidate_BelowThreshold(t *testing.T) {
	client := &stubBSVClient{}
	fw := NewFeeWallet(client, newStubKey(), 0)
	for i := uint32(0); i < 10; i++ {
		fw.AddUTXO(makeUTXO(i, 1000))
	}
	if err := fw.Consolidate(context.Background()); err != nil {
		t.Fatalf("Consolidate (below threshold): %v", err)
	}
	// Wallet untouched: 10 UTXOs, no broadcast attempted.
	if got := fw.UTXOCount(); got != 10 {
		t.Errorf("UTXOCount = %d, want 10 (no consolidation should run)", got)
	}
}

func TestFeeWallet_Consolidate_AtThreshold(t *testing.T) {
	var broadcastHex string
	client := &stubBSVClient{
		broadcast: func(rawHex string) (string, error) {
			broadcastHex = rawHex
			return "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", nil
		},
	}
	fw := NewFeeWallet(client, newStubKey(), 0)
	fw.SetConsolidationThreshold(5)

	for i := uint32(0); i < 10; i++ {
		fw.AddUTXO(makeUTXO(i, 1000))
	}

	if err := fw.Consolidate(context.Background()); err != nil {
		t.Fatalf("Consolidate: %v", err)
	}
	if broadcastHex == "" {
		t.Fatal("expected BroadcastTx to be called")
	}
	// After consolidation: one consolidated UTXO at the new txid.
	if got := fw.UTXOCount(); got != 1 {
		t.Errorf("UTXOCount after Consolidate = %d, want 1", got)
	}
	// Total balance: 10 * 1000 - fee. Fee is computed from the
	// estimator in fee_wallet_consolidate.go; the exact number is an
	// implementation detail. Just check it's < 10_000 and > 0.
	bal := fw.Balance()
	if bal == 0 || bal >= 10_000 {
		t.Errorf("Balance after consolidate = %d, want 0 < x < 10000", bal)
	}
}

func TestFeeWallet_Consolidate_BroadcastError(t *testing.T) {
	client := &stubBSVClient{
		broadcast: func(string) (string, error) {
			return "", errors.New("rpc unreachable")
		},
	}
	fw := NewFeeWallet(client, newStubKey(), 0)
	fw.SetConsolidationThreshold(2)
	for i := uint32(0); i < 5; i++ {
		fw.AddUTXO(makeUTXO(i, 1000))
	}

	err := fw.Consolidate(context.Background())
	if err == nil {
		t.Fatal("expected error from failed broadcast")
	}
	// Wallet state untouched: all 5 UTXOs still in available pool.
	if got := fw.UTXOCount(); got != 5 {
		t.Errorf("UTXOCount after failed Consolidate = %d, want 5", got)
	}
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

func TestFeeWallet_Refresh_AddsAndRemoves(t *testing.T) {
	client := &stubBSVClient{
		utxos: []UTXO{
			makeUTXO(0, 1000),
			makeUTXO(1, 2000),
		},
	}
	fw := NewFeeWallet(client, newStubKey(), 0)
	if err := fw.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := fw.UTXOCount(); got != 2 {
		t.Errorf("UTXOCount after Refresh = %d, want 2", got)
	}

	// Node now reports a different set: vout 0 is gone, vout 2 is new.
	client.mu.Lock()
	client.utxos = []UTXO{makeUTXO(1, 2000), makeUTXO(2, 3000)}
	client.mu.Unlock()
	if err := fw.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh 2: %v", err)
	}

	if got := fw.UTXOCount(); got != 2 {
		t.Errorf("UTXOCount after second Refresh = %d, want 2", got)
	}
	if got := fw.Balance(); got != 5000 {
		t.Errorf("Balance after second Refresh = %d, want 5000", got)
	}
}

func TestFeeWallet_Refresh_PreservesReserved(t *testing.T) {
	client := &stubBSVClient{
		utxos: []UTXO{makeUTXO(0, 1000), makeUTXO(1, 2000)},
	}
	fw := NewFeeWallet(client, newStubKey(), 0)
	if err := fw.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	sel, err := fw.SelectUTXOs(context.Background(), 1500)
	if err != nil {
		t.Fatalf("SelectUTXOs: %v", err)
	}
	// Re-running Refresh must not move reserved UTXOs back into the pool.
	if err := fw.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh 2: %v", err)
	}
	// Confirm we can't re-pick the reserved set.
	for _, u := range sel {
		k := utxoKey(u.TxID, u.Vout)
		if _, ok := fw.available[k]; ok {
			t.Errorf("reserved UTXO %s reappeared in available pool", k)
		}
	}
}

// ---------------------------------------------------------------------------
// Manager wiring
// ---------------------------------------------------------------------------

func TestCovenantManager_FeeWalletAccessor(t *testing.T) {
	cm := &CovenantManager{}
	if cm.FeeWallet() != nil {
		t.Fatal("expected nil fee wallet on bare manager")
	}
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	cm.SetFeeWallet(fw)
	if cm.FeeWallet() != fw {
		t.Fatal("FeeWallet() did not return the value set via SetFeeWallet")
	}
	cm.SetFeeWallet(nil)
	if cm.FeeWallet() != nil {
		t.Fatal("SetFeeWallet(nil) should clear the wallet")
	}
}

// ---------------------------------------------------------------------------
// Metrics hooks
// ---------------------------------------------------------------------------

func TestFeeWallet_MetricsHooks(t *testing.T) {
	fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
	var (
		balanceCalls int32
		lastBalance  uint64
		lastCount    int
		starvations  int32
	)
	fw.SetMetricsHooks(
		func(balance uint64, utxoCount int) {
			atomic.AddInt32(&balanceCalls, 1)
			lastBalance = balance
			lastCount = utxoCount
		},
		func() {
			atomic.AddInt32(&starvations, 1)
		},
	)

	fw.AddUTXO(makeUTXO(0, 1000))
	fw.AddUTXO(makeUTXO(1, 2000))
	if atomic.LoadInt32(&balanceCalls) < 2 {
		t.Errorf("expected at least 2 balance hook calls, got %d", balanceCalls)
	}
	if lastBalance != 3000 || lastCount != 2 {
		t.Errorf("hook reported balance=%d count=%d, want 3000/2", lastBalance, lastCount)
	}

	if _, err := fw.SelectUTXOs(context.Background(), 100_000); !errors.Is(err, ErrFeeWalletEmpty) {
		t.Fatalf("expected ErrFeeWalletEmpty, got %v", err)
	}
	if atomic.LoadInt32(&starvations) != 1 {
		t.Errorf("expected starvation hook to fire once, got %d", starvations)
	}
}

// Ensure SelectUTXOs returns deterministic ordering for the same pool
// regardless of map-iteration order.
func TestFeeWallet_SelectUTXOs_DeterministicOrder(t *testing.T) {
	const repeats = 5
	type result struct{ keys []string }
	results := make([]result, repeats)
	for r := 0; r < repeats; r++ {
		fw := NewFeeWallet(&stubBSVClient{}, newStubKey(), 0)
		for i, sats := range []uint64{1000, 2000, 3000, 4000} {
			fw.AddUTXO(makeUTXO(uint32(i), sats))
		}
		sel, err := fw.SelectUTXOs(context.Background(), 6000)
		if err != nil {
			t.Fatalf("SelectUTXOs: %v", err)
		}
		ks := make([]string, len(sel))
		for i, u := range sel {
			ks[i] = utxoKey(u.TxID, u.Vout)
		}
		results[r] = result{keys: ks}
	}
	// Sort each result's key list and compare — selection is a set, but
	// the greedy ordering should also be stable. We compare the sorted
	// set across runs to ensure no run picked a different combination.
	first := append([]string{}, results[0].keys...)
	sort.Strings(first)
	for i := 1; i < repeats; i++ {
		got := append([]string{}, results[i].keys...)
		sort.Strings(got)
		if fmt.Sprint(got) != fmt.Sprint(first) {
			t.Errorf("run %d picked %v, run 0 picked %v", i, got, first)
		}
	}
}
