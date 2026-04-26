package bridge

import (
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// TestBridgeMonitor_RetractDepositsAbove_Pending drops in-memory
// pending deposits above the supplied height and leaves entries at or
// below it untouched.
func TestBridgeMonitor_RetractDepositsAbove_Pending(t *testing.T) {
	m, _ := newTestMonitor(t)

	// Three pending deposits at heights 100, 105, 110.
	for i, h := range []uint64{100, 105, 110} {
		var txid types.Hash
		txid[0] = byte(i + 1)
		dep := NewDepositWithVout(txid, uint32(i), h,
			types.HexToAddress("0x3333333333333333333333333333333333333333"),
			20_000,
		)
		m.pendingDeposits = append(m.pendingDeposits, dep)
	}
	if got := m.PendingCount(); got != 3 {
		t.Fatalf("setup: PendingCount = %d, want 3", got)
	}

	// Retract above 104 — should drop the 105 + 110 entries, keep 100.
	m.RetractDepositsAbove(104)

	if got := m.PendingCount(); got != 1 {
		t.Fatalf("after retract: PendingCount = %d, want 1", got)
	}
	if m.pendingDeposits[0].BSVBlockHeight != 100 {
		t.Fatalf("survivor BSVBlockHeight = %d, want 100", m.pendingDeposits[0].BSVBlockHeight)
	}
}

// TestBridgeMonitor_RetractDepositsAbove_Persisted removes persisted
// deposits + clears their processed flags so the next ProcessBlock can
// re-credit them on the new chain.
func TestBridgeMonitor_RetractDepositsAbove_Persisted(t *testing.T) {
	m, store := newTestMonitor(t)

	// Persist three deposits at heights 200, 205, 210.
	for i, h := range []uint64{200, 205, 210} {
		var txid types.Hash
		txid[0] = byte(i + 0x80)
		dep := NewDepositWithVout(txid, uint32(i), h,
			types.HexToAddress("0x4444444444444444444444444444444444444444"),
			30_000,
		)
		dep.Confirmed = true
		if err := m.PersistDeposit(dep); err != nil {
			t.Fatalf("PersistDeposit: %v", err)
		}
	}
	if !m.IsProcessed(types.Hash{0x82}, 2) {
		t.Fatal("setup: third deposit should be processed")
	}

	// Retract above 204 — drops 205 + 210.
	m.RetractDepositsAbove(204)

	// 200 stays, 205 + 210 gone from the processed map AND from disk.
	if !m.IsProcessed(types.Hash{0x80}, 0) {
		t.Error("deposit at h=200 should still be processed")
	}
	if m.IsProcessed(types.Hash{0x81}, 1) {
		t.Error("deposit at h=205 should be retracted")
	}
	if m.IsProcessed(types.Hash{0x82}, 2) {
		t.Error("deposit at h=210 should be retracted")
	}

	// Re-load a fresh monitor from the same DB; only the height-200
	// entry should survive.
	m2 := NewBridgeMonitor(DefaultConfig(), &mockBSVClient{}, &mockOverlaySubmitter{}, store)
	if err := m2.LoadProcessedDeposits(); err != nil {
		t.Fatalf("LoadProcessedDeposits: %v", err)
	}
	if !m2.IsProcessed(types.Hash{0x80}, 0) {
		t.Error("after reload: deposit at h=200 should survive")
	}
	if m2.IsProcessed(types.Hash{0x81}, 1) {
		t.Error("after reload: deposit at h=205 should NOT survive")
	}
	if m2.IsProcessed(types.Hash{0x82}, 2) {
		t.Error("after reload: deposit at h=210 should NOT survive")
	}
}

// TestBridgeMonitor_RetractDepositsAbove_NoOp ensures retracting at a
// height above every recorded deposit is a no-op.
func TestBridgeMonitor_RetractDepositsAbove_NoOp(t *testing.T) {
	m, _ := newTestMonitor(t)

	dep := NewDepositWithVout(
		types.Hash{0xaa}, 0, 50,
		types.HexToAddress("0x5555555555555555555555555555555555555555"),
		15_000,
	)
	m.pendingDeposits = append(m.pendingDeposits, dep)

	m.RetractDepositsAbove(1000)

	if got := m.PendingCount(); got != 1 {
		t.Fatalf("PendingCount = %d, want 1 (no-op)", got)
	}
}
