package overlay

import (
	"bytes"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

func TestInboxMonitor_AddTransaction(t *testing.T) {
	im := NewInboxMonitor()

	initialHash := im.QueueHash()
	if im.PendingCount() != 0 {
		t.Fatalf("expected 0 pending, got %d", im.PendingCount())
	}

	txRLP := []byte{0x01, 0x02, 0x03, 0x04}
	im.AddInboxTransaction(txRLP)

	if im.PendingCount() != 1 {
		t.Fatalf("expected 1 pending, got %d", im.PendingCount())
	}

	newHash := im.QueueHash()
	if newHash == initialHash {
		t.Error("queue hash should change after adding a transaction")
	}

	// Hash should not be the zero hash.
	if newHash == (types.Hash{}) {
		t.Error("queue hash should not be the zero hash")
	}
}

func TestInboxMonitor_MultipleTransactions(t *testing.T) {
	im := NewInboxMonitor()

	for i := 0; i < 5; i++ {
		im.AddInboxTransaction([]byte{byte(i), 0xAA, 0xBB})
	}

	if im.PendingCount() != 5 {
		t.Fatalf("expected 5 pending, got %d", im.PendingCount())
	}
}

func TestInboxMonitor_MustDrainInbox_NotTriggered(t *testing.T) {
	im := NewInboxMonitor()

	// Add a pending transaction.
	im.AddInboxTransaction([]byte{0x01})

	// Record fewer than MaxAdvancesWithoutInboxDrain advances.
	for i := 0; i < MaxAdvancesWithoutInboxDrain-1; i++ {
		im.RecordAdvance()
	}

	if im.MustDrainInbox() {
		t.Error("MustDrainInbox should be false with fewer than 10 advances")
	}
}

func TestInboxMonitor_MustDrainInbox_Triggered(t *testing.T) {
	im := NewInboxMonitor()

	// Add a pending transaction.
	im.AddInboxTransaction([]byte{0x01})

	// Record exactly MaxAdvancesWithoutInboxDrain advances.
	for i := 0; i < MaxAdvancesWithoutInboxDrain; i++ {
		im.RecordAdvance()
	}

	if !im.MustDrainInbox() {
		t.Error("MustDrainInbox should be true after 10 advances with pending txs")
	}
}

func TestInboxMonitor_MustDrainInbox_NoPending(t *testing.T) {
	im := NewInboxMonitor()

	// No pending transactions — just record advances.
	for i := 0; i < MaxAdvancesWithoutInboxDrain+5; i++ {
		im.RecordAdvance()
	}

	if im.MustDrainInbox() {
		t.Error("MustDrainInbox should be false with no pending transactions")
	}
}

func TestInboxMonitor_DrainPending(t *testing.T) {
	im := NewInboxMonitor()

	tx1 := []byte{0x01, 0x02}
	tx2 := []byte{0x03, 0x04}
	tx3 := []byte{0x05, 0x06}
	im.AddInboxTransaction(tx1)
	im.AddInboxTransaction(tx2)
	im.AddInboxTransaction(tx3)

	// Record some advances.
	for i := 0; i < MaxAdvancesWithoutInboxDrain; i++ {
		im.RecordAdvance()
	}

	if !im.MustDrainInbox() {
		t.Fatal("expected MustDrainInbox to be true before drain")
	}

	// Drain pending transactions.
	pending := im.DrainPending()
	if len(pending) != 3 {
		t.Fatalf("expected 3 pending txs, got %d", len(pending))
	}
	if !bytes.Equal(pending[0], tx1) {
		t.Errorf("first tx mismatch: got %x, want %x", pending[0], tx1)
	}
	if !bytes.Equal(pending[1], tx2) {
		t.Errorf("second tx mismatch: got %x, want %x", pending[1], tx2)
	}
	if !bytes.Equal(pending[2], tx3) {
		t.Errorf("third tx mismatch: got %x, want %x", pending[2], tx3)
	}

	// After drain, state should be reset.
	if im.PendingCount() != 0 {
		t.Errorf("expected 0 pending after drain, got %d", im.PendingCount())
	}
	if im.MustDrainInbox() {
		t.Error("MustDrainInbox should be false after drain")
	}

	// Queue hash should be back to the initial empty hash.
	freshMonitor := NewInboxMonitor()
	if im.QueueHash() != freshMonitor.QueueHash() {
		t.Error("queue hash should be reset to empty hash after drain")
	}
}

func TestInboxMonitor_RecordAdvance(t *testing.T) {
	im := NewInboxMonitor()

	// Add a tx so MustDrainInbox can trigger.
	im.AddInboxTransaction([]byte{0x01})

	// Each call should increment the counter.
	for i := 0; i < MaxAdvancesWithoutInboxDrain; i++ {
		if im.MustDrainInbox() {
			t.Fatalf("MustDrainInbox should be false at advance %d", i)
		}
		im.RecordAdvance()
	}

	// After exactly MaxAdvancesWithoutInboxDrain calls, it should trigger.
	if !im.MustDrainInbox() {
		t.Error("MustDrainInbox should be true after max advances")
	}
}

func TestInboxMonitor_HashChainDeterminism(t *testing.T) {
	// Two monitors with the same transactions should produce the same hash.
	im1 := NewInboxMonitor()
	im2 := NewInboxMonitor()

	txs := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
		{0x07, 0x08, 0x09},
	}

	for _, tx := range txs {
		im1.AddInboxTransaction(tx)
		im2.AddInboxTransaction(tx)
	}

	if im1.QueueHash() != im2.QueueHash() {
		t.Error("same transactions should produce the same queue hash")
	}

	// Adding a different transaction should produce a different hash.
	im3 := NewInboxMonitor()
	for _, tx := range txs {
		im3.AddInboxTransaction(tx)
	}
	im3.AddInboxTransaction([]byte{0xFF})

	if im1.QueueHash() == im3.QueueHash() {
		t.Error("different transactions should produce different queue hashes")
	}
}

func TestInboxMonitor_AdvancesSinceDrain(t *testing.T) {
	im := NewInboxMonitor()

	// Initially zero.
	if im.AdvancesSinceDrain() != 0 {
		t.Fatalf("expected 0 advances since drain, got %d", im.AdvancesSinceDrain())
	}

	// Increment several times.
	for i := uint16(1); i <= 7; i++ {
		im.RecordAdvance()
		if im.AdvancesSinceDrain() != i {
			t.Fatalf("expected %d advances since drain, got %d", i, im.AdvancesSinceDrain())
		}
	}

	// Drain resets the counter.
	im.AddInboxTransaction([]byte{0x01})
	im.DrainPending()
	if im.AdvancesSinceDrain() != 0 {
		t.Fatalf("expected 0 advances after drain, got %d", im.AdvancesSinceDrain())
	}
}

func TestInboxMonitor_ForcedInclusion(t *testing.T) {
	im := NewInboxMonitor()

	// Add a transaction so forced inclusion can trigger.
	im.AddInboxTransaction([]byte{0xAA, 0xBB})

	// Advance 10 times — should trigger forced inclusion.
	for i := 0; i < MaxAdvancesWithoutInboxDrain; i++ {
		if im.MustDrainInbox() {
			t.Fatalf("MustDrainInbox should be false at advance %d", i)
		}
		im.RecordAdvance()
	}

	if !im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be true after 10 advances with pending txs")
	}
}

func TestInboxMonitor_DrainResetsCounter(t *testing.T) {
	im := NewInboxMonitor()

	// Add a transaction and record some advances.
	im.AddInboxTransaction([]byte{0x01})
	for i := 0; i < 5; i++ {
		im.RecordAdvance()
	}

	if im.AdvancesSinceDrain() != 5 {
		t.Fatalf("expected 5 advances, got %d", im.AdvancesSinceDrain())
	}

	// Drain should reset the counter to 0.
	im.DrainPending()

	if im.AdvancesSinceDrain() != 0 {
		t.Fatal("expected 0 advances after drain")
	}

	// MustDrainInbox should be false (no pending txs, counter reset).
	if im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be false after drain")
	}

	// Adding new txs and advancing again should work correctly.
	im.AddInboxTransaction([]byte{0x02})
	for i := 0; i < MaxAdvancesWithoutInboxDrain; i++ {
		im.RecordAdvance()
	}
	if !im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be true after re-filling and advancing")
	}
}

func TestInboxMonitor_NoDrainWhenEmpty(t *testing.T) {
	im := NewInboxMonitor()

	// No pending transactions — advance well past the threshold.
	for i := 0; i < MaxAdvancesWithoutInboxDrain+20; i++ {
		im.RecordAdvance()
	}

	if im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be false when there are no pending transactions")
	}

	if im.AdvancesSinceDrain() != uint16(MaxAdvancesWithoutInboxDrain+20) {
		t.Fatalf("expected %d advances, got %d",
			MaxAdvancesWithoutInboxDrain+20, im.AdvancesSinceDrain())
	}
}

func TestInboxMonitor_QueueHashChain(t *testing.T) {
	im := NewInboxMonitor()

	// Record hashes after each addition.
	hashes := make([]types.Hash, 0)
	hashes = append(hashes, im.QueueHash()) // genesis hash

	txs := [][]byte{
		{0x10, 0x20, 0x30},
		{0x40, 0x50, 0x60},
		{0x70, 0x80, 0x90},
	}

	for _, tx := range txs {
		im.AddInboxTransaction(tx)
		hashes = append(hashes, im.QueueHash())
	}

	// Each hash should be unique (no collisions in the chain).
	seen := make(map[types.Hash]int)
	for i, h := range hashes {
		if prev, ok := seen[h]; ok {
			t.Fatalf("hash collision: hash[%d] == hash[%d] == %s", i, prev, h.Hex())
		}
		seen[h] = i
	}

	// Verify against a fresh monitor with the same transactions.
	im2 := NewInboxMonitor()
	for _, tx := range txs {
		im2.AddInboxTransaction(tx)
	}
	if im.QueueHash() != im2.QueueHash() {
		t.Fatal("hash chain should be deterministic for the same transaction sequence")
	}

	// Verify that reversing the order produces a different hash.
	im3 := NewInboxMonitor()
	for i := len(txs) - 1; i >= 0; i-- {
		im3.AddInboxTransaction(txs[i])
	}
	if im.QueueHash() == im3.QueueHash() {
		t.Fatal("hash chain should differ for different transaction orderings")
	}
}
