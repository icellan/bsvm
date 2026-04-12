package overlay

import (
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// makeUTXO creates a FeeUTXO with the given vout and satoshis.
// The TxID is derived from vout for deterministic test keys.
func makeUTXO(vout uint32, satoshis uint64) *FeeUTXO {
	var txid types.Hash
	txid[0] = byte(vout)
	txid[1] = byte(vout >> 8)
	return &FeeUTXO{
		TxID:         txid,
		Vout:         vout,
		Satoshis:     satoshis,
		ScriptPubKey: []byte{0x76, 0xa9, 0x14}, // truncated P2PKH prefix
		Confirmed:    true,
	}
}

func TestFeeWallet_AddRemoveUTXO(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	utxo := makeUTXO(0, 5000)
	if err := fw.AddUTXO(utxo); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	if fw.UTXOCount() != 1 {
		t.Errorf("expected 1 UTXO, got %d", fw.UTXOCount())
	}
	if fw.Balance() != 5000 {
		t.Errorf("expected balance 5000, got %d", fw.Balance())
	}

	if err := fw.RemoveUTXO(utxo.TxID, utxo.Vout); err != nil {
		t.Fatalf("RemoveUTXO failed: %v", err)
	}

	if fw.UTXOCount() != 0 {
		t.Errorf("expected 0 UTXOs after remove, got %d", fw.UTXOCount())
	}
	if fw.Balance() != 0 {
		t.Errorf("expected balance 0 after remove, got %d", fw.Balance())
	}
}

func TestFeeWallet_SelectUTXOs_SingleSufficient(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	if err := fw.AddUTXO(makeUTXO(0, 10000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	selected, total, err := fw.SelectUTXOs(5000)
	if err != nil {
		t.Fatalf("SelectUTXOs failed: %v", err)
	}
	if len(selected) != 1 {
		t.Errorf("expected 1 selected UTXO, got %d", len(selected))
	}
	if total != 10000 {
		t.Errorf("expected total 10000, got %d", total)
	}
}

func TestFeeWallet_SelectUTXOs_MultipleNeeded(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Add 3 UTXOs: 1000 + 2000 + 3000 = 6000 total.
	if err := fw.AddUTXO(makeUTXO(0, 1000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(1, 2000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(2, 3000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	// Target 5500 requires all 3 (3000 + 2000 + 1000 = 6000 >= 5500).
	selected, total, err := fw.SelectUTXOs(5500)
	if err != nil {
		t.Fatalf("SelectUTXOs failed: %v", err)
	}
	if len(selected) != 3 {
		t.Errorf("expected 3 selected UTXOs, got %d", len(selected))
	}
	if total != 6000 {
		t.Errorf("expected total 6000, got %d", total)
	}
}

func TestFeeWallet_SelectUTXOs_InsufficientFunds(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	if err := fw.AddUTXO(makeUTXO(0, 500)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	_, _, err := fw.SelectUTXOs(1000)
	if err == nil {
		t.Fatal("expected error for insufficient funds")
	}
}

func TestFeeWallet_SelectUTXOs_ExactAmount(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	if err := fw.AddUTXO(makeUTXO(0, 3000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(1, 2000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	// Target exactly 5000 (3000 + 2000).
	selected, total, err := fw.SelectUTXOs(5000)
	if err != nil {
		t.Fatalf("SelectUTXOs failed: %v", err)
	}
	if total < 5000 {
		t.Errorf("expected total >= 5000, got %d", total)
	}
	if len(selected) < 1 {
		t.Error("expected at least 1 selected UTXO")
	}
}

func TestFeeWallet_SelectUTXOs_LargestFirst(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Add UTXOs in random order.
	if err := fw.AddUTXO(makeUTXO(0, 100)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(1, 5000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(2, 2000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	// Target 4000: should pick the 5000 sat UTXO first (single suffices).
	selected, total, err := fw.SelectUTXOs(4000)
	if err != nil {
		t.Fatalf("SelectUTXOs failed: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("expected 1 selected (largest first), got %d", len(selected))
	}
	if selected[0].Satoshis != 5000 {
		t.Errorf("expected largest UTXO (5000) selected first, got %d", selected[0].Satoshis)
	}
	if total != 5000 {
		t.Errorf("expected total 5000, got %d", total)
	}
}

func TestFeeWallet_Balance(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	if err := fw.AddUTXO(makeUTXO(0, 1000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(1, 2500)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(2, 3500)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	if fw.Balance() != 7000 {
		t.Errorf("expected balance 7000, got %d", fw.Balance())
	}
}

func TestFeeWallet_NeedsConsolidation_UTXOCount(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Add 49 UTXOs (below threshold of 50).
	for i := uint32(0); i < 49; i++ {
		if err := fw.AddUTXO(makeUTXO(i, 100)); err != nil {
			t.Fatalf("AddUTXO failed: %v", err)
		}
	}

	if fw.NeedsConsolidation() {
		t.Error("should not need consolidation at 49 UTXOs")
	}

	// Add one more to hit 50.
	if err := fw.AddUTXO(makeUTXO(49, 100)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	if !fw.NeedsConsolidation() {
		t.Error("should need consolidation at 50 UTXOs")
	}
}

func TestFeeWallet_NeedsConsolidation_AdvanceCount(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Add a single UTXO (well below UTXO count threshold).
	if err := fw.AddUTXO(makeUTXO(0, 50000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	// Record 99 advances (below threshold of 100).
	for i := 0; i < 99; i++ {
		fw.RecordAdvance()
	}

	if fw.NeedsConsolidation() {
		t.Error("should not need consolidation at 99 advances")
	}

	// One more advance hits 100.
	fw.RecordAdvance()

	if !fw.NeedsConsolidation() {
		t.Error("should need consolidation at 100 advances")
	}
}

func TestFeeWallet_ConsolidationInputs(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	if err := fw.AddUTXO(makeUTXO(0, 1000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(1, 2000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw.AddUTXO(makeUTXO(2, 3000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	inputs := fw.ConsolidationInputs()
	if len(inputs) != 3 {
		t.Errorf("expected 3 consolidation inputs, got %d", len(inputs))
	}

	// Verify total value.
	var total uint64
	for _, u := range inputs {
		total += u.Satoshis
	}
	if total != 6000 {
		t.Errorf("expected total 6000, got %d", total)
	}
}

func TestFeeWallet_IsStarved(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Empty wallet is starved.
	if !fw.IsStarved() {
		t.Error("empty wallet should be starved")
	}

	// Add 999 sats (still starved).
	if err := fw.AddUTXO(makeUTXO(0, 999)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if !fw.IsStarved() {
		t.Error("wallet with 999 sats should be starved")
	}
}

func TestFeeWallet_IsStarved_NotStarved(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Add exactly 1000 sats (not starved).
	if err := fw.AddUTXO(makeUTXO(0, 1000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if fw.IsStarved() {
		t.Error("wallet with 1000 sats should not be starved")
	}

	// Add more to be clearly not starved.
	if err := fw.AddUTXO(makeUTXO(1, 50000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if fw.IsStarved() {
		t.Error("wallet with 51000 sats should not be starved")
	}
}

func TestFeeWallet_Persistence(t *testing.T) {
	database := db.NewMemoryDB()

	// Create wallet and add UTXOs.
	fw1 := NewFeeWallet(database)
	if err := fw1.AddUTXO(makeUTXO(0, 1000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw1.AddUTXO(makeUTXO(1, 2000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if err := fw1.AddUTXO(makeUTXO(2, 3000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}

	// Create a new wallet from the same database.
	fw2 := NewFeeWallet(database)
	if err := fw2.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB failed: %v", err)
	}

	// Verify all UTXOs survived.
	if fw2.UTXOCount() != 3 {
		t.Errorf("expected 3 UTXOs after reload, got %d", fw2.UTXOCount())
	}
	if fw2.Balance() != 6000 {
		t.Errorf("expected balance 6000 after reload, got %d", fw2.Balance())
	}
}

func TestFeeWallet_RemoveNonexistent(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Removing a nonexistent UTXO should be a no-op (no error).
	err := fw.RemoveUTXO(types.Hash{}, 999)
	if err != nil {
		t.Errorf("removing nonexistent UTXO should not error, got: %v", err)
	}

	if fw.UTXOCount() != 0 {
		t.Errorf("expected 0 UTXOs, got %d", fw.UTXOCount())
	}
}

func TestFeeWallet_RecordAdvance(t *testing.T) {
	fw := NewFeeWallet(db.NewMemoryDB())

	// Verify initial advance count is 0 (indirectly via NeedsConsolidation).
	// With no UTXOs and 0 advances, should not need consolidation.
	if fw.NeedsConsolidation() {
		t.Error("should not need consolidation initially")
	}

	// Record advances and verify counter increments.
	for i := 0; i < 50; i++ {
		fw.RecordAdvance()
	}

	// 50 advances is still below threshold of 100.
	// Add a UTXO so we have something, but below UTXO threshold.
	if err := fw.AddUTXO(makeUTXO(0, 5000)); err != nil {
		t.Fatalf("AddUTXO failed: %v", err)
	}
	if fw.NeedsConsolidation() {
		t.Error("should not need consolidation at 50 advances with 1 UTXO")
	}

	// Record 50 more to hit 100.
	for i := 0; i < 50; i++ {
		fw.RecordAdvance()
	}
	if !fw.NeedsConsolidation() {
		t.Error("should need consolidation at 100 advances")
	}
}
