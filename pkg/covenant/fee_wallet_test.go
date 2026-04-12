package covenant

import (
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// makeTestUTXO creates a FeeUTXO with the given satoshis and a deterministic
// TxID derived from the id byte.
func makeTestUTXO(id byte, satoshis uint64) FeeUTXO {
	var txID types.Hash
	txID[0] = id
	var pkh [20]byte
	pkh[0] = 0xaa
	return FeeUTXO{
		TxID:       txID,
		Vout:       0,
		Satoshis:   satoshis,
		Script:     buildP2PKHScript(pkh[:]),
		PubKeyHash: pkh,
	}
}

func TestFeeWallet_SelectUTXOs_Basic(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01, 0x02, 0x03})

	fw.AddUTXO(makeTestUTXO(1, 50000))
	fw.AddUTXO(makeTestUTXO(2, 30000))
	fw.AddUTXO(makeTestUTXO(3, 20000))

	inputs, err := fw.SelectUTXOs(40000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should select the largest UTXO (50000) which covers 40000.
	if len(inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(inputs))
	}
	if inputs[0].Satoshis != 50000 {
		t.Errorf("expected 50000 satoshis, got %d", inputs[0].Satoshis)
	}
}

func TestFeeWallet_SelectUTXOs_Greedy(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	fw.AddUTXO(makeTestUTXO(1, 10000))
	fw.AddUTXO(makeTestUTXO(2, 50000))
	fw.AddUTXO(makeTestUTXO(3, 30000))
	fw.AddUTXO(makeTestUTXO(4, 5000))

	inputs, err := fw.SelectUTXOs(70000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should select largest first: 50000, 30000 = 80000 >= 70000.
	if len(inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(inputs))
	}
	if inputs[0].Satoshis != 50000 {
		t.Errorf("first input should be 50000, got %d", inputs[0].Satoshis)
	}
	if inputs[1].Satoshis != 30000 {
		t.Errorf("second input should be 30000, got %d", inputs[1].Satoshis)
	}
}

func TestFeeWallet_SelectUTXOs_Deterministic(t *testing.T) {
	// Two wallets with same UTXOs should produce same selection.
	makeWallet := func() *FeeWallet {
		fw := NewFeeWallet([]byte{0x01})
		// Add in different order.
		fw.AddUTXO(makeTestUTXO(3, 20000))
		fw.AddUTXO(makeTestUTXO(1, 50000))
		fw.AddUTXO(makeTestUTXO(2, 30000))
		return fw
	}

	fw1 := makeWallet()
	fw2 := makeWallet()

	inputs1, err1 := fw1.SelectUTXOs(60000)
	inputs2, err2 := fw2.SelectUTXOs(60000)

	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v, %v", err1, err2)
	}

	if len(inputs1) != len(inputs2) {
		t.Fatalf("different number of inputs: %d vs %d", len(inputs1), len(inputs2))
	}

	for i := range inputs1 {
		if inputs1[i].TxID != inputs2[i].TxID {
			t.Errorf("input %d TxID mismatch: %v vs %v", i, inputs1[i].TxID, inputs2[i].TxID)
		}
		if inputs1[i].Satoshis != inputs2[i].Satoshis {
			t.Errorf("input %d satoshis mismatch: %d vs %d", i, inputs1[i].Satoshis, inputs2[i].Satoshis)
		}
	}
}

func TestFeeWallet_SelectUTXOs_Starved(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	fw.AddUTXO(makeTestUTXO(1, 1000))
	fw.AddUTXO(makeTestUTXO(2, 2000))

	_, err := fw.SelectUTXOs(50000)
	if err == nil {
		t.Fatal("expected error for insufficient funds")
	}
	if !strings.Contains(err.Error(), "fee wallet starved") {
		t.Errorf("expected 'fee wallet starved' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "have 3000") {
		t.Errorf("expected 'have 3000' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "need 50000") {
		t.Errorf("expected 'need 50000' in error, got: %v", err)
	}
}

func TestFeeWallet_SelectUTXOs_ExactAmount(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	fw.AddUTXO(makeTestUTXO(1, 25000))
	fw.AddUTXO(makeTestUTXO(2, 25000))

	// Request exactly the total amount.
	inputs, err := fw.SelectUTXOs(50000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var total uint64
	for _, inp := range inputs {
		total += inp.Satoshis
	}
	if total != 50000 {
		t.Errorf("expected exact 50000, got %d", total)
	}
}

func TestFeeWallet_ReleaseUTXOs(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	fw.AddUTXO(makeTestUTXO(1, 50000))

	// Select the UTXO.
	inputs, err := fw.SelectUTXOs(50000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wallet should now be empty.
	if fw.Balance() != 0 {
		t.Errorf("expected 0 balance after select, got %d", fw.Balance())
	}

	// Release and re-select.
	fw.ReleaseUTXOs(inputs)

	if fw.Balance() != 50000 {
		t.Errorf("expected 50000 balance after release, got %d", fw.Balance())
	}

	// Should be selectable again.
	inputs2, err := fw.SelectUTXOs(50000)
	if err != nil {
		t.Fatalf("unexpected error on re-select: %v", err)
	}
	if len(inputs2) != 1 || inputs2[0].Satoshis != 50000 {
		t.Errorf("unexpected re-selected input: %v", inputs2)
	}
}

func TestFeeWallet_Balance(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	if fw.Balance() != 0 {
		t.Errorf("expected 0 balance for empty wallet, got %d", fw.Balance())
	}

	fw.AddUTXO(makeTestUTXO(1, 10000))
	fw.AddUTXO(makeTestUTXO(2, 20000))
	fw.AddUTXO(makeTestUTXO(3, 30000))

	if fw.Balance() != 60000 {
		t.Errorf("expected 60000 balance, got %d", fw.Balance())
	}

	// Spend some.
	_, err := fw.SelectUTXOs(25000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Largest (30000) was selected, remaining = 30000.
	if fw.Balance() != 30000 {
		t.Errorf("expected 30000 after spending, got %d", fw.Balance())
	}
}

func TestFeeWallet_UTXOCount(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	if fw.UTXOCount() != 0 {
		t.Errorf("expected 0 count for empty wallet, got %d", fw.UTXOCount())
	}

	fw.AddUTXO(makeTestUTXO(1, 10000))
	fw.AddUTXO(makeTestUTXO(2, 20000))
	fw.AddUTXO(makeTestUTXO(3, 30000))

	if fw.UTXOCount() != 3 {
		t.Errorf("expected 3, got %d", fw.UTXOCount())
	}

	// Spend one.
	_, err := fw.SelectUTXOs(25000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fw.UTXOCount() != 2 {
		t.Errorf("expected 2 after spending, got %d", fw.UTXOCount())
	}
}

func TestFeeWallet_IsStarved(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	// Empty wallet is starved.
	if !fw.IsStarved() {
		t.Error("empty wallet should be starved")
	}

	// Below threshold.
	fw.AddUTXO(makeTestUTXO(1, 5000))
	if !fw.IsStarved() {
		t.Error("wallet with 5000 sats should be starved")
	}

	// Exactly at threshold.
	fw.AddUTXO(makeTestUTXO(2, 5000))
	if fw.IsStarved() {
		t.Error("wallet with exactly 10000 sats should not be starved")
	}

	// Above threshold.
	fw.AddUTXO(makeTestUTXO(3, 50000))
	if fw.IsStarved() {
		t.Error("wallet with 60000 sats should not be starved")
	}
}

func TestFeeWallet_ConsolidateUTXOs(t *testing.T) {
	changeAddr := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd}
	fw := NewFeeWallet(changeAddr)

	fw.AddUTXO(makeTestUTXO(1, 1000))
	fw.AddUTXO(makeTestUTXO(2, 2000))
	fw.AddUTXO(makeTestUTXO(3, 3000))
	fw.AddUTXO(makeTestUTXO(4, 100000))

	// Consolidate 3 smallest UTXOs.
	tx, err := fw.ConsolidateUTXOs(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 3 inputs (the 3 smallest: 1000, 2000, 3000).
	if len(tx.Inputs) != 3 {
		t.Errorf("expected 3 inputs, got %d", len(tx.Inputs))
	}

	// Should have 1 output.
	if len(tx.Outputs) != 1 {
		t.Errorf("expected 1 output, got %d", len(tx.Outputs))
	}

	// Output value should be total minus fee.
	totalInput := uint64(1000 + 2000 + 3000)
	if tx.Outputs[0].Value >= totalInput {
		t.Errorf("output value %d should be less than total input %d (fee deducted)",
			tx.Outputs[0].Value, totalInput)
	}
	if tx.Outputs[0].Value == 0 {
		t.Error("output value should not be zero")
	}

	// Version should be 1.
	if tx.Version != 1 {
		t.Errorf("expected version 1, got %d", tx.Version)
	}
}

func TestFeeWallet_ConsolidateUTXOs_TooFew(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	fw.AddUTXO(makeTestUTXO(1, 50000))

	_, err := fw.ConsolidateUTXOs(5)
	if err == nil {
		t.Fatal("expected error with only 1 UTXO")
	}
	if !strings.Contains(err.Error(), "at least 2") {
		t.Errorf("expected 'at least 2' in error, got: %v", err)
	}
}

func TestFeeWallet_ConsolidateUTXOs_Empty(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	_, err := fw.ConsolidateUTXOs(5)
	if err == nil {
		t.Fatal("expected error with empty wallet")
	}
}

func TestFeeWallet_AddUTXO_SortOrder(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	// Add in random order.
	fw.AddUTXO(makeTestUTXO(3, 10000))
	fw.AddUTXO(makeTestUTXO(1, 50000))
	fw.AddUTXO(makeTestUTXO(5, 30000))
	fw.AddUTXO(makeTestUTXO(2, 50000))
	fw.AddUTXO(makeTestUTXO(4, 20000))

	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Verify sorted order: descending by satoshis, then ascending by TxID.
	expectedOrder := []struct {
		id       byte
		satoshis uint64
	}{
		{1, 50000}, // 50000, TxID[0]=1 (lower)
		{2, 50000}, // 50000, TxID[0]=2 (higher)
		{5, 30000},
		{4, 20000},
		{3, 10000},
	}

	if len(fw.utxos) != len(expectedOrder) {
		t.Fatalf("expected %d UTXOs, got %d", len(expectedOrder), len(fw.utxos))
	}

	for i, exp := range expectedOrder {
		if fw.utxos[i].TxID[0] != exp.id {
			t.Errorf("position %d: expected TxID[0]=%d, got %d", i, exp.id, fw.utxos[i].TxID[0])
		}
		if fw.utxos[i].Satoshis != exp.satoshis {
			t.Errorf("position %d: expected %d sats, got %d", i, exp.satoshis, fw.utxos[i].Satoshis)
		}
	}
}

func TestFeeWallet_SelectUTXOs_SpentFiltered(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	fw.AddUTXO(makeTestUTXO(1, 50000))
	fw.AddUTXO(makeTestUTXO(2, 30000))
	fw.AddUTXO(makeTestUTXO(3, 20000))

	// Select the largest UTXO (50000).
	_, err := fw.SelectUTXOs(40000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now select again — the 50000 UTXO should be filtered out.
	inputs, err := fw.SelectUTXOs(25000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should select the next largest (30000).
	if len(inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(inputs))
	}
	if inputs[0].Satoshis != 30000 {
		t.Errorf("expected 30000 satoshis, got %d", inputs[0].Satoshis)
	}
}

func TestFeeWallet_Empty(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01, 0x02})

	// Balance on empty wallet.
	if fw.Balance() != 0 {
		t.Errorf("expected 0 balance, got %d", fw.Balance())
	}

	// UTXOCount on empty wallet.
	if fw.UTXOCount() != 0 {
		t.Errorf("expected 0 count, got %d", fw.UTXOCount())
	}

	// IsStarved on empty wallet.
	if !fw.IsStarved() {
		t.Error("empty wallet should be starved")
	}

	// SelectUTXOs on empty wallet.
	_, err := fw.SelectUTXOs(1000)
	if err == nil {
		t.Fatal("expected error on empty wallet select")
	}
	if !strings.Contains(err.Error(), "fee wallet starved") {
		t.Errorf("expected 'fee wallet starved' in error, got: %v", err)
	}

	// ReleaseUTXOs on empty wallet (should not panic).
	fw.ReleaseUTXOs(nil)
	fw.ReleaseUTXOs([]FeeInput{})

	// ChangeAddress returns correct value.
	addr := fw.ChangeAddress()
	if len(addr) != 2 || addr[0] != 0x01 || addr[1] != 0x02 {
		t.Errorf("unexpected change address: %v", addr)
	}

	// ConsolidateUTXOs on empty wallet.
	_, err = fw.ConsolidateUTXOs(5)
	if err == nil {
		t.Fatal("expected error on empty wallet consolidate")
	}
}

func TestFeeWallet_SignInput_NoKey(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	utxo := makeTestUTXO(1, 50000)
	_, err := fw.SignInput([]byte{0x00}, 0, utxo)
	if err == nil {
		t.Fatal("expected error when no private key registered")
	}
	if !strings.Contains(err.Error(), "no private key") {
		t.Errorf("expected 'no private key' in error, got: %v", err)
	}
}

func TestFeeWallet_SignInput_WithKey(t *testing.T) {
	fw := NewFeeWallet([]byte{0x01})

	utxo := makeTestUTXO(1, 50000)
	privKey := make([]byte, 32)
	privKey[0] = 0xff
	fw.AddPrivateKey(utxo.PubKeyHash, privKey)

	sig, err := fw.SignInput([]byte{0x00}, 0, utxo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature placeholder")
	}
}

func TestFeeWallet_ChangeAddress(t *testing.T) {
	addr := []byte{0xde, 0xad, 0xbe, 0xef}
	fw := NewFeeWallet(addr)

	got := fw.ChangeAddress()
	if len(got) != len(addr) {
		t.Fatalf("expected %d bytes, got %d", len(addr), len(got))
	}
	for i := range addr {
		if got[i] != addr[i] {
			t.Errorf("byte %d: expected %02x, got %02x", i, addr[i], got[i])
		}
	}

	// Verify it's a copy (modifying returned slice doesn't affect wallet).
	got[0] = 0x00
	got2 := fw.ChangeAddress()
	if got2[0] != 0xde {
		t.Error("ChangeAddress returned a reference, not a copy")
	}
}
