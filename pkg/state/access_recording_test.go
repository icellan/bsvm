package state

import (
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// TestAccessRecording verifies that StartAccessRecording and
// StopAccessRecording correctly capture all accessed accounts and
// storage slots during state operations.
func TestAccessRecording(t *testing.T) {
	sdb := newTestStateDB(t)

	addr1 := types.HexToAddress("0x1111")
	addr2 := types.HexToAddress("0x2222")
	addr3 := types.HexToAddress("0x3333")
	slot1 := types.HexToHash("0x01")
	slot2 := types.HexToHash("0x02")

	// Set up some accounts.
	sdb.CreateAccount(addr1)
	sdb.AddBalance(addr1, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	sdb.CreateAccount(addr2)
	sdb.SetState(addr2, slot1, types.HexToHash("0xaa"))

	// Start recording.
	sdb.StartAccessRecording()

	// Access various accounts and slots.
	sdb.GetBalance(addr1)                               // reads addr1
	sdb.GetNonce(addr1)                                 // reads addr1 again (should not duplicate)
	sdb.GetState(addr2, slot1)                          // reads addr2 and slot1
	sdb.SetState(addr2, slot2, types.HexToHash("0xbb")) // writes addr2 and slot2
	sdb.Exist(addr3)                                    // reads addr3 (non-existent)

	// Stop recording.
	recording := sdb.StopAccessRecording()

	// Verify accounts.
	accountSet := make(map[types.Address]bool)
	for _, addr := range recording.Accounts {
		accountSet[addr] = true
	}
	if !accountSet[addr1] {
		t.Error("addr1 should be in recorded accounts")
	}
	if !accountSet[addr2] {
		t.Error("addr2 should be in recorded accounts")
	}
	if !accountSet[addr3] {
		t.Error("addr3 should be in recorded accounts (even if non-existent)")
	}

	// Verify slots.
	addr2Slots := make(map[types.Hash]bool)
	for _, s := range recording.Slots[addr2] {
		addr2Slots[s] = true
	}
	if !addr2Slots[slot1] {
		t.Error("slot1 should be recorded for addr2")
	}
	if !addr2Slots[slot2] {
		t.Error("slot2 should be recorded for addr2")
	}
	// addr1 should have no slots recorded.
	if len(recording.Slots[addr1]) != 0 {
		t.Errorf("addr1 should have no slots recorded, got %d", len(recording.Slots[addr1]))
	}
}

// TestAccessRecordingNotActive verifies that StopAccessRecording returns
// an empty recording when recording was never started.
func TestAccessRecordingNotActive(t *testing.T) {
	sdb := newTestStateDB(t)

	recording := sdb.StopAccessRecording()
	if recording == nil {
		t.Fatal("expected non-nil recording")
	}
	if len(recording.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(recording.Accounts))
	}
	if recording.Slots == nil {
		t.Error("expected non-nil Slots map")
	}
}

// TestAccessRecordingStopClearsState verifies that stopping recording
// clears the recorder so subsequent operations are not tracked.
func TestAccessRecordingStopClearsState(t *testing.T) {
	sdb := newTestStateDB(t)

	addr := types.HexToAddress("0x1111")
	sdb.CreateAccount(addr)

	// First recording session.
	sdb.StartAccessRecording()
	sdb.GetBalance(addr)
	recording1 := sdb.StopAccessRecording()
	if len(recording1.Accounts) == 0 {
		t.Fatal("first recording should have captured addr")
	}

	// After stopping, accesses should not be recorded.
	sdb.GetBalance(addr)

	// Second recording session should start fresh.
	sdb.StartAccessRecording()
	recording2 := sdb.StopAccessRecording()
	if len(recording2.Accounts) != 0 {
		t.Errorf("second recording should be empty, got %d accounts", len(recording2.Accounts))
	}
}

// TestAccessRecordingMultipleTransactions verifies that access recording
// accumulates across multiple simulated "transactions" without resetting.
func TestAccessRecordingMultipleTransactions(t *testing.T) {
	sdb := newTestStateDB(t)

	addr1 := types.HexToAddress("0x1111")
	addr2 := types.HexToAddress("0x2222")
	sdb.CreateAccount(addr1)
	sdb.CreateAccount(addr2)

	sdb.StartAccessRecording()

	// Simulate transaction 1.
	sdb.GetBalance(addr1)
	sdb.SetState(addr1, types.HexToHash("0x01"), types.HexToHash("0xaa"))

	// Simulate transaction 2.
	sdb.GetBalance(addr2)
	sdb.SetState(addr2, types.HexToHash("0x02"), types.HexToHash("0xbb"))
	sdb.GetState(addr1, types.HexToHash("0x03")) // access addr1 slot again

	recording := sdb.StopAccessRecording()

	// Both accounts should be recorded.
	accountSet := make(map[types.Address]bool)
	for _, addr := range recording.Accounts {
		accountSet[addr] = true
	}
	if !accountSet[addr1] || !accountSet[addr2] {
		t.Error("both addr1 and addr2 should be in recorded accounts")
	}

	// Check slots.
	addr1Slots := make(map[types.Hash]bool)
	for _, s := range recording.Slots[addr1] {
		addr1Slots[s] = true
	}
	if !addr1Slots[types.HexToHash("0x01")] {
		t.Error("addr1 slot 0x01 should be recorded")
	}
	if !addr1Slots[types.HexToHash("0x03")] {
		t.Error("addr1 slot 0x03 should be recorded")
	}

	addr2Slots := make(map[types.Hash]bool)
	for _, s := range recording.Slots[addr2] {
		addr2Slots[s] = true
	}
	if !addr2Slots[types.HexToHash("0x02")] {
		t.Error("addr2 slot 0x02 should be recorded")
	}
}

// TestAccessRecordingRestart verifies that starting a new recording
// discards the previous one.
func TestAccessRecordingRestart(t *testing.T) {
	sdb := newTestStateDB(t)

	addr1 := types.HexToAddress("0x1111")
	addr2 := types.HexToAddress("0x2222")
	sdb.CreateAccount(addr1)
	sdb.CreateAccount(addr2)

	// First recording.
	sdb.StartAccessRecording()
	sdb.GetBalance(addr1)

	// Start new recording without stopping (resets).
	sdb.StartAccessRecording()
	sdb.GetBalance(addr2)

	recording := sdb.StopAccessRecording()

	accountSet := make(map[types.Address]bool)
	for _, addr := range recording.Accounts {
		accountSet[addr] = true
	}
	// addr1 should NOT be present (recording was restarted).
	if accountSet[addr1] {
		t.Error("addr1 should not be in recording after restart")
	}
	// addr2 should be present.
	if !accountSet[addr2] {
		t.Error("addr2 should be in recording")
	}
}
