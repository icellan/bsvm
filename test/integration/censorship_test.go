//go:build integration

package integration

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// Censorship resistance / forced inclusion tests
// ---------------------------------------------------------------------------
//
// These tests exercise the InboxMonitor that tracks forced inclusion of
// inbox transactions. The inbox mechanism guarantees that after
// MaxAdvancesWithoutInboxDrain (10) covenant advances, any pending inbox
// transactions MUST be prepended to the next batch.

// TestCensorship_InboxQueueTracking verifies the inbox monitor's basic
// queue mechanics: pending count, advance counting, and the
// MustDrainInbox threshold.
func TestCensorship_InboxQueueTracking(t *testing.T) {
	bundle := happyPathSetup(t)
	im := bundle.Node.InboxMonitor()

	// Initial state: empty queue, no forced drain required.
	if got := im.PendingCount(); got != 0 {
		t.Fatalf("initial PendingCount = %d, want 0", got)
	}
	if im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be false with empty queue")
	}

	// Add a fake inbox transaction.
	im.AddInboxTransaction([]byte{0x01, 0x02, 0x03})

	if got := im.PendingCount(); got != 1 {
		t.Fatalf("PendingCount after add = %d, want 1", got)
	}
	if im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be false with 0 advances")
	}

	// Record 9 advances — still below the threshold.
	for i := 0; i < 9; i++ {
		im.RecordAdvance()
	}
	if im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be false with 9 advances")
	}

	// 10th advance crosses the threshold.
	im.RecordAdvance()
	if !im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be true after 10 advances with pending tx")
	}
	if got := im.AdvancesSinceDrain(); got != 10 {
		t.Fatalf("AdvancesSinceDrain = %d, want 10", got)
	}
}

// TestCensorship_DrainResetsState verifies that DrainPending returns all
// pending transactions and resets the queue, advance counter, and pending
// count to their initial values.
func TestCensorship_DrainResetsState(t *testing.T) {
	bundle := happyPathSetup(t)
	im := bundle.Node.InboxMonitor()

	// Add 3 fake inbox transactions.
	im.AddInboxTransaction([]byte{0x01})
	im.AddInboxTransaction([]byte{0x02})
	im.AddInboxTransaction([]byte{0x03})

	// Record 10 advances to trigger forced inclusion.
	for i := 0; i < 10; i++ {
		im.RecordAdvance()
	}
	if !im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be true before drain")
	}

	// Drain the inbox.
	pending := im.DrainPending()
	if got := len(pending); got != 3 {
		t.Fatalf("DrainPending returned %d txs, want 3", got)
	}

	// After drain: everything is reset.
	if im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be false after drain")
	}
	if got := im.PendingCount(); got != 0 {
		t.Fatalf("PendingCount after drain = %d, want 0", got)
	}
	if got := im.AdvancesSinceDrain(); got != 0 {
		t.Fatalf("AdvancesSinceDrain after drain = %d, want 0", got)
	}
}

// TestCensorship_QueueHashChain verifies that each AddInboxTransaction
// extends the hash chain (producing a new distinct root) and that
// DrainPending resets the hash to the genesis value hash256(zeroes(32)).
func TestCensorship_QueueHashChain(t *testing.T) {
	bundle := happyPathSetup(t)
	im := bundle.Node.InboxMonitor()

	h0 := im.QueueHash()

	// Adding tx A must change the hash.
	im.AddInboxTransaction([]byte("txA"))
	h1 := im.QueueHash()
	if h1 == h0 {
		t.Fatal("hash did not change after adding txA")
	}

	// Adding tx B must change the hash again (and differ from both h0 and h1).
	im.AddInboxTransaction([]byte("txB"))
	h2 := im.QueueHash()
	if h2 == h1 {
		t.Fatal("hash did not change after adding txB")
	}
	if h2 == h0 {
		t.Fatal("hash after txB equals initial hash")
	}

	// After drain the hash returns to the genesis value.
	_ = im.DrainPending()
	hPost := im.QueueHash()
	if hPost != h0 {
		t.Fatalf("hash after drain = %s, want genesis %s", hPost.Hex(), h0.Hex())
	}
}

// TestCensorship_ForcedInclusionInBatch is an end-to-end test that verifies
// ProcessBatch honours the forced inclusion mechanism. An inbox transaction
// is added, 10 batches are processed (each containing one transfer), and on
// the 11th batch the inbox is automatically drained.
func TestCensorship_ForcedInclusionInBatch(t *testing.T) {
	bundle := happyPathSetup(t)
	im := bundle.Node.InboxMonitor()

	// Build a valid signed transfer for the inbox. Use nonce 100 (well
	// beyond the batch nonces 0..10) so it does not conflict. The inbox
	// tx may fail EVM execution (nonce gap), but forced inclusion drains
	// the queue regardless of execution outcome.
	recipient := types.HexToAddress("0x00000000000000000000000000000000000000ff")
	inboxTx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    100,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &recipient,
		Value:    uint256.NewInt(1),
	})
	var buf bytes.Buffer
	if err := inboxTx.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP inbox tx: %v", err)
	}
	im.AddInboxTransaction(buf.Bytes())

	if got := im.PendingCount(); got != 1 {
		t.Fatalf("PendingCount after inbox add = %d, want 1", got)
	}

	// Process 10 batches (nonces 0..9). Each batch contains a single
	// transfer. After 10 ProcessBatch calls the advance counter reaches 10.
	transferAmt := uint256.NewInt(1)
	for i := 0; i < 10; i++ {
		to := types.HexToAddress("0x00000000000000000000000000000000000000a1")
		tx := signTransfer(t, bundle, uint64(i), to, transferAmt)
		if _, err := bundle.Node.ProcessBatch([]*types.Transaction{tx}); err != nil {
			t.Fatalf("ProcessBatch #%d: %v", i, err)
		}
	}

	// After 10 advances with a pending inbox tx, MustDrainInbox is true.
	if !im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be true after 10 advances with pending inbox tx")
	}

	// Process the 11th batch — ProcessBatch should drain the inbox.
	to := types.HexToAddress("0x00000000000000000000000000000000000000a1")
	tx11 := signTransfer(t, bundle, 10, to, transferAmt)
	if _, err := bundle.Node.ProcessBatch([]*types.Transaction{tx11}); err != nil {
		t.Fatalf("ProcessBatch #11: %v", err)
	}

	// Inbox should be fully drained after the 11th batch.
	if im.MustDrainInbox() {
		t.Fatal("MustDrainInbox should be false after inbox was drained")
	}
	if got := im.PendingCount(); got != 0 {
		t.Fatalf("PendingCount after forced inclusion = %d, want 0", got)
	}
}
