package prover

import (
	"crypto/sha256"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// hash256_local mirrors pkg/overlay/inbox_monitor.go::hash256 — duplicated
// here to avoid pulling overlay (and its EVM/state graph) into the prover
// test surface. The whole point of the parity test is that the chain root
// computed by InboxChainRoot matches the chain root the InboxMonitor
// produces incrementally; we verify that by reimplementing the monitor's
// step-by-step extension here independently.
func hash256_local(data []byte) types.Hash {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return types.BytesToHash(second[:])
}

// stepwiseChainRoot extends the chain one tx at a time, exactly the way
// the on-chain inbox covenant and InboxMonitor do it. If InboxChainRoot's
// bulk computation diverges from this, the SP1 guest will reject the
// host's claimed `inboxRootBefore` and the proof will abort.
func stepwiseChainRoot(rawTxs [][]byte) types.Hash {
	zeroes := make([]byte, 32)
	root := hash256_local(zeroes)
	for _, rlp := range rawTxs {
		txHash := hash256_local(rlp)
		buf := make([]byte, 0, 64)
		buf = append(buf, root[:]...)
		buf = append(buf, txHash[:]...)
		root = hash256_local(buf)
	}
	return root
}

// TestInboxChainRoot_EmptyMatchesGenesis verifies the empty-queue marker
// matches the on-chain `EmptyInboxState` and `NewInboxMonitor` initial
// hash (= hash256(zeros(32))).
func TestInboxChainRoot_EmptyMatchesGenesis(t *testing.T) {
	got := EmptyInboxRoot()
	want := hash256_local(make([]byte, 32))
	if got != want {
		t.Fatalf("empty inbox root mismatch:\n  got  %s\n  want %s", got.Hex(), want.Hex())
	}

	// And the bulk chain over an empty list must equal the genesis marker.
	if InboxChainRoot(nil) != want {
		t.Fatalf("InboxChainRoot(nil) != EmptyInboxRoot()")
	}
	if InboxChainRoot([][]byte{}) != want {
		t.Fatalf("InboxChainRoot([]) != EmptyInboxRoot()")
	}
}

// TestInboxChainRoot_StepwiseParity is the core safety net: the bulk
// chain root computed by InboxChainRoot must match the step-by-step
// extension done by the inbox covenant on every Submit call. Any drift
// between these would cause the SP1 guest to reject the witness even
// when nothing was wrong.
func TestInboxChainRoot_StepwiseParity(t *testing.T) {
	cases := [][][]byte{
		nil,
		{},
		{{0x01}},
		{{0x01, 0x02, 0x03}},
		{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}},
		{
			[]byte("inbox-tx-rlp-fixture-1"),
			[]byte("inbox-tx-rlp-fixture-2-longer-payload"),
			[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33},
		},
	}
	for i, txs := range cases {
		bulk := InboxChainRoot(txs)
		stepwise := stepwiseChainRoot(txs)
		if bulk != stepwise {
			t.Errorf("case %d: bulk %s vs stepwise %s",
				i, bulk.Hex(), stepwise.Hex())
		}
	}
}

// TestInboxChainRoot_OrderSensitive confirms reordering changes the root
// — a basic sanity check on the chain construction (a Merkle-style root
// over a multiset would NOT have this property and would silently allow
// reordering attacks).
func TestInboxChainRoot_OrderSensitive(t *testing.T) {
	a := [][]byte{[]byte("alpha"), []byte("beta")}
	b := [][]byte{[]byte("beta"), []byte("alpha")}
	if InboxChainRoot(a) == InboxChainRoot(b) {
		t.Fatal("inbox chain root must depend on order")
	}
}

// TestBuildInboxWitness_FullDrain_ResetsToEmptyMarker verifies that a
// full drain produces `inboxRootAfter == EmptyInboxRoot()`. The covenant
// (per spec 10) treats `before != after` as "drain happened" and resets
// the advancesSinceInbox counter; both partial-drain and full-drain
// trigger this reset, but a full drain returns the queue to genesis.
func TestBuildInboxWitness_FullDrain_ResetsToEmptyMarker(t *testing.T) {
	queue := [][]byte{{0x10}, {0x20}, {0x30}}

	witness, before, after, err := BuildInboxWitness(queue, 3)
	if err != nil {
		t.Fatalf("BuildInboxWitness: %v", err)
	}
	if len(witness) != 3 {
		t.Fatalf("witness len = %d, want 3", len(witness))
	}
	if before != InboxChainRoot(queue) {
		t.Fatalf("before mismatch: got %s, want %s",
			before.Hex(), InboxChainRoot(queue).Hex())
	}
	if after != EmptyInboxRoot() {
		t.Fatalf("after should be empty marker on full drain, got %s", after.Hex())
	}
	if before == after {
		t.Fatal("before == after on a full drain — covenant would not reset counter")
	}
}

// TestBuildInboxWitness_PartialDrain_KeepsRemainder verifies the carry-
// forward semantics: a partial drain emits `inboxRootAfter = chain over
// the trailing remainder`. The covenant still resets the counter
// (before != after), and the next batch will start from the remainder.
func TestBuildInboxWitness_PartialDrain_KeepsRemainder(t *testing.T) {
	queue := [][]byte{{0x01}, {0x02}, {0x03}, {0x04}}

	_, before, after, err := BuildInboxWitness(queue, 2)
	if err != nil {
		t.Fatalf("BuildInboxWitness: %v", err)
	}
	if before != InboxChainRoot(queue) {
		t.Fatalf("before mismatch: %s vs %s", before.Hex(), InboxChainRoot(queue).Hex())
	}
	wantAfter := InboxChainRoot(queue[2:])
	if after != wantAfter {
		t.Fatalf("after mismatch: got %s, want %s", after.Hex(), wantAfter.Hex())
	}
	if after == EmptyInboxRoot() {
		t.Fatal("partial-drain after must NOT equal the empty marker")
	}
	if before == after {
		t.Fatal("before == after on partial drain — covenant would not reset counter")
	}
}

// TestBuildInboxWitness_NoDrain_RootsEqual covers the steady-state
// "nothing to drain this batch" path. The covenant uses `before == after`
// as the no-drain signal that increments the advancesSinceInbox counter.
func TestBuildInboxWitness_NoDrain_RootsEqual(t *testing.T) {
	queue := [][]byte{{0xAA}, {0xBB}}

	_, before, after, err := BuildInboxWitness(queue, 0)
	if err != nil {
		t.Fatalf("BuildInboxWitness: %v", err)
	}
	if before != after {
		t.Fatalf("before %s != after %s on zero-drain — covenant would treat as drain",
			before.Hex(), after.Hex())
	}
}

// TestBuildInboxWitness_EmptyQueue confirms the no-inbox baseline: an
// empty queue with zero drain produces both roots equal to the genesis
// empty-chain marker.
func TestBuildInboxWitness_EmptyQueue(t *testing.T) {
	_, before, after, err := BuildInboxWitness(nil, 0)
	if err != nil {
		t.Fatalf("BuildInboxWitness: %v", err)
	}
	if before != EmptyInboxRoot() || after != EmptyInboxRoot() {
		t.Fatalf("expected both = empty marker, got before=%s after=%s",
			before.Hex(), after.Hex())
	}
}

// TestBuildInboxWitness_DrainOverflow rejects nonsensical inputs.
func TestBuildInboxWitness_DrainOverflow(t *testing.T) {
	queue := [][]byte{{0x01}, {0x02}}
	if _, _, _, err := BuildInboxWitness(queue, 3); err == nil {
		t.Fatal("expected error when drainCount > len(queue)")
	}
}

// TestBuildInboxWitness_QueueAtCap_OK verifies the boundary: a queue at
// exactly MaxInboxDrainPerBatch (= 1024) is accepted. This is the
// "happy path at the cap" — the SP1 guest mirrors the same boundary in
// `inbox::MAX_INBOX_DRAIN_PER_BATCH`.
func TestBuildInboxWitness_QueueAtCap_OK(t *testing.T) {
	queue := make([][]byte, MaxInboxDrainPerBatch)
	for i := range queue {
		queue[i] = []byte{byte(i & 0xff)}
	}
	w, _, _, err := BuildInboxWitness(queue, 0)
	if err != nil {
		t.Fatalf("queue at cap (%d) must be accepted: %v",
			MaxInboxDrainPerBatch, err)
	}
	if len(w) != MaxInboxDrainPerBatch {
		t.Fatalf("witness len = %d, want %d", len(w), MaxInboxDrainPerBatch)
	}
}

// TestBuildInboxWitness_QueueOverCap_Rejected verifies the W4-3
// mainnet-hardening invariant: a queue of MaxInboxDrainPerBatch + 1
// triggers a hard error rather than silent truncation. Silent
// truncation would hide a producer-side pagination bug from the
// operator and risk leaving inbox txs un-drained past spec-10's
// forced-inclusion threshold (10 advances), which the covenant would
// then REJECT. Documented choice (D7 in docs/decisions/inbox-drain.md):
// ERROR rather than truncate-and-warn.
func TestBuildInboxWitness_QueueOverCap_Rejected(t *testing.T) {
	queue := make([][]byte, MaxInboxDrainPerBatch+1)
	for i := range queue {
		queue[i] = []byte{byte(i & 0xff)}
	}
	if _, _, _, err := BuildInboxWitness(queue, 0); err == nil {
		t.Fatalf("queue over cap (%d) must be rejected", len(queue))
	}
}

// TestBuildInboxWitness_FixtureThreeDrainTwo is the W4-3 acceptance
// scenario from the task spec: a fixture inbox of three txs, drain two,
// verify the witness reconciles end-to-end. We check three things:
//
//  1. The witness ships all three txs (host can't hide tx #3).
//  2. `before` matches the full-queue chain root (gate the guest enforces).
//  3. `after` matches the chain root of just tx #3 (carry-forward state).
func TestBuildInboxWitness_FixtureThreeDrainTwo(t *testing.T) {
	fixtureRLPs := [][]byte{
		[]byte("evm-tx-A"),
		[]byte("evm-tx-B"),
		[]byte("evm-tx-C"),
	}
	witness, before, after, err := BuildInboxWitness(fixtureRLPs, 2)
	if err != nil {
		t.Fatalf("BuildInboxWitness: %v", err)
	}

	// (1) All three txs are in the witness, in order, untouched.
	if len(witness) != 3 {
		t.Fatalf("witness len = %d, want 3", len(witness))
	}
	for i, w := range witness {
		if string(w.RawTxRLP) != string(fixtureRLPs[i]) {
			t.Errorf("witness[%d] RLP mismatch", i)
		}
	}

	// (2) `before` matches the chain over all 3 txs.
	want := InboxChainRoot(fixtureRLPs)
	if before != want {
		t.Errorf("before mismatch: got %s, want %s", before.Hex(), want.Hex())
	}

	// (3) `after` matches the chain over just the carry-forward (tx C).
	wantAfter := InboxChainRoot(fixtureRLPs[2:])
	if after != wantAfter {
		t.Errorf("after mismatch: got %s, want %s", after.Hex(), wantAfter.Hex())
	}

	// Sanity: roots must differ — covenant treats this as "drain happened".
	if before == after {
		t.Fatal("before == after; covenant would not reset advancesSinceInbox")
	}
}
