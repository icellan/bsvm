package overlay

import (
	"bytes"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// newRaceSetup spins up a second independent overlay node that shares the
// same genesis allocation and chainID as the primary newTestSetup helper.
// The second node is used to simulate a peer that wins a covenant advance
// race; its produced batch data and post-state root can then be replayed
// against the primary node's cascade-rollback path.
type raceSetup struct {
	node     *OverlayNode
	database db.Database
	chainDB  *block.ChainDB
	coinbase types.Address
	genesis  *block.L2Header
}

func newRaceSetup(t *testing.T, sharedAddr types.Address) *raceSetup {
	t.Helper()

	cbKeyBytes := make([]byte, 32)
	cbKeyBytes[31] = 3
	cbKey, err := crypto.ToECDSA(cbKeyBytes)
	if err != nil {
		t.Fatalf("failed to create coinbase key: %v", err)
	}
	coinbase := types.Address(crypto.PubkeyToAddress(cbKey.PublicKey))

	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30_000_000,
		Alloc: map[types.Address]block.GenesisAccount{
			sharedAddr: {Balance: uint256.NewInt(1_000_000_000_000_000_000)},
		},
	}
	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("failed to init genesis: %v", err)
	}

	config := DefaultOverlayConfig()
	config.ChainID = testChainID
	config.Coinbase = coinbase
	config.MaxBatchFlushDelay = 100 * time.Millisecond

	sp1Prover := prover.NewSP1Prover(prover.DefaultConfig())
	compiledCovenant := &covenant.CompiledCovenant{}
	initialState := covenant.CovenantState{
		StateRoot:   genesisHeader.StateRoot,
		BlockNumber: 0,
	}
	covenantMgr := covenant.NewCovenantManager(
		compiledCovenant, types.Hash{}, 0, 10000,
		initialState, testChainID, covenant.VerifyGroth16,
	)
	chainDB := block.NewChainDB(database)
	node, err := NewOverlayNode(config, chainDB, database, covenantMgr, sp1Prover)
	if err != nil {
		t.Fatalf("failed to create second overlay node: %v", err)
	}

	return &raceSetup{
		node:     node,
		database: database,
		chainDB:  chainDB,
		coinbase: coinbase,
		genesis:  genesisHeader,
	}
}

// Finding 1 — Two-node race: loser must replay the winner's batch and
// land on an identical state root. We simulate this by running two
// independent overlay nodes against the same genesis, having each
// process a different transaction at height 1, and then driving the
// "loser" through CascadeRollback with the winner's batch.
func TestOverlayNode_TwoNodeRace_LoserConvergesOnWinner(t *testing.T) {
	loser := newTestSetup(t)
	defer loser.node.Stop()

	// Stand up an independent winner node. We reuse the loser's signing
	// key so both nodes accept the same transaction format/nonce/chainID.
	winner := newRaceSetup(t, loser.addr)
	defer winner.node.Stop()

	recipientA := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	recipientB := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	amount := uint256.NewInt(10_000_000_000_000)

	// Loser's version of block 1: transfer to A.
	loserTx := loser.signTx(t, 0, recipientA, amount, nil)
	if _, err := loser.node.ProcessBatch([]*types.Transaction{loserTx}); err != nil {
		t.Fatalf("loser ProcessBatch failed: %v", err)
	}

	// Winner's version of block 1: same nonce, different recipient.
	winnerTx := loser.signTx(t, 0, recipientB, amount, nil)
	winnerResult, err := winner.node.ProcessBatch([]*types.Transaction{winnerTx})
	if err != nil {
		t.Fatalf("winner ProcessBatch failed: %v", err)
	}

	// Pull the winner's encoded batch out of its tx cache and build a
	// CovenantAdvanceEvent as the loser would observe on the BSV wire.
	winnerCached := winner.node.txCache.GetByL2Block(1)
	if winnerCached == nil {
		t.Fatal("winner has no cached entry for block 1")
	}
	event := &CovenantAdvanceEvent{
		BSVTxID:       types.HexToHash("0xfeedface"),
		L2BlockNum:    1,
		PostStateRoot: winnerResult.StateRoot,
		BatchData:     winnerCached.BatchData,
		IsOurs:        false,
	}

	if err := loser.node.CascadeRollback(event); err != nil {
		t.Fatalf("loser cascade rollback failed: %v", err)
	}

	// After rollback the loser should sit at block 1 with the winner's
	// state root and should see the winner's recipient credited.
	if loser.node.ExecutionTip() != 1 {
		t.Errorf("expected tip 1 after rollback, got %d", loser.node.ExecutionTip())
	}
	gotRoot := loser.node.StateDB().IntermediateRoot(true)
	if gotRoot != winnerResult.StateRoot {
		t.Errorf("loser state root %s != winner root %s", gotRoot.Hex(), winnerResult.StateRoot.Hex())
	}
	if loser.node.StateDB().GetBalance(recipientB).Cmp(amount) != 0 {
		t.Errorf("expected recipientB credited to %s, got %s",
			amount, loser.node.StateDB().GetBalance(recipientB))
	}
	// And recipientA (the loser's orphaned target) should have zero balance.
	if loser.node.StateDB().GetBalance(recipientA).Sign() != 0 {
		t.Errorf("expected recipientA balance to be zero after rollback, got %s",
			loser.node.StateDB().GetBalance(recipientA))
	}
}

// Finding 2 — State-root mismatch during replay. The current
// CascadeRollback returns an error but does NOT trip the circuit
// breaker. We assert both:
//  1. the call fails
//  2. the circuit breaker's failure counter reflects the mismatch
//
// If the breaker does not react, the test is skipped with a TODO
// pointing at cascade_rollback.go:75-84.
func TestOverlayNode_CascadeRollback_StateRootMismatchTripsBreaker(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	amount := uint256.NewInt(10_000_000_000_000)

	// Build a real block 1 on the loser first so that the rollback
	// target (block 0) has proper headers behind it.
	tx1 := ts.signTx(t, 0, recipient, amount, nil)
	if _, err := ts.node.ProcessBatch([]*types.Transaction{tx1}); err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Build a winner batch that contains a VALID transaction but whose
	// PostStateRoot is a garbage value. When CascadeRollback replays
	// the batch, the replayed root will match the honest replay and
	// therefore NOT match the advertised (garbage) root, hitting the
	// mismatch branch at cascade_rollback.go:75.
	winnerTx := ts.signTx(t, 0, recipient, amount, nil)
	w := &bytesWriter{}
	if err := winnerTx.EncodeRLP(w); err != nil {
		t.Fatalf("encode winner tx: %v", err)
	}
	batchData := &block.BatchData{
		Version:      block.BatchVersion,
		Timestamp:    uint64(time.Now().Unix()),
		Coinbase:     ts.coinbase,
		ParentHash:   ts.genesis.Hash(),
		Transactions: [][]byte{w.Bytes()},
	}
	encodedBatch, err := block.EncodeBatchData(batchData)
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}

	bogusRoot := types.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	event := &CovenantAdvanceEvent{
		BSVTxID:       types.HexToHash("0xbad00bad"),
		L2BlockNum:    1,
		PostStateRoot: bogusRoot,
		BatchData:     encodedBatch,
		IsOurs:        false,
	}

	breaker := ts.node.CircuitBreaker()
	failuresBefore := breaker.ConsecutiveFailures()

	err = ts.node.CascadeRollback(event)
	if err == nil {
		t.Fatal("expected CascadeRollback to fail on state-root mismatch")
	}

	// The breaker MUST record the disagreement on a state-root mismatch.
	if breaker.ConsecutiveFailures() <= failuresBefore {
		t.Errorf("expected circuit breaker failures to grow on replay mismatch, got %d (was %d)",
			breaker.ConsecutiveFailures(), failuresBefore)
	}
}

// Finding 3 — ExecutionVerifier is defined but never called from the
// overlay node. We assert that (1) the node wires an ExecutionVerifier
// at construction time, and (2) the peer-advance acceptance path
// actually calls VerifyCovenantAdvance and refuses to accept an advance
// that does not verify.
func TestOverlayNode_AcceptPeerAdvance_InvokesExecutionVerifier(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// (1) Wiring assertion: the verifier must be constructed alongside
	// the node and reachable via the ExecutionVerifier accessor.
	if ts.node.ExecutionVerifier() == nil {
		t.Fatal("OverlayNode.ExecutionVerifier() returned nil; NewOverlayNode " +
			"must instantiate an ExecutionVerifier via NewExecutionVerifierFromNode")
	}

	// (2) Behaviour assertion: build a peer advance whose advertised
	// post-state root is garbage and feed it through the peer-advance
	// path. The execution verifier should fire, the advance should be
	// rejected, and the circuit breaker should record a disagreement.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	amount := uint256.NewInt(10_000_000_000_000)

	// Seed block 1 so the verifier can look up a real parent header.
	tx1 := ts.signTx(t, 0, recipient, amount, nil)
	if _, err := ts.node.ProcessBatch([]*types.Transaction{tx1}); err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Build a bogus peer batch for block 2 with an unrelated state root.
	peerTx := ts.signTx(t, 1, recipient, amount, nil)
	w := &bytesWriter{}
	if err := peerTx.EncodeRLP(w); err != nil {
		t.Fatalf("encode peer tx: %v", err)
	}
	batchData := &block.BatchData{
		Version:      block.BatchVersion,
		Timestamp:    uint64(time.Now().Unix()),
		Coinbase:     ts.coinbase,
		ParentHash:   types.Hash{},
		Transactions: [][]byte{w.Bytes()},
	}
	encoded, err := block.EncodeBatchData(batchData)
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}

	bogus := types.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	event := &CovenantAdvanceEvent{
		BSVTxID:       types.HexToHash("0xcafe"),
		L2BlockNum:    2,
		PostStateRoot: bogus,
		BatchData:     encoded,
		IsOurs:        false,
	}

	breaker := ts.node.CircuitBreaker()
	before := breaker.ConsecutiveFailures()

	if err := ts.node.CascadeRollback(event); err == nil {
		t.Fatal("expected CascadeRollback to reject an unverifiable peer advance")
	}

	if breaker.ConsecutiveFailures() <= before {
		t.Errorf("expected breaker to record a disagreement from the execution verifier, "+
			"failures stayed at %d", breaker.ConsecutiveFailures())
	}
}

// Finding 4 — Unseeded math/rand. Two independently-constructed
// RaceDetector instances must produce DIFFERENT backoff sequences.
// With the package-level math/rand (pre-v2) the global source was
// deterministic unless explicitly seeded, so both instances would
// return identical sequences. We flipped the import to math/rand/v2
// which is OS-seeded per-process; this test locks that behaviour in.
func TestRaceDetector_Backoff_SeededJitter(t *testing.T) {
	const samples = 20

	collect := func() []time.Duration {
		rd := NewRaceDetector(nil)
		rd.mu.Lock()
		rd.consecutiveLosses = 3
		rd.mu.Unlock()
		out := make([]time.Duration, samples)
		for i := range out {
			out[i] = rd.BackoffDuration()
		}
		return out
	}

	a := collect()
	b := collect()

	// They must not be byte-for-byte identical. (With a properly
	// seeded RNG this is astronomically unlikely to collide.)
	identical := true
	for i := range a {
		if a[i] != b[i] {
			identical = false
			break
		}
	}
	if identical {
		t.Fatalf("expected distinct backoff sequences from two detectors, got identical:\n a=%v\n b=%v", a, b)
	}
}

// Finding 5 — process.go uses time.Now() for the L2 block timestamp.
// Spec 11/12 requires the timestamp to be deterministic per batch
// (the prover and every replaying node must land on the same hash).
// We run the same single-tx batch against two fresh nodes and compare
// the resulting block timestamps. If they diverge we skip with a TODO
// so the wall-clock dependency surfaces in CI output.
func TestOverlayNode_BlockTimestamp_IsDeterministic(t *testing.T) {
	tsA := newTestSetup(t)
	defer tsA.node.Stop()
	tsB := newRaceSetup(t, tsA.addr)
	defer tsB.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	amount := uint256.NewInt(10_000_000_000_000)

	txA := tsA.signTx(t, 0, recipient, amount, nil)
	resA, err := tsA.node.ProcessBatch([]*types.Transaction{txA})
	if err != nil {
		t.Fatalf("A ProcessBatch failed: %v", err)
	}
	// Sleep a hair to make the wall-clock path visibly non-deterministic
	// if that is the current behaviour. A deterministic implementation
	// (derived from parent timestamp + interval) would be unaffected.
	time.Sleep(1100 * time.Millisecond)
	txB := tsA.signTx(t, 0, recipient, amount, nil) // reuse key, nonce 0 on fresh node
	resB, err := tsB.node.ProcessBatch([]*types.Transaction{txB})
	if err != nil {
		t.Fatalf("B ProcessBatch failed: %v", err)
	}

	if resA.Block.Time() != resB.Block.Time() {
		t.Fatalf("block timestamps must be deterministic, got %d vs %d",
			resA.Block.Time(), resB.Block.Time())
	}
}

// Finding 6 — synthetic_proofs.go builds a mock proof unconditionally,
// even when the prover returns the MOCK_SP1_PROOF sentinel. A production
// config (OverlayConfig.RequireRealProof = true) must reject a mock
// proof rather than wrap it in a synthetic Basefold/Groth16 envelope.
func TestProcessBatch_ProductionConfig_RejectsMockProof(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Flip the node into production-proof mode. The hermetic test prover
	// still returns MOCK_SP1_PROOF, so ProcessBatch must refuse it.
	ts.node.config.RequireRealProof = true

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	amount := uint256.NewInt(10_000_000_000_000)
	tx := ts.signTx(t, 0, recipient, amount, nil)

	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err == nil {
		t.Fatal("expected ProcessBatch to refuse a mock SP1 proof under RequireRealProof=true")
	}
}

// Finding 7 — Rollback.go calls txCache.Truncate without checking for
// errors (Truncate doesn't return one). We verify that if the cache
// rejects truncation, the rollback would leave state+tip stale.
// Because Truncate currently has no failure path, we test the weaker
// invariant: after a successful Rollback, the txCache length, the
// executionTip, and the stateDB all agree on the target block. If
// Truncate silently fails (e.g. via a future error return) these
// invariants are the ones that must be preserved.
func TestOverlayNode_Rollback_CacheAndStateStayConsistent(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	amount := uint256.NewInt(10_000_000_000_000)

	// Build 3 blocks and capture block 1's state root.
	var block1Root types.Hash
	for i := uint64(0); i < 3; i++ {
		tx := ts.signTx(t, i, recipient, amount, nil)
		res, err := ts.node.ProcessBatch([]*types.Transaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch %d failed: %v", i+1, err)
		}
		if i == 0 {
			block1Root = res.StateRoot
		}
	}
	if ts.node.txCache.Len() != 3 {
		t.Fatalf("expected 3 cache entries before rollback, got %d", ts.node.txCache.Len())
	}

	// Roll back to block 1.
	if err := ts.node.Rollback(1); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Invariants: all three of tip, cache length, and state root must
	// reflect block 1. If Truncate silently misbehaved in the future,
	// the cache/tip disagreement will show up here.
	if tip := ts.node.ExecutionTip(); tip != 1 {
		t.Errorf("executionTip = %d, want 1", tip)
	}
	if n := ts.node.txCache.Len(); n != 1 {
		t.Errorf("txCache.Len = %d, want 1", n)
	}
	if root := ts.node.StateDB().IntermediateRoot(true); root != block1Root {
		t.Errorf("state root = %s, want %s", root.Hex(), block1Root.Hex())
	}
	if entry := ts.node.txCache.GetByL2Block(1); entry == nil {
		t.Error("expected cache entry for block 1 to survive rollback")
	}
	// Blocks past the new tip must be gone from the cache.
	for _, b := range []uint64{2, 3} {
		if ts.node.txCache.GetByL2Block(b) != nil {
			t.Errorf("block %d should have been truncated", b)
		}
	}

	// Confirm that a programmatic Truncate past the chain is a no-op —
	// the caller of Rollback must not observe a length-changing failure.
	before := ts.node.txCache.Len()
	ts.node.txCache.Truncate(999)
	if after := ts.node.txCache.Len(); after != before {
		t.Errorf("Truncate past chain should be no-op, len %d -> %d", before, after)
	}
}

// Bonus: Rollback must update finalizedTip/provenTip when they are
// ahead of the new tip. rollback.go handles this inline; we guard
// against a regression here because the same code path is triggered
// by CascadeRollback.
func TestOverlayNode_Rollback_AdjustsProvenAndFinalizedTips(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	amount := uint256.NewInt(10_000_000_000_000)
	for i := uint64(0); i < 3; i++ {
		tx := ts.signTx(t, i, recipient, amount, nil)
		if _, err := ts.node.ProcessBatch([]*types.Transaction{tx}); err != nil {
			t.Fatalf("ProcessBatch %d failed: %v", i+1, err)
		}
	}

	// Mark block 3 as confirmed/finalized, then roll back to 1.
	ts.node.SetConfirmedTip(3)
	ts.node.SetFinalizedTip(3)

	if err := ts.node.Rollback(1); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if ts.node.FinalizedTip() > 1 {
		t.Errorf("finalizedTip should be clamped to 1, got %d", ts.node.FinalizedTip())
	}
	if ts.node.ProvenTip() > 1 {
		t.Errorf("provenTip should be clamped to 1, got %d", ts.node.ProvenTip())
	}
}

// Sanity smoke test to make sure the race detector actually triggers
// the CascadeRollback on race-loss, closing a wiring gap that could
// otherwise be silently broken.
func TestRaceDetector_OnRaceLost_FiresCascadeRollback(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	var (
		mu     sync.Mutex
		called bool
	)
	// Replace the cascade callback with a spy that records the event.
	ts.node.raceDetector.OnRaceLost(func(ev *CovenantAdvanceEvent) {
		mu.Lock()
		defer mu.Unlock()
		called = true
	})

	ev := &CovenantAdvanceEvent{
		BSVTxID:    types.HexToHash("0xabc"),
		L2BlockNum: 1,
		IsOurs:     false,
	}
	if err := ts.node.raceDetector.HandleCovenantAdvance(ev); err != nil {
		t.Fatalf("HandleCovenantAdvance failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Fatal("expected OnRaceLost callback to fire for a peer advance")
	}
}

// The following helpers live here so that the failing-cache regression
// test can expand later without touching the production type. Right now
// TxCache.Truncate returns no error; if it gains one, this variant can
// be swapped in to force the failure and verify Rollback propagates it.
type failingTruncateCache struct {
	*TxCache
	fail bool
}

func (f *failingTruncateCache) Truncate(afterBlock uint64) {
	if f.fail {
		return // silently skip truncation
	}
	f.TxCache.Truncate(afterBlock)
}

// Ensure helper type is exercised so the file compiles clean.
var _ = func() *failingTruncateCache {
	return &failingTruncateCache{
		TxCache: NewTxCache(ConfirmedState{}),
	}
}

// Silence unused-import linter for odd combinations above.
var (
	_ = bytes.Equal
	_ = big.NewInt
	_ = state.New
	_ = db.NewMemoryDB
	_ = vm.DefaultL2Config
)
