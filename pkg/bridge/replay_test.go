package bridge

import (
	"bytes"
	"math"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildDepositTx constructs a BSV transaction carrying a deposit payment
// to the given bridge script plus an OP_RETURN with the deposit payload
// (shard_id + l2_address).
func buildDepositTx(txID types.Hash, bridgeScript []byte, shardID []byte, l2Addr types.Address, satoshis uint64, blockHeight uint64) *BSVTransaction {
	if len(shardID) != 4 {
		panic("shardID must be 4 bytes")
	}

	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)

	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	return &BSVTransaction{
		TxID:        txID,
		BlockHeight: blockHeight,
		Outputs: []BSVOutput{
			{Script: bridgeScript, Value: satoshis},
			{Script: opReturnScript, Value: 0},
		},
	}
}

// newReplayMonitor creates a BridgeMonitor with a fresh in-memory DB
// suitable for replay tests.
func newReplayMonitor(t *testing.T, bridgeScript []byte) (*BridgeMonitor, *mockOverlaySubmitter) {
	t.Helper()
	store := db.NewMemoryDB()
	cfg := DefaultConfig()
	cfg.BSVConfirmations = 1
	cfg.MinDepositSatoshis = 1
	submitter := &mockOverlaySubmitter{}
	m := NewBridgeMonitor(cfg, &mockBSVClient{}, submitter, store)
	m.SetBridgeScriptHash(bridgeScript)
	return m, submitter
}

// ---------------------------------------------------------------------------
// A. Deposit replay
// ---------------------------------------------------------------------------

// TestDepositReplay_SameUTXO_CreditedOnce feeds the same deposit UTXO
// through the monitor twice and asserts that after MarkProcessed the
// monitor refuses to emit a second credit for the same (txid, vout).
func TestDepositReplay_SameUTXO_CreditedOnce(t *testing.T) {
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	m, _ := newReplayMonitor(t, bridgeScript)

	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	shardID := make([]byte, 4)
	txID := types.HexToHash("0xfeed")

	tx := buildDepositTx(txID, bridgeScript, shardID, l2Addr, 50_000, 100)

	// First feed: deposit becomes pending.
	m.ProcessBlock(100, []*BSVTransaction{tx})
	if m.PendingCount() != 1 {
		t.Fatalf("expected 1 pending after first feed, got %d", m.PendingCount())
	}

	// Credit it once.
	eligible := m.EligibleDeposits(200)
	if len(eligible) != 1 {
		t.Fatalf("expected 1 eligible after first feed, got %d", len(eligible))
	}
	// Mark as processed (this is what the overlay does after inclusion).
	m.MarkProcessed(txID, 0)

	// Second feed of the same UTXO: dedup map should prevent re-credit.
	m.ProcessBlock(101, []*BSVTransaction{tx})

	eligible = m.EligibleDeposits(201)
	if len(eligible) != 0 {
		t.Errorf("replay of processed deposit produced %d credits, want 0", len(eligible))
	}

	// The monitor's view of whether it's processed must remain true.
	if !m.IsProcessed(txID, 0) {
		t.Error("deposit should still be marked processed after replay attempt")
	}
}

// TestDepositReplay_WrongShardID asserts that a deposit whose OP_RETURN
// targets a different shard is rejected by the monitor (no credit
// emitted). This pins the fix for the review finding that ParseDeposit
// previously ignored shard_id, letting cross-shard deposits through.
func TestDepositReplay_WrongShardID(t *testing.T) {
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	m, _ := newReplayMonitor(t, bridgeScript)
	// Our local shard is shard 1; the deposit targets shard 2.
	m.SetLocalShardID(1)

	l2Addr := types.HexToAddress("0x2222222222222222222222222222222222222222")
	foreignShardID := []byte{0x00, 0x00, 0x00, 0x02}

	txID := types.HexToHash("0xcafe01")
	tx := buildDepositTx(txID, bridgeScript, foreignShardID, l2Addr, 70_000, 100)

	// Parser-level behaviour: ParseDeposit must validate shard_id and
	// return nil for a foreign shard.
	if parsed := ParseDeposit(tx, bridgeScript, 1); parsed != nil {
		t.Fatalf("ParseDeposit accepted foreign shard_id 2 when local=1: %+v", parsed)
	}

	// Monitor-level: feeding the same tx through the monitor must not
	// credit anything.
	m.ProcessBlock(100, []*BSVTransaction{tx})
	if m.PendingCount() != 0 {
		t.Errorf("foreign-shard deposit became pending (count=%d), want 0", m.PendingCount())
	}
	eligible := m.EligibleDeposits(200)
	if len(eligible) != 0 {
		t.Errorf("foreign-shard deposit became eligible (count=%d), want 0", len(eligible))
	}

	// Sanity: a matching shard deposit IS accepted.
	matchingShardID := []byte{0x00, 0x00, 0x00, 0x01}
	good := buildDepositTx(types.HexToHash("0xcafe02"), bridgeScript,
		matchingShardID, l2Addr, 80_000, 101)
	if parsed := ParseDeposit(good, bridgeScript, 1); parsed == nil {
		t.Fatalf("ParseDeposit rejected matching shard_id 1; expected acceptance")
	}
}

// TestDepositReplay_SameTxIDDifferentVout verifies that the (txid, vout)
// composite key correctly treats two outputs in the same BSV tx as
// independent deposits — replaying one does not suppress the other, and
// replaying both does not double-credit either.
func TestDepositReplay_SameTxIDDifferentVout(t *testing.T) {
	m, _ := newReplayMonitor(t, []byte{0xaa})

	txID := types.HexToHash("0xabcdef")
	dep0 := NewDepositWithVout(txID, 0, 100,
		types.HexToAddress("0x1111111111111111111111111111111111111111"), 10_000)
	dep1 := NewDepositWithVout(txID, 1, 100,
		types.HexToAddress("0x2222222222222222222222222222222222222222"), 20_000)
	dep0.Confirmed = true
	dep1.Confirmed = true

	if err := m.PersistDeposit(dep0); err != nil {
		t.Fatalf("PersistDeposit(vout=0): %v", err)
	}
	if err := m.PersistDeposit(dep1); err != nil {
		t.Fatalf("PersistDeposit(vout=1): %v", err)
	}

	// Replaying dep0 must be a no-op idempotently.
	if err := m.PersistDeposit(dep0); err != nil {
		t.Fatalf("replay PersistDeposit(vout=0): %v", err)
	}

	// Both independent credits must remain marked processed exactly once.
	if !m.IsProcessed(txID, 0) {
		t.Error("vout=0 should be processed")
	}
	if !m.IsProcessed(txID, 1) {
		t.Error("vout=1 should be processed")
	}
}

// ---------------------------------------------------------------------------
// B. Withdrawal replay (BSV reorg scenario)
// ---------------------------------------------------------------------------

// TestWithdrawalReplay_ReorgRevertsNonce models the covenant-side bridge
// state across a BSV reorg:
//
//  1. Start with WithdrawalNonce=N.
//  2. Execute withdrawal with nonce=N. Covenant advances to N+1.
//  3. Simulate a BSV reorg that rolls the covenant back to nonce=N.
//  4. Feed the SAME withdrawal (same bsvAddress, amount, nonce=N).
//
// The go-model persists a set of spent withdrawal nullifiers alongside
// CovenantState, so a replay at the same (recipient, amount, nonce) is
// rejected even after a nonce-rollback.
func TestWithdrawalReplay_ReorgRevertsNonce(t *testing.T) {
	const initialBalance = uint64(1_000_000_000) // 10 BSV
	const withdrawAmount = uint64(100_000_000)   // 1 BSV
	const startNonce = uint64(7)

	genesis := types.HexToHash("0x0001")
	stateCovenant := types.HexToHash("0x0002")
	initial := covenant.BridgeState{
		Balance:         initialBalance,
		WithdrawalNonce: startNonce,
	}
	bm := covenant.NewBridgeManager(genesis, 0, initialBalance, initial, stateCovenant)

	addr := make([]byte, 20)
	addr[0] = 0xab
	root := types.HexToHash("0xbeef")
	proof := [][]byte{make([]byte, 32)} // minimal valid proof shape

	// Step 1: first withdrawal at nonce=startNonce succeeds.
	data, err := bm.BuildWithdrawalData(addr, withdrawAmount, root, proof, 0)
	if err != nil {
		t.Fatalf("first BuildWithdrawalData: %v", err)
	}
	if data.Nonce != startNonce {
		t.Fatalf("first withdrawal Nonce = %d, want %d", data.Nonce, startNonce)
	}
	firstTx := types.HexToHash("0x1111")
	bm.ApplyWithdrawal(firstTx, withdrawAmount)

	if got := bm.CurrentState().WithdrawalNonce; got != startNonce+1 {
		t.Fatalf("after first withdrawal, nonce = %d, want %d", got, startNonce+1)
	}
	postAdvanceBalance := bm.CurrentState().Balance
	if postAdvanceBalance != initialBalance-withdrawAmount {
		t.Fatalf("post-advance balance = %d, want %d",
			postAdvanceBalance, initialBalance-withdrawAmount)
	}

	// The commitment MUST have advanced off zero — it's the tamper-
	// evident log the on-chain bridge covenant keeps.
	var zeroCommit types.Hash
	commitAfterApply := bm.CurrentState().WithdrawalsCommitment
	if commitAfterApply == zeroCommit {
		t.Fatalf("after first withdrawal, commitment still zero; manager is not folding nullifiers")
	}

	// Step 2: BSV reorg rolls the covenant nonce+balance back to the
	// pre-advance snapshot — but the nullifier set is part of the
	// manager's durable state and must survive the nonce rollback (a
	// replay of a BSV-confirmed withdrawal is a credible double-spend
	// vector, so once observed the nullifier MUST persist). The running
	// WithdrawalsCommitment is likewise monotonic: it must not retreat,
	// otherwise a reorg replay could silently hide the earlier
	// observation from an auditor.
	bm.RollbackWithdrawal(firstTx, withdrawAmount)
	if got := bm.CurrentState().WithdrawalNonce; got != startNonce {
		t.Fatalf("after reorg rollback, nonce = %d, want %d", got, startNonce)
	}
	if got := bm.CurrentState().Balance; got != initialBalance {
		t.Fatalf("after reorg rollback, balance = %d, want %d", got, initialBalance)
	}
	if got := bm.CurrentState().WithdrawalsCommitment; got != commitAfterApply {
		t.Errorf("commitment rolled back on reorg: got %x, want %x (commitment must be monotonic)",
			got, commitAfterApply)
	}

	// Step 3: replay the same withdrawal at the same nonce must fail
	// because the nullifier (recipient || amount || nonce) has been
	// observed already.
	if _, err := bm.BuildWithdrawalData(addr, withdrawAmount, root, proof, 0); err == nil {
		t.Errorf("replay of previously-observed withdrawal at nonce=%d was accepted (amount=%d, addr=%x); expected rejection via nullifier set",
			startNonce, withdrawAmount, addr)
	}

	// Sanity: a withdrawal to a DIFFERENT recipient at the same nonce
	// must still be accepted (the nullifier is per-(recipient,amount,nonce)).
	otherAddr := make([]byte, 20)
	otherAddr[0] = 0xcd
	if _, err := bm.BuildWithdrawalData(otherAddr, withdrawAmount, root, proof, 0); err != nil {
		t.Errorf("distinct recipient withdrawal at same nonce rejected: %v", err)
	}
}

// TestWithdrawalReplay_NonceMustMatchCurrent provides positive coverage
// of the nonce == WithdrawalNonce check that the contract DOES enforce:
// feeding a withdrawal that doesn't advance the nonce (stale nonce) is
// rejected at the BridgeManager level via sequential-nonce enforcement
// from the withdrawer. This pins the existing (narrow) defence.
func TestWithdrawalReplay_NonceMustMatchCurrent(t *testing.T) {
	const startNonce = uint64(3)
	initial := covenant.BridgeState{Balance: 1_000_000, WithdrawalNonce: startNonce}
	bm := covenant.NewBridgeManager(types.HexToHash("0x01"), 0, 1_000_000, initial,
		types.HexToHash("0x02"))

	// First withdrawal (nonce=3) advances covenant to nonce=4.
	first, err := bm.BuildWithdrawalData(make([]byte, 20), 100_000,
		types.HexToHash("0xaa"), [][]byte{make([]byte, 32)}, 0)
	if err != nil {
		t.Fatalf("first BuildWithdrawalData: %v", err)
	}
	if first.Nonce != startNonce {
		t.Fatalf("first Nonce = %d, want %d", first.Nonce, startNonce)
	}
	bm.ApplyWithdrawal(types.HexToHash("0x10"), 100_000)

	// Second withdrawal must use nonce=4 — a replay of nonce=3 is
	// represented as building a withdrawal whose embedded Nonce field
	// is compared against the live state on-chain. The BridgeManager
	// always tags the build data with the CURRENT nonce, so the second
	// call yields Nonce=4 (not 3). This confirms that at least the
	// "active nonce counter" branch cannot emit nonce=3 again via the
	// manager — the replay risk is specifically the reorg scenario
	// exercised in TestWithdrawalReplay_ReorgRevertsNonce.
	second, err := bm.BuildWithdrawalData(make([]byte, 20), 100_000,
		types.HexToHash("0xbb"), [][]byte{make([]byte, 32)}, 0)
	if err != nil {
		t.Fatalf("second BuildWithdrawalData: %v", err)
	}
	if second.Nonce == startNonce {
		t.Errorf("manager re-used nonce=%d after withdrawal; replay defence bypassed",
			startNonce)
	}
	if second.Nonce != startNonce+1 {
		t.Errorf("second Nonce = %d, want %d", second.Nonce, startNonce+1)
	}
}

// ---------------------------------------------------------------------------
// C. Deposit tree inclusion / exclusion proofs
// ---------------------------------------------------------------------------

// buildTreeWithDeposits populates a fresh DepositTree with n deterministic
// deposits, commits it, and reopens from the committed root so the tree
// in-memory state reflects the persisted inclusion set.
func buildTreeWithDeposits(t *testing.T, n int) (*DepositTree, []*Deposit, types.Hash) {
	t.Helper()
	diskDB := db.NewMemoryDB()
	tree, err := NewDepositTree(diskDB, types.EmptyRootHash)
	if err != nil {
		t.Fatalf("NewDepositTree: %v", err)
	}
	deps := make([]*Deposit, n)
	for i := 0; i < n; i++ {
		var txid types.Hash
		txid[0] = byte(i >> 8)
		txid[1] = byte(i & 0xff)
		txid[2] = 0xcc // marker so absent-txid stays distinct
		dep := NewDepositWithVout(txid, 0, uint64(100+i),
			types.HexToAddress("0x1111111111111111111111111111111111111111"),
			uint64(10_000+i),
		)
		dep.Confirmed = true
		tree.AddDeposit(dep)
		deps[i] = dep
	}
	root, err := tree.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Reopen at the committed root so later reads traverse the persisted
	// MPT rather than the stale in-memory trie.
	reopened, err := NewDepositTree(diskDB, root)
	if err != nil {
		t.Fatalf("reopen DepositTree: %v", err)
	}
	return reopened, deps, root
}

// TestDepositTree_InclusionAndExclusion covers trees of size 1, 5, and
// 100. For each size we:
//   - Verify every inserted deposit is found (positive inclusion).
//   - Tamper with the returned deposit bytes and verify the tree's own
//     view (GetDeposit returns what was stored; the tampered copy is not
//     equal — acts as our proof-of-inclusion integrity check).
//   - Assert a known-absent BSV txid is rejected (exclusion).
func TestDepositTree_InclusionAndExclusion(t *testing.T) {
	for _, n := range []int{1, 5, 100} {
		n := n
		t.Run("", func(t *testing.T) {
			tree, deps, root := buildTreeWithDeposits(t, n)
			if root == (types.Hash{}) || root == types.EmptyRootHash {
				t.Fatalf("committed root is trivial for n=%d", n)
			}

			// Inclusion: every inserted deposit is found, with matching payload.
			for i, d := range deps {
				if !tree.HasDeposit(d.BSVTxID) {
					t.Fatalf("n=%d: inserted deposit %d missing", n, i)
				}
				got := tree.GetDeposit(d.BSVTxID)
				if got == nil {
					t.Fatalf("n=%d: GetDeposit returned nil for index %d", n, i)
				}
				if got.SatoshiAmount != d.SatoshiAmount {
					t.Errorf("n=%d idx=%d: amount %d != %d", n, i, got.SatoshiAmount, d.SatoshiAmount)
				}
				if got.L2Address != d.L2Address {
					t.Errorf("n=%d idx=%d: l2addr mismatch", n, i)
				}
				if got.BSVBlockHeight != d.BSVBlockHeight {
					t.Errorf("n=%d idx=%d: height %d != %d", n, i, got.BSVBlockHeight, d.BSVBlockHeight)
				}

				// Tamper: flip a byte in the stored txid used as the lookup
				// key. The tamper is against the CLIENT-held key; the tree
				// must then either return nil (not found) or a non-matching
				// deposit. This guards against a consumer accidentally
				// trusting a tampered txid.
				tampered := d.BSVTxID
				tampered[5] ^= 0xff
				if tampered == d.BSVTxID {
					t.Fatalf("tamper produced same txid; test bug")
				}
				if tree.HasDeposit(tampered) {
					// It's astronomically unlikely a random flip collides
					// with another inserted deposit, but guard anyway.
					if _, collides := findDepositByTxID(deps, tampered); !collides {
						t.Errorf("n=%d idx=%d: tampered txid %x unexpectedly present",
							n, i, tampered[:])
					}
				}
			}

			// Exclusion: a known-absent txid is rejected.
			var absent types.Hash
			absent[0] = 0xab
			absent[31] = 0xcd
			if _, collides := findDepositByTxID(deps, absent); collides {
				t.Fatalf("n=%d: absent probe collides with real deposit; test bug", n)
			}
			if tree.HasDeposit(absent) {
				t.Errorf("n=%d: absent deposit reported as present", n)
			}
			if got := tree.GetDeposit(absent); got != nil {
				t.Errorf("n=%d: GetDeposit for absent returned non-nil: %+v", n, got)
			}
		})
	}
}

// findDepositByTxID returns the deposit with a matching txid, if any.
func findDepositByTxID(deps []*Deposit, txid types.Hash) (*Deposit, bool) {
	for _, d := range deps {
		if d.BSVTxID == txid {
			return d, true
		}
	}
	return nil, false
}

// TestWithdrawalMerkleProof_TamperFailsVerification hardens review item
// #3 on the withdrawal side: a one-byte tamper of a Merkle proof element
// must cause verification to fail.
func TestWithdrawalMerkleProof_TamperFailsVerification(t *testing.T) {
	for _, n := range []int{1, 5, 100} {
		n := n
		t.Run("", func(t *testing.T) {
			hashes := make([]types.Hash, n)
			for i := range hashes {
				hashes[i] = WithdrawalHash([]byte{byte(i + 1)}, uint64(i+1)*100, uint64(i))
			}
			root, allProofs := BuildWithdrawalMerkleTree(hashes)

			for i, proof := range allProofs {
				if !VerifyWithdrawalProof(hashes[i], proof, i, root) {
					t.Fatalf("n=%d idx=%d: clean proof failed verification", n, i)
				}
				if len(proof) == 0 {
					continue // single-leaf tree, no siblings to tamper
				}
				// Tamper a single bit of the first sibling.
				tampered := make([]types.Hash, len(proof))
				copy(tampered, proof)
				tampered[0][0] ^= 0x01
				if VerifyWithdrawalProof(hashes[i], tampered, i, root) {
					t.Errorf("n=%d idx=%d: tampered proof still verified", n, i)
				}
			}

			// Exclusion: a leaf NOT in the tree must not verify against
			// any valid-shaped proof copied from a real leaf.
			if len(hashes) > 0 {
				absent := WithdrawalHash([]byte{0xaa, 0xbb, 0xcc}, 99_999_999, 9_999_999)
				if _, ok := findHash(hashes, absent); ok {
					t.Fatalf("n=%d: absent probe collides; test bug", n)
				}
				if len(allProofs[0]) > 0 &&
					VerifyWithdrawalProof(absent, allProofs[0], 0, root) {
					t.Errorf("n=%d: absent leaf verified with real proof shape", n)
				}
			}
		})
	}
}

// findHash returns true if h is in hashes.
func findHash(hashes []types.Hash, h types.Hash) (int, bool) {
	for i, x := range hashes {
		if bytes.Equal(x[:], h[:]) {
			return i, true
		}
	}
	return -1, false
}

// ---------------------------------------------------------------------------
// D. Satoshis <-> Wei boundary cases
// ---------------------------------------------------------------------------

// TestSatoshisToWei_Boundaries exercises the conversion at zero, one,
// and max uint64. The multiplier is 1e10, and max_uint64 * 1e10 fits in
// uint256, so the conversion must not overflow.
func TestSatoshisToWei_Boundaries(t *testing.T) {
	tests := []struct {
		name     string
		sats     uint64
		wantZero bool
		// check is a post-conversion assertion. It is called with the
		// computed wei value.
		check func(t *testing.T, wei *uint256.Int)
	}{
		{
			name:     "zero satoshis",
			sats:     0,
			wantZero: true,
			check: func(t *testing.T, wei *uint256.Int) {
				if !wei.IsZero() {
					t.Errorf("0 sats -> wei = %s, want 0", wei)
				}
				if got := types.WeiToSatoshis(wei); got != 0 {
					t.Errorf("roundtrip 0 sats = %d, want 0", got)
				}
			},
		},
		{
			name: "one satoshi is smallest non-zero wei unit",
			sats: 1,
			check: func(t *testing.T, wei *uint256.Int) {
				want := uint256.NewInt(1e10)
				if wei.Cmp(want) != 0 {
					t.Errorf("1 sat -> wei = %s, want 1e10", wei)
				}
				// Anything strictly less than 1e10 wei should truncate to 0 sat.
				sub := new(uint256.Int).Sub(want, uint256.NewInt(1))
				if got := types.WeiToSatoshis(sub); got != 0 {
					t.Errorf("wei=1e10-1 -> %d sats, want 0", got)
				}
				// Exactly 1e10 -> 1 sat.
				if got := types.WeiToSatoshis(want); got != 1 {
					t.Errorf("wei=1e10 -> %d sats, want 1", got)
				}
			},
		},
		{
			name: "max uint64 satoshis does not overflow",
			sats: math.MaxUint64,
			check: func(t *testing.T, wei *uint256.Int) {
				// max_uint64 * 1e10 = ~1.8e29 — well inside uint256 (~1.1e77).
				// So it must NOT saturate, and roundtrip must be exact.
				expected := new(uint256.Int).Mul(
					new(uint256.Int).SetUint64(math.MaxUint64),
					uint256.NewInt(1e10),
				)
				if wei.Cmp(expected) != 0 {
					t.Errorf("maxuint64 sat -> wei = %s, want %s", wei, expected)
				}
				// Roundtrip must preserve max uint64.
				if got := types.WeiToSatoshis(wei); got != math.MaxUint64 {
					t.Errorf("roundtrip max sat = %d, want %d", got, uint64(math.MaxUint64))
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			wei := types.SatoshisToWei(tt.sats)
			if wei == nil {
				t.Fatalf("SatoshisToWei(%d) returned nil", tt.sats)
			}
			if tt.wantZero && !wei.IsZero() {
				t.Errorf("SatoshisToWei(%d) = %s, want zero", tt.sats, wei)
			}
			tt.check(t, wei)
		})
	}
}

// TestWeiToSatoshis_Saturation checks that wei values whose integer
// satoshi quotient exceeds math.MaxUint64 saturate to math.MaxUint64
// rather than silently wrapping via the low 64 bits of a uint256 Div
// result.
func TestWeiToSatoshis_Saturation(t *testing.T) {
	// Construct wei = (max_uint64 + 1) * 1e10, which is one satoshi
	// past the saturation point.
	over := new(uint256.Int).SetUint64(math.MaxUint64)
	over.Add(over, uint256.NewInt(1))
	over.Mul(over, uint256.NewInt(1e10))

	got := types.WeiToSatoshis(over)
	if got != math.MaxUint64 {
		t.Errorf("WeiToSatoshis over max uint64 = %d, want %d (saturation)",
			got, uint64(math.MaxUint64))
	}
}
