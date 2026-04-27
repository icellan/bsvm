package bridge

import (
	"context"
	"errors"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// fakeChainReader is an in-memory implementation of ChainReader used by
// the scanner unit tests. It stores headers + receipts keyed by block
// number and exposes a convenience `addBatch` builder that constructs a
// canonical header and a single receipt with a list of synthetic
// WithdrawalInitiated logs.
type fakeChainReader struct {
	headers  map[uint64]*ChainHeader
	receipts map[uint64][]*types.Receipt
}

func newFakeChainReader() *fakeChainReader {
	return &fakeChainReader{
		headers:  map[uint64]*ChainHeader{},
		receipts: map[uint64][]*types.Receipt{},
	}
}

func (f *fakeChainReader) HeaderByNumber(number uint64) *ChainHeader {
	return f.headers[number]
}

func (f *fakeChainReader) ReceiptsByBlock(_ types.Hash, number uint64) []*types.Receipt {
	return f.receipts[number]
}

// addBatch records a canonical block at `blockNum` whose receipts emit
// the supplied withdrawals (preserving order). Each withdrawal becomes
// one log on a single receipt — matching how ApplyWithdrawTx emits.
//
// `nonceCursor` is the bridge's withdrawalNonce slot value before this
// batch executed (i.e. the first nonce assigned in this batch).
func (f *fakeChainReader) addBatch(blockNum uint64, nonceCursor uint64, ws []withdrawalSpec) {
	hash := types.HexToHash("0x" + repeatHex("aa", 32))
	hash[0] = byte(blockNum)
	f.headers[blockNum] = &ChainHeader{Number: blockNum, Hash: hash}

	logs := make([]*types.Log, 0, len(ws))
	for i, w := range ws {
		nonce := nonceCursor + uint64(i)
		logs = append(logs, makeWithdrawalLog(w.bsvAddr, w.satoshis, nonce, blockNum))
	}
	f.receipts[blockNum] = []*types.Receipt{{
		Status: 1,
		Logs:   logs,
	}}
}

type withdrawalSpec struct {
	bsvAddr  []byte
	satoshis uint64
}

// makeWithdrawalLog produces a synthetic WithdrawalInitiated log whose
// data layout exactly matches what ApplyWithdrawTx emits in production.
// Data: addrPadded(32) || weiAmount(32) || withdrawalHash(32).
func makeWithdrawalLog(bsvAddr []byte, satoshis uint64, nonce uint64, blockNum uint64) *types.Log {
	data := make([]byte, 96)
	copy(data[0:20], bsvAddr)
	// weiAmount = satoshis * 10^10, big-endian. Encoded into the low 8
	// bytes of the second 32-byte word — fits as long as satoshis fits
	// in uint64 (true for the test scale).
	wei := uint64(satoshis) * 10_000_000_000
	for i := 0; i < 8; i++ {
		data[63-i] = byte(wei >> (8 * i))
	}
	wh := WithdrawalHash(bsvAddr, satoshis, nonce)
	copy(data[64:96], wh[:])
	return &types.Log{
		Address:     types.BridgeContractAddress,
		Topics:      []types.Hash{withdrawalInitiatedTopic, {}},
		Data:        data,
		BlockNumber: blockNum,
	}
}

func repeatHex(b string, n int) string {
	out := make([]byte, 0, n*len(b))
	for i := 0; i < n; i++ {
		out = append(out, b...)
	}
	return string(out)
}

// TestChainDBScanner_HappyPath: 3 finalized batches, two of which carry
// withdrawals, one carries multiple. fromNonce=0 so all are returned;
// each PendingWithdrawal must carry the right BatchHashes / LeafIndex
// so the Withdrawer can compute a valid proof.
func TestChainDBScanner_HappyPath(t *testing.T) {
	addrA := []byte("aaaaaaaaaaaaaaaaaaaa")
	addrB := []byte("bbbbbbbbbbbbbbbbbbbb")
	addrC := []byte("cccccccccccccccccccc")

	chain := newFakeChainReader()
	// Block 1: 1 withdrawal (nonce 0)
	chain.addBatch(1, 0, []withdrawalSpec{{bsvAddr: addrA, satoshis: 100}})
	// Block 2: no withdrawals (just to confirm the gap is fine)
	chain.headers[2] = &ChainHeader{Number: 2}
	// Block 3: 2 withdrawals (nonces 1,2)
	chain.addBatch(3, 1, []withdrawalSpec{
		{bsvAddr: addrB, satoshis: 200},
		{bsvAddr: addrC, satoshis: 300},
	})

	scanner := NewChainDBWithdrawalScanner(chain, FinalizedTipFunc(func() uint64 { return 3 }))
	got, err := scanner.ScanPendingWithdrawals(0)
	if err != nil {
		t.Fatalf("ScanPendingWithdrawals: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d withdrawals, want 3", len(got))
	}

	// Check nonces assigned in emission order across the chain.
	wantNonces := []uint64{0, 1, 2}
	for i, w := range got {
		if w.Nonce != wantNonces[i] {
			t.Errorf("withdrawal[%d].Nonce = %d, want %d", i, w.Nonce, wantNonces[i])
		}
	}

	// Check first withdrawal: block 1, addrA, single-leaf batch.
	w0 := got[0]
	if w0.L2BlockNum != 1 {
		t.Errorf("w0.L2BlockNum = %d, want 1", w0.L2BlockNum)
	}
	if len(w0.BatchHashes) != 1 {
		t.Errorf("w0.BatchHashes len = %d, want 1", len(w0.BatchHashes))
	}
	if w0.LeafIndex != 0 {
		t.Errorf("w0.LeafIndex = %d, want 0", w0.LeafIndex)
	}

	// Check w1 + w2: same batch, BatchHashes shared, leaf indexes 0/1.
	w1, w2 := got[1], got[2]
	if w1.L2BlockNum != 3 || w2.L2BlockNum != 3 {
		t.Errorf("w1/w2 block = %d/%d, want 3/3", w1.L2BlockNum, w2.L2BlockNum)
	}
	if len(w1.BatchHashes) != 2 || len(w2.BatchHashes) != 2 {
		t.Errorf("BatchHashes len = %d/%d, want 2/2", len(w1.BatchHashes), len(w2.BatchHashes))
	}
	if w1.LeafIndex != 0 || w2.LeafIndex != 1 {
		t.Errorf("leaf indexes = %d/%d, want 0/1", w1.LeafIndex, w2.LeafIndex)
	}

	// Confirm the Merkle proof reconstructed by the scanner verifies.
	root, proof := WithdrawalProof(w1.BatchHashes, w1.LeafIndex)
	if !VerifyWithdrawalProof(w1.WithdrawalHash, proof, w1.LeafIndex, root) {
		t.Error("scanner-supplied BatchHashes do not verify w1 proof")
	}

	// Check satoshi/recipient round-trip.
	if got[0].AmountSatoshis != 100 || got[1].AmountSatoshis != 200 || got[2].AmountSatoshis != 300 {
		t.Errorf("satoshis = %d/%d/%d, want 100/200/300",
			got[0].AmountSatoshis, got[1].AmountSatoshis, got[2].AmountSatoshis)
	}
}

// TestChainDBScanner_FiltersClaimed: when fromNonce is set the scanner
// must drop any withdrawal whose nonce < fromNonce, leaving the
// LastClaimedNonce-respecting cursor semantics the Withdrawer relies
// on for idempotent ProcessFinalizedWithdrawals passes.
func TestChainDBScanner_FiltersClaimed(t *testing.T) {
	addr := []byte("aaaaaaaaaaaaaaaaaaaa")
	chain := newFakeChainReader()
	chain.addBatch(1, 0, []withdrawalSpec{
		{bsvAddr: addr, satoshis: 100},
		{bsvAddr: addr, satoshis: 200},
	})
	chain.addBatch(2, 2, []withdrawalSpec{
		{bsvAddr: addr, satoshis: 300},
	})

	scanner := NewChainDBWithdrawalScanner(chain, FinalizedTipFunc(func() uint64 { return 2 }))

	// LastClaimedNonce = 1 → fromNonce = 2; nonce 0+1 must be filtered.
	got, err := scanner.ScanPendingWithdrawals(2)
	if err != nil {
		t.Fatalf("ScanPendingWithdrawals: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 (only nonce 2 should remain)", len(got))
	}
	if got[0].Nonce != 2 {
		t.Errorf("nonce = %d, want 2", got[0].Nonce)
	}
}

// TestChainDBScanner_IdempotentTwoPasses: two scans with the same
// fromNonce return identical records. This guards the Withdrawer's
// "scan twice, broadcast once" property — without it a slow broadcast
// could cause double-claiming.
func TestChainDBScanner_IdempotentTwoPasses(t *testing.T) {
	addr := []byte("aaaaaaaaaaaaaaaaaaaa")
	chain := newFakeChainReader()
	chain.addBatch(1, 0, []withdrawalSpec{{bsvAddr: addr, satoshis: 100}})
	chain.addBatch(2, 1, []withdrawalSpec{{bsvAddr: addr, satoshis: 200}})

	scanner := NewChainDBWithdrawalScanner(chain, FinalizedTipFunc(func() uint64 { return 2 }))

	first, err := scanner.ScanPendingWithdrawals(0)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	second, err := scanner.ScanPendingWithdrawals(0)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("len mismatch: first=%d second=%d", len(first), len(second))
	}
	for i := range first {
		if first[i].Nonce != second[i].Nonce ||
			first[i].WithdrawalHash != second[i].WithdrawalHash ||
			first[i].LeafIndex != second[i].LeafIndex {
			t.Errorf("withdrawal[%d] differs across passes", i)
		}
	}
}

// TestChainDBScanner_RespectsFinalizedTip: only blocks <= finalizedTip
// should be scanned. Speculative blocks above the tip are ignored.
func TestChainDBScanner_RespectsFinalizedTip(t *testing.T) {
	addr := []byte("aaaaaaaaaaaaaaaaaaaa")
	chain := newFakeChainReader()
	chain.addBatch(1, 0, []withdrawalSpec{{bsvAddr: addr, satoshis: 100}})
	chain.addBatch(2, 1, []withdrawalSpec{{bsvAddr: addr, satoshis: 200}}) // unfinalized

	scanner := NewChainDBWithdrawalScanner(chain, FinalizedTipFunc(func() uint64 { return 1 }))
	got, err := scanner.ScanPendingWithdrawals(0)
	if err != nil {
		t.Fatalf("ScanPendingWithdrawals: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 (block 2 is past finalized tip and must be ignored)", len(got))
	}
	if got[0].L2BlockNum != 1 {
		t.Errorf("got block %d, want 1", got[0].L2BlockNum)
	}
}

// TestChainDBScanner_ZeroTip: with finalizedTip=0 (no L2 blocks
// confirmed yet) the scanner returns no withdrawals.
func TestChainDBScanner_ZeroTip(t *testing.T) {
	chain := newFakeChainReader()
	scanner := NewChainDBWithdrawalScanner(chain, FinalizedTipFunc(func() uint64 { return 0 }))
	got, err := scanner.ScanPendingWithdrawals(0)
	if err != nil {
		t.Fatalf("ScanPendingWithdrawals: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d withdrawals at zero tip, want 0", len(got))
	}
}

// TestChainDBScanner_ContextCancel ensures the context-aware variant
// bails out cleanly mid-walk.
func TestChainDBScanner_ContextCancel(t *testing.T) {
	addr := []byte("aaaaaaaaaaaaaaaaaaaa")
	chain := newFakeChainReader()
	for i := uint64(1); i <= 5; i++ {
		chain.addBatch(i, i-1, []withdrawalSpec{{bsvAddr: addr, satoshis: 100}})
	}
	scanner := NewChainDBWithdrawalScanner(chain, FinalizedTipFunc(func() uint64 { return 5 }))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := scanner.ScanPendingWithdrawalsCtx(ctx, 0)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestChainDBScanner_NilDeps: both the chain and the finalized provider
// must be supplied. Nil → error rather than panic.
func TestChainDBScanner_NilDeps(t *testing.T) {
	scanner := &ChainDBWithdrawalScanner{}
	if _, err := scanner.ScanPendingWithdrawals(0); err == nil {
		t.Error("expected error with nil deps")
	}
}
