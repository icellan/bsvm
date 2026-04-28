package bridge

import (
	"errors"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// fakeAnchorReader is an in-memory AnchorReader for finder unit tests.
type fakeAnchorReader struct {
	records map[uint64]struct {
		txid      types.Hash
		confirmed bool
	}
}

func newFakeAnchorReader() *fakeAnchorReader {
	return &fakeAnchorReader{records: make(map[uint64]struct {
		txid      types.Hash
		confirmed bool
	})}
}

func (f *fakeAnchorReader) Set(blockNum uint64, txid types.Hash, confirmed bool) {
	f.records[blockNum] = struct {
		txid      types.Hash
		confirmed bool
	}{txid: txid, confirmed: confirmed}
}

func (f *fakeAnchorReader) ReadAnchor(blockNum uint64) (types.Hash, bool, bool) {
	r, ok := f.records[blockNum]
	if !ok {
		return types.Hash{}, false, false
	}
	return r.txid, r.confirmed, true
}

// fakeBSVTxFetcher is an in-memory BSVTxFetcher for finder unit tests.
type fakeBSVTxFetcher struct {
	txs    map[types.Hash]*BSVTransaction
	called int
}

func newFakeBSVTxFetcher() *fakeBSVTxFetcher {
	return &fakeBSVTxFetcher{txs: make(map[types.Hash]*BSVTransaction)}
}

func (f *fakeBSVTxFetcher) FetchBSVTx(txid types.Hash) (*BSVTransaction, error) {
	f.called++
	tx, ok := f.txs[txid]
	if !ok {
		return nil, nil
	}
	return tx, nil
}

// TestChainDBAdvanceFinder_NoRecord verifies the no-record branch
// returns ErrAdvanceNotYetAnchored.
func TestChainDBAdvanceFinder_NoRecord(t *testing.T) {
	anchors := newFakeAnchorReader()
	fetcher := newFakeBSVTxFetcher()
	finder := NewChainDBAdvanceFinder(anchors, fetcher)

	_, err := finder.FindCovenantAdvanceForBlock(99)
	if !errors.Is(err, ErrAdvanceNotYetAnchored) {
		t.Fatalf("missing record: got %v, want ErrAdvanceNotYetAnchored", err)
	}
	if fetcher.called != 0 {
		t.Fatalf("fetcher called %d times, want 0 (no record path must short-circuit)",
			fetcher.called)
	}
}

// TestChainDBAdvanceFinder_UnconfirmedAnchor verifies the new gating
// behaviour: a record with Confirmed=false returns
// ErrAdvanceNotYetConfirmed and does NOT call the BSV tx fetcher (so
// the bridge withdrawer can't accidentally build a claim against an
// unconfirmed advance, which a re-org could orphan).
func TestChainDBAdvanceFinder_UnconfirmedAnchor(t *testing.T) {
	anchors := newFakeAnchorReader()
	fetcher := newFakeBSVTxFetcher()
	finder := NewChainDBAdvanceFinder(anchors, fetcher)

	const blockNum uint64 = 7
	txid := types.BytesToHash([]byte{0x07})
	anchors.Set(blockNum, txid, false /* confirmed */)
	fetcher.txs[txid] = &BSVTransaction{TxID: txid}

	_, err := finder.FindCovenantAdvanceForBlock(blockNum)
	if !errors.Is(err, ErrAdvanceNotYetConfirmed) {
		t.Fatalf("unconfirmed anchor: got %v, want ErrAdvanceNotYetConfirmed", err)
	}
	if fetcher.called != 0 {
		t.Fatalf("fetcher called %d times for unconfirmed anchor, want 0 (no fetch on retry-deferred)",
			fetcher.called)
	}
}

// TestChainDBAdvanceFinder_ConfirmedAnchor verifies the happy path:
// a confirmed record fetches and returns the BSV transaction.
func TestChainDBAdvanceFinder_ConfirmedAnchor(t *testing.T) {
	anchors := newFakeAnchorReader()
	fetcher := newFakeBSVTxFetcher()
	finder := NewChainDBAdvanceFinder(anchors, fetcher)

	const blockNum uint64 = 7
	txid := types.BytesToHash([]byte{0x07})
	anchors.Set(blockNum, txid, true /* confirmed */)
	want := &BSVTransaction{TxID: txid, BlockHeight: 800_000}
	fetcher.txs[txid] = want

	got, err := finder.FindCovenantAdvanceForBlock(blockNum)
	if err != nil {
		t.Fatalf("confirmed anchor: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("returned nil tx for confirmed anchor")
	}
	if got.TxID != want.TxID {
		t.Fatalf("got tx %s, want %s", got.TxID.BSVString(), want.TxID.BSVString())
	}
	if fetcher.called != 1 {
		t.Fatalf("fetcher called %d times, want 1", fetcher.called)
	}
}
