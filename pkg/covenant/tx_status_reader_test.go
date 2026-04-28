package covenant

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// fakeConfSource is a hand-rolled ConfirmationSource that returns a
// canned response for each txid. The hex argument the production code
// passes is the txid in BSV's big-endian display form
// (types.Hash.BSVString) — fakeConfSource keys its responses by the
// raw txid hex, not by Hash, so the test asserts on what the reader
// actually sends to the BSV node.
type fakeConfSource struct {
	mu    sync.Mutex
	resps map[string]map[string]interface{}
	errs  map[string]error
	calls []string
}

func newFakeConfSource() *fakeConfSource {
	return &fakeConfSource{
		resps: make(map[string]map[string]interface{}),
		errs:  make(map[string]error),
	}
}

func (f *fakeConfSource) GetRawTransactionVerbose(txidHex string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, txidHex)
	if e, ok := f.errs[txidHex]; ok {
		return nil, e
	}
	r, ok := f.resps[txidHex]
	if !ok {
		return nil, errors.New("unknown txid")
	}
	return r, nil
}

// fakeHeaderSource counts calls so cache-hit tests can assert no
// additional RPC happens.
type fakeHeaderSource struct {
	mu       sync.Mutex
	resps    map[string]map[string]interface{}
	errs     map[string]error
	callsBy  map[string]int
	totalRPC int
}

func newFakeHeaderSource() *fakeHeaderSource {
	return &fakeHeaderSource{
		resps:   make(map[string]map[string]interface{}),
		errs:    make(map[string]error),
		callsBy: make(map[string]int),
	}
}

func (f *fakeHeaderSource) GetBlockHeader(blockHash string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.totalRPC++
	f.callsBy[blockHash]++
	if e, ok := f.errs[blockHash]; ok {
		return nil, e
	}
	r, ok := f.resps[blockHash]
	if !ok {
		return nil, errors.New("unknown block hash")
	}
	return r, nil
}

func (f *fakeHeaderSource) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.totalRPC
}

// txidFromHex builds a types.Hash from a 64-char BSV-display-form hex
// string and returns the same string back so tests can use both the
// Hash and the canonical RPC argument without re-deriving them.
func txidFromHex(t *testing.T, hex string) (types.Hash, string) {
	t.Helper()
	h := types.BSVHashFromHex(hex)
	return h, h.BSVString()
}

// TestTxStatusReader_FastPath_BlockHeightProvided pins the modern-node
// path: when getrawtransaction returns blockheight directly, the
// reader returns it and never touches getblockheader.
func TestTxStatusReader_FastPath_BlockHeightProvided(t *testing.T) {
	conf := newFakeConfSource()
	hdr := newFakeHeaderSource()

	txid, txHex := txidFromHex(t, "11"+repeatHex("00", 31))
	conf.resps[txHex] = map[string]interface{}{
		"confirmations": float64(7),
		"blockhash":     "abc",
		"blockheight":   float64(5_000_001),
	}

	rdr := NewTxStatusReader(conf, hdr)
	st, err := rdr.GetTransactionStatus(context.Background(), txid)
	if err != nil {
		t.Fatalf("GetTransactionStatus: %v", err)
	}
	if st.Confirmations != 7 {
		t.Errorf("Confirmations = %d, want 7", st.Confirmations)
	}
	if st.BlockHeight != 5_000_001 {
		t.Errorf("BlockHeight = %d, want 5000001", st.BlockHeight)
	}
	if hdr.calls() != 0 {
		t.Errorf("modern-node fast path made %d getblockheader calls; want 0", hdr.calls())
	}
}

// TestTxStatusReader_Fallback_LegacyNodeHeightAbsent pins the legacy-
// node path: when the primary response has blockhash but no
// blockheight, the reader issues getblockheader and returns the
// recovered height.
func TestTxStatusReader_Fallback_LegacyNodeHeightAbsent(t *testing.T) {
	conf := newFakeConfSource()
	hdr := newFakeHeaderSource()

	txid, txHex := txidFromHex(t, "22"+repeatHex("00", 31))
	conf.resps[txHex] = map[string]interface{}{
		"confirmations": float64(3),
		"blockhash":     "deadbeefblockhash",
		// no blockheight
	}
	hdr.resps["deadbeefblockhash"] = map[string]interface{}{
		"height": float64(12_345),
	}

	rdr := NewTxStatusReader(conf, hdr)
	st, err := rdr.GetTransactionStatus(context.Background(), txid)
	if err != nil {
		t.Fatalf("GetTransactionStatus: %v", err)
	}
	if st.Confirmations != 3 {
		t.Errorf("Confirmations = %d, want 3", st.Confirmations)
	}
	if st.BlockHeight != 12_345 {
		t.Errorf("BlockHeight = %d, want 12345", st.BlockHeight)
	}
	if hdr.calls() != 1 {
		t.Errorf("legacy-node fallback made %d getblockheader calls; want 1", hdr.calls())
	}
}

// TestTxStatusReader_Cache_HitOnSameBlockHash pins the LRU cache
// behaviour: two confirmed txs in the same block produce only one
// getblockheader RPC.
func TestTxStatusReader_Cache_HitOnSameBlockHash(t *testing.T) {
	conf := newFakeConfSource()
	hdr := newFakeHeaderSource()

	tx1, hex1 := txidFromHex(t, "33"+repeatHex("00", 31))
	tx2, hex2 := txidFromHex(t, "44"+repeatHex("00", 31))

	const blockHash = "sharedblockhash"
	conf.resps[hex1] = map[string]interface{}{
		"confirmations": float64(2),
		"blockhash":     blockHash,
	}
	conf.resps[hex2] = map[string]interface{}{
		"confirmations": float64(1),
		"blockhash":     blockHash,
	}
	hdr.resps[blockHash] = map[string]interface{}{
		"height": float64(99),
	}

	rdr := NewTxStatusReader(conf, hdr)
	st1, err := rdr.GetTransactionStatus(context.Background(), tx1)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	st2, err := rdr.GetTransactionStatus(context.Background(), tx2)
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if st1.BlockHeight != 99 || st2.BlockHeight != 99 {
		t.Errorf("heights = (%d, %d), want (99, 99)", st1.BlockHeight, st2.BlockHeight)
	}
	if hdr.calls() != 1 {
		t.Errorf("LRU cache failed: getblockheader called %d times; want 1", hdr.calls())
	}
}

// TestTxStatusReader_NilHeaderSource_NoFallback verifies the
// reader gracefully degrades when no BlockHeaderSource is wired:
// height stays at 0 even when blockhash is non-empty.
func TestTxStatusReader_NilHeaderSource_NoFallback(t *testing.T) {
	conf := newFakeConfSource()
	txid, txHex := txidFromHex(t, "55"+repeatHex("00", 31))
	conf.resps[txHex] = map[string]interface{}{
		"confirmations": float64(2),
		"blockhash":     "somehash",
	}

	rdr := NewTxStatusReader(conf, nil)
	st, err := rdr.GetTransactionStatus(context.Background(), txid)
	if err != nil {
		t.Fatalf("GetTransactionStatus: %v", err)
	}
	if st.Confirmations != 2 {
		t.Errorf("Confirmations = %d, want 2", st.Confirmations)
	}
	if st.BlockHeight != 0 {
		t.Errorf("BlockHeight = %d, want 0 (no header source)", st.BlockHeight)
	}
}

// TestTxStatusReader_UnconfirmedTx pins the mempool path: blockhash
// missing means the tx hasn't been mined; reader must NOT call
// getblockheader regardless of whether one is wired.
func TestTxStatusReader_UnconfirmedTx(t *testing.T) {
	conf := newFakeConfSource()
	hdr := newFakeHeaderSource()
	txid, txHex := txidFromHex(t, "66"+repeatHex("00", 31))
	conf.resps[txHex] = map[string]interface{}{
		"confirmations": float64(0),
	}

	rdr := NewTxStatusReader(conf, hdr)
	st, err := rdr.GetTransactionStatus(context.Background(), txid)
	if err != nil {
		t.Fatalf("GetTransactionStatus: %v", err)
	}
	if st.Confirmations != 0 || st.BlockHeight != 0 {
		t.Errorf("unconfirmed tx = (%d, %d), want (0, 0)",
			st.Confirmations, st.BlockHeight)
	}
	if hdr.calls() != 0 {
		t.Errorf("mempool path made %d getblockheader calls; want 0", hdr.calls())
	}
}

// TestTxStatusReader_HeaderError_PartialReturn verifies the reader
// surfaces a wrapped error AND a partial TxStatus (confirmations
// non-zero, height zero) when getblockheader fails. The
// ConfirmationWatcher tolerates height=0 with a non-zero confirmation,
// so the partial result is the right answer.
func TestTxStatusReader_HeaderError_PartialReturn(t *testing.T) {
	conf := newFakeConfSource()
	hdr := newFakeHeaderSource()
	txid, txHex := txidFromHex(t, "77"+repeatHex("00", 31))
	conf.resps[txHex] = map[string]interface{}{
		"confirmations": float64(4),
		"blockhash":     "broken",
	}
	hdr.errs["broken"] = errors.New("rpc oops")

	rdr := NewTxStatusReader(conf, hdr)
	st, err := rdr.GetTransactionStatus(context.Background(), txid)
	if err == nil {
		t.Fatal("expected error from getblockheader, got nil")
	}
	if st.Confirmations != 4 {
		t.Errorf("partial Confirmations = %d, want 4", st.Confirmations)
	}
	if st.BlockHeight != 0 {
		t.Errorf("partial BlockHeight = %d, want 0", st.BlockHeight)
	}
}

// TestTxStatusReader_Cache_EvictsBeyondCapacity asserts the LRU caps at
// blockHeightCacheCapacity. The test uses the unexported cache directly
// so it doesn't need to issue 257 fake RPCs.
func TestTxStatusReader_Cache_EvictsBeyondCapacity(t *testing.T) {
	c := newBlockHeightCache(4)
	for i := 0; i < 6; i++ {
		c.put(makeHashKey(i), uint64(i))
	}
	if got := c.Len(); got != 4 {
		t.Errorf("Len = %d, want 4", got)
	}
	// Keys 0 and 1 should have been evicted (LRU); 2..5 remain.
	if _, ok := c.get(makeHashKey(0)); ok {
		t.Errorf("key 0 should be evicted")
	}
	if _, ok := c.get(makeHashKey(1)); ok {
		t.Errorf("key 1 should be evicted")
	}
	for i := 2; i <= 5; i++ {
		if _, ok := c.get(makeHashKey(i)); !ok {
			t.Errorf("key %d should be present", i)
		}
	}
}

// repeatHex returns s repeated n times. Used for assembling padded
// hex constants without dragging in another import.
func repeatHex(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func makeHashKey(i int) string {
	return "blockhash-" + string(rune('a'+i))
}
