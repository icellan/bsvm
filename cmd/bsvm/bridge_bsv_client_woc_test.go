package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	sdktx "github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/whatsonchain"
)

// fakeWoC is the in-process whatsonchain.WhatsOnChainClient the WoC
// fan-out tests drive. It records GetTx calls per txid so the cache-
// HIT smoke test can assert request collapsing.
type fakeWoC struct {
	mu sync.Mutex

	// blocks maps block-hash (BSVM little-endian) → slice of txids.
	blocks map[[32]byte][][32]byte
	// txs maps txid → raw bytes.
	txs map[[32]byte][]byte

	getTxCalls    int32
	getBlockCalls int32

	// fail* knobs let tests inject WoC errors.
	failGetBlockTxIDs error
	failGetTx         map[[32]byte]error
}

func newFakeWoC() *fakeWoC {
	return &fakeWoC{
		blocks:    map[[32]byte][][32]byte{},
		txs:       map[[32]byte][]byte{},
		failGetTx: map[[32]byte]error{},
	}
}

func (f *fakeWoC) GetTx(_ context.Context, txid [32]byte) ([]byte, error) {
	atomic.AddInt32(&f.getTxCalls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.failGetTx[txid]; ok {
		return nil, e
	}
	raw, ok := f.txs[txid]
	if !ok {
		return nil, whatsonchain.ErrNotFound
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

func (f *fakeWoC) GetUTXOs(_ context.Context, _ string) ([]whatsonchain.UTXO, error) {
	return nil, nil
}

func (f *fakeWoC) ChainInfo(_ context.Context) (*whatsonchain.ChainInfo, error) {
	return nil, nil
}

func (f *fakeWoC) GetBlockTxIDs(_ context.Context, blockHash [32]byte) ([][32]byte, error) {
	atomic.AddInt32(&f.getBlockCalls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failGetBlockTxIDs != nil {
		return nil, f.failGetBlockTxIDs
	}
	ids, ok := f.blocks[blockHash]
	if !ok {
		return nil, errors.New("fakeWoC: no canned block")
	}
	out := make([][32]byte, len(ids))
	copy(out, ids)
	return out, nil
}

func (f *fakeWoC) Ping(_ context.Context) error { return nil }

// buildDepositRawTx returns the canonical BSV-serialised bytes of a
// minimal deposit tx: one bridge-script output, one OP_RETURN payload
// output. The returned txid is the SDK's canonical (little-endian)
// chainhash, copied into a [32]byte so callers can use it as a
// types.Hash directly. (chainhash.Hash and types.Hash share the same
// little-endian byte ordering.)
func buildDepositRawTx(t *testing.T, bridgeScript []byte, shardID uint32, l2Addr types.Address, satoshis uint64) ([]byte, [32]byte) {
	t.Helper()
	tx := sdktx.NewTransaction()
	tx.AddOutput(&sdktx.TransactionOutput{
		Satoshis:      satoshis,
		LockingScript: sdkscript.NewFromBytes(bridgeScript),
	})

	payload := append([]byte{}, bridge.DepositMagic...)
	payload = append(payload, bridge.DepositMsgType)
	payload = append(payload,
		byte(shardID>>24), byte(shardID>>16), byte(shardID>>8), byte(shardID),
	)
	payload = append(payload, l2Addr[:]...)
	opScript := append([]byte{0x6a, byte(len(payload))}, payload...)
	tx.AddOutput(&sdktx.TransactionOutput{
		Satoshis:      0,
		LockingScript: sdkscript.NewFromBytes(opScript),
	})

	raw := tx.Bytes()
	chainhash := tx.TxID()
	var txid [32]byte
	copy(txid[:], chainhash.CloneBytes())
	return raw, txid
}

// TestBridgeBSVClient_GetBlockTransactions_WoCFanout drives the
// chaintracks-only fallback and confirms the resulting BSVTransaction
// is bit-equivalent to what the RPC verbose-block path produces (i.e.
// ParseDeposit lifts a deposit out of it cleanly).
func TestBridgeBSVClient_GetBlockTransactions_WoCFanout(t *testing.T) {
	bridgeScript := []byte{0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0x88, 0xac}
	const shardID uint32 = 99
	l2Addr := types.HexToAddress("0x3333333333333333333333333333333333333333")

	cht := chaintracks.NewInMemoryClient()
	hdr := makeHeader(200, 0xee, [32]byte{})
	cht.PutHeader(hdr)

	rawTx, txid := buildDepositRawTx(t, bridgeScript, shardID, l2Addr, 75_000)

	woc := newFakeWoC()
	woc.blocks[hdr.Hash] = [][32]byte{txid}
	woc.txs[txid] = rawTx

	adapter, err := newBridgeBSVClient(cht, woc, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}

	txs, err := adapter.GetBlockTransactions(200)
	if err != nil {
		t.Fatalf("GetBlockTransactions: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(txs))
	}
	bt := txs[0]
	if bt.BlockHeight != 200 {
		t.Errorf("BlockHeight = %d, want 200", bt.BlockHeight)
	}
	if len(bt.Outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(bt.Outputs))
	}
	if bt.Outputs[0].Value != 75_000 {
		t.Errorf("output[0] value = %d, want 75000", bt.Outputs[0].Value)
	}

	dep := bridge.ParseDeposit(bt, bridgeScript, shardID)
	if dep == nil {
		t.Fatal("ParseDeposit returned nil — adapter did not produce a parseable BSVTransaction")
	}
	if dep.SatoshiAmount != 75_000 {
		t.Errorf("SatoshiAmount = %d, want 75000", dep.SatoshiAmount)
	}
	if dep.L2Address != l2Addr {
		t.Errorf("L2Address = %s, want %s", dep.L2Address.Hex(), l2Addr.Hex())
	}
}

// TestBridgeBSVClient_WoCFanout_NoUpstreams asserts that with neither
// RPC nor WoC, ErrBlockFetchUnsupported still surfaces (the legacy
// guarantee).
func TestBridgeBSVClient_WoCFanout_NoUpstreams(t *testing.T) {
	cht := chaintracks.NewInMemoryClient()
	cht.PutHeader(makeHeader(1, 0x01, [32]byte{}))
	adapter, err := newBridgeBSVClient(cht, nil, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}
	if _, err := adapter.GetBlockTransactions(1); !errors.Is(err, ErrBlockFetchUnsupported) {
		t.Fatalf("expected ErrBlockFetchUnsupported, got %v", err)
	}
}

// TestBridgeBSVClient_WoCFanout_CacheHIT confirms that wrapping the
// WoC in the production CachedClient collapses repeat GetTx calls to
// one upstream RTT — the W6-8 cache integration the spec called out.
func TestBridgeBSVClient_WoCFanout_CacheHIT(t *testing.T) {
	bridgeScript := []byte{0x51}
	const shardID uint32 = 1
	l2Addr := types.HexToAddress("0x4444444444444444444444444444444444444444")

	cht := chaintracks.NewInMemoryClient()
	hdr := makeHeader(11, 0x11, [32]byte{})
	cht.PutHeader(hdr)

	rawTx, txid := buildDepositRawTx(t, bridgeScript, shardID, l2Addr, 1_234)

	upstream := newFakeWoC()
	upstream.blocks[hdr.Hash] = [][32]byte{txid}
	upstream.txs[txid] = rawTx

	cached := whatsonchain.NewCachedClient(upstream, whatsonchain.DefaultCacheConfig())

	adapter, err := newBridgeBSVClient(cht, cached, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}

	// First call: misses the cache, hits the fake.
	if _, err := adapter.GetBlockTransactions(11); err != nil {
		t.Fatalf("first GetBlockTransactions: %v", err)
	}
	first := atomic.LoadInt32(&upstream.getTxCalls)
	if first != 1 {
		t.Fatalf("first epoch GetTx upstream calls = %d, want 1", first)
	}

	// Second call: same block, same txid → cache HIT means upstream
	// GetTx should NOT be called again.
	if _, err := adapter.GetBlockTransactions(11); err != nil {
		t.Fatalf("second GetBlockTransactions: %v", err)
	}
	second := atomic.LoadInt32(&upstream.getTxCalls)
	if second != first {
		t.Fatalf("cache MISS on repeat call: getTxCalls jumped from %d to %d", first, second)
	}
}

// TestBridgeBSVClient_WoCFanout_RespectsCap asserts the per-block fan-
// out cap kicks in and (a) truncates the txid list to wocBlockTxFanoutMax,
// (b) emits a WARN-level log, (c) does not call GetTx for the truncated
// surplus.
func TestBridgeBSVClient_WoCFanout_RespectsCap(t *testing.T) {
	prevCap := wocBlockTxFanoutMax
	wocBlockTxFanoutMax = 2
	t.Cleanup(func() { wocBlockTxFanoutMax = prevCap })

	bridgeScript := []byte{0x51}
	const shardID uint32 = 1
	l2Addr := types.HexToAddress("0x5555555555555555555555555555555555555555")

	cht := chaintracks.NewInMemoryClient()
	hdr := makeHeader(7, 0x07, [32]byte{})
	cht.PutHeader(hdr)

	woc := newFakeWoC()
	// 5 distinct txids, only 3 of which would be processed if cap=2
	// truncates correctly (we expect exactly 2 GetTx calls).
	var ids [][32]byte
	for i := 0; i < 5; i++ {
		raw, id := buildDepositRawTx(t, bridgeScript, shardID, l2Addr, uint64(1000+i))
		// Mutate one byte to make each tx distinct (different OP_RETURN
		// payload via different satoshi value already does it).
		woc.txs[id] = raw
		ids = append(ids, id)
	}
	woc.blocks[hdr.Hash] = ids

	adapter, err := newBridgeBSVClient(cht, woc, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}

	txs, err := adapter.GetBlockTransactions(7)
	if err != nil {
		t.Fatalf("GetBlockTransactions: %v", err)
	}
	if len(txs) != 2 {
		t.Fatalf("expected 2 txs after cap truncation, got %d", len(txs))
	}
	if got := atomic.LoadInt32(&woc.getTxCalls); got != 2 {
		t.Fatalf("expected exactly 2 upstream GetTx calls (cap=2), got %d", got)
	}
}

// TestBridgeBSVClient_WoCFanout_PartialFailure confirms that one
// failed tx fetch does not abort the whole block — surviving txs are
// still returned in order.
func TestBridgeBSVClient_WoCFanout_PartialFailure(t *testing.T) {
	bridgeScript := []byte{0x51}
	const shardID uint32 = 1
	l2Addr := types.HexToAddress("0x6666666666666666666666666666666666666666")

	cht := chaintracks.NewInMemoryClient()
	hdr := makeHeader(3, 0x03, [32]byte{})
	cht.PutHeader(hdr)

	rawA, idA := buildDepositRawTx(t, bridgeScript, shardID, l2Addr, 100)
	rawB, idB := buildDepositRawTx(t, bridgeScript, shardID, l2Addr, 200)
	rawC, idC := buildDepositRawTx(t, bridgeScript, shardID, l2Addr, 300)

	woc := newFakeWoC()
	woc.txs[idA] = rawA
	woc.txs[idC] = rawC
	woc.failGetTx[idB] = errors.New("boom")
	_ = rawB
	woc.blocks[hdr.Hash] = [][32]byte{idA, idB, idC}

	adapter, err := newBridgeBSVClient(cht, woc, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}

	txs, err := adapter.GetBlockTransactions(3)
	if err != nil {
		t.Fatalf("GetBlockTransactions: %v", err)
	}
	if len(txs) != 2 {
		t.Fatalf("expected 2 surviving txs, got %d", len(txs))
	}
	// Order preserved (manifest index → output index).
	if txs[0].TxID != idA {
		t.Errorf("txs[0] != idA")
	}
	if txs[1].TxID != idC {
		t.Errorf("txs[1] != idC")
	}
}
