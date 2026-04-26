package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/types"
)

// fakeRPC implements bridgeRPCClient. It serves canned getblock
// responses keyed by the (big-endian) block-hash hex the caller
// supplies; unknown calls return an error so test-bugs surface
// loudly.
type fakeRPC struct {
	mu      sync.Mutex
	blocks  map[string]json.RawMessage // key = block-hash hex (big-endian, the form bitcoind expects)
	calls   []string
	failure error
}

func (f *fakeRPC) Call(method string, params ...interface{}) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return nil, f.failure
	}
	if method != "getblock" {
		return nil, fmt.Errorf("fakeRPC: unexpected method %q", method)
	}
	if len(params) == 0 {
		return nil, errors.New("fakeRPC: getblock missing block-hash param")
	}
	hash, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("fakeRPC: getblock first param must be string, got %T", params[0])
	}
	f.calls = append(f.calls, hash)
	body, ok := f.blocks[hash]
	if !ok {
		return nil, fmt.Errorf("fakeRPC: no canned block for hash %s", hash)
	}
	return body, nil
}

// makeVerboseBlock builds a minimal `getblock <hash> 2` JSON payload
// containing one tx that pays satoshis to bridgeScript and carries an
// OP_RETURN with the deposit payload for shardID + l2Addr.
func makeVerboseBlock(txidHex string, bridgeScript []byte, shardID uint32, l2Addr types.Address, satoshis uint64) json.RawMessage {
	payload := make([]byte, 0, 29)
	payload = append(payload, bridge.DepositMagic...)
	payload = append(payload, bridge.DepositMsgType)
	payload = append(payload,
		byte(shardID>>24), byte(shardID>>16), byte(shardID>>8), byte(shardID),
	)
	payload = append(payload, l2Addr[:]...)

	opReturn := make([]byte, 0, 2+len(payload))
	opReturn = append(opReturn, 0x6a, byte(len(payload)))
	opReturn = append(opReturn, payload...)

	// Each verbose-vout `value` is in BSV. Use float math that
	// round-trips exactly to satoshis: value = satoshis / 1e8.
	bsvValue := float64(satoshis) / 1e8

	body := map[string]interface{}{
		"tx": []map[string]interface{}{
			{
				"txid": txidHex,
				"vout": []map[string]interface{}{
					{
						"value": bsvValue,
						"scriptPubKey": map[string]interface{}{
							"hex": hex.EncodeToString(bridgeScript),
						},
					},
					{
						"value": 0.0,
						"scriptPubKey": map[string]interface{}{
							"hex": hex.EncodeToString(opReturn),
						},
					},
				},
			},
		},
	}
	raw, _ := json.Marshal(body)
	return raw
}

// makeHeader builds a chaintracks BlockHeader for a synthetic chain.
// The hash is derived from height + tag so each test gets distinct
// hashes without colliding with any real BSV block.
func makeHeader(height uint64, tag byte, prev [32]byte) *chaintracks.BlockHeader {
	var h [32]byte
	h[0] = tag
	h[31] = byte(height & 0xff)
	return &chaintracks.BlockHeader{
		Height:   height,
		Hash:     h,
		PrevHash: prev,
	}
}

// recordingMonitor implements bridgeNotifier and records every
// RetractDepositsAbove call so reorg tests can assert the height the
// adapter retracted at.
type recordingMonitor struct {
	mu       sync.Mutex
	retracts []uint64
}

func (r *recordingMonitor) RetractDepositsAbove(min uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retracts = append(r.retracts, min)
}

func (r *recordingMonitor) snapshot() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uint64, len(r.retracts))
	copy(out, r.retracts)
	return out
}

// TestBridgeBSVClient_GetBlockTransactionsParsesDeposit drives a
// canned getblock response through GetBlockTransactions and confirms
// the resulting BSVTransaction shape is what bridge.ParseDeposit
// expects.
func TestBridgeBSVClient_GetBlockTransactionsParsesDeposit(t *testing.T) {
	bridgeScript := []byte{0x76, 0xa9, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0x88, 0xac}
	const shardID uint32 = 31337
	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")

	// Big-endian tx hash hex (the form bitcoind / WoC speak on the
	// wire). The internal types.Hash is little-endian, so the adapter
	// must reverse on decode.
	const txidBE = "1122334455667788990011223344556677889900112233445566778899001122"
	body := makeVerboseBlock(txidBE, bridgeScript, shardID, l2Addr, 50_000)

	cht := chaintracks.NewInMemoryClient()
	prev := [32]byte{}
	hdr := makeHeader(100, 0xaa, prev)
	cht.PutHeader(hdr)

	// The adapter passes `getblock` the BSV-canonical big-endian hex
	// of the block hash. Build the key the fakeRPC will see.
	blockHashBE := hex.EncodeToString(reverseBytes(hdr.Hash[:]))

	rpc := &fakeRPC{blocks: map[string]json.RawMessage{
		blockHashBE: body,
	}}

	adapter, err := newBridgeBSVClient(cht, nil, rpc, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}

	txs, err := adapter.GetBlockTransactions(100)
	if err != nil {
		t.Fatalf("GetBlockTransactions: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(txs))
	}
	tx := txs[0]
	if tx.BlockHeight != 100 {
		t.Errorf("BlockHeight = %d, want 100", tx.BlockHeight)
	}
	if tx.TxIndex != 0 {
		t.Errorf("TxIndex = %d, want 0", tx.TxIndex)
	}
	if len(tx.Outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(tx.Outputs))
	}
	if tx.Outputs[0].Value != 50_000 {
		t.Errorf("output[0] value = %d, want 50000", tx.Outputs[0].Value)
	}

	// ParseDeposit should now extract the deposit cleanly.
	dep := bridge.ParseDeposit(tx, bridgeScript, shardID)
	if dep == nil {
		t.Fatal("ParseDeposit returned nil — adapter did not produce a parseable BSVTransaction")
	}
	if dep.SatoshiAmount != 50_000 {
		t.Errorf("SatoshiAmount = %d, want 50000", dep.SatoshiAmount)
	}
	if dep.L2Address != l2Addr {
		t.Errorf("L2Address = %s, want %s", dep.L2Address.Hex(), l2Addr.Hex())
	}

	// Round-trip the txid: types.Hash is little-endian, so the BE hex
	// reverses to dep.BSVTxID.
	wantInternal, _ := hex.DecodeString(txidBE)
	for i := 0; i < 32; i++ {
		if dep.BSVTxID[i] != wantInternal[31-i] {
			t.Fatalf("BSVTxID byte %d = 0x%02x, want 0x%02x", i, dep.BSVTxID[i], wantInternal[31-i])
		}
	}
}

// TestBridgeBSVClient_GetBlockTransactions_NoRPC asserts the adapter
// returns ErrBlockFetchUnsupported when no RPC client is configured —
// the chaintracks-only deployment path.
func TestBridgeBSVClient_GetBlockTransactions_NoRPC(t *testing.T) {
	cht := chaintracks.NewInMemoryClient()
	adapter, err := newBridgeBSVClient(cht, nil, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}
	if _, err := adapter.GetBlockTransactions(1); !errors.Is(err, ErrBlockFetchUnsupported) {
		t.Fatalf("expected ErrBlockFetchUnsupported, got %v", err)
	}
}

// TestBridgeBSVClient_SubscribeNewBlocks_ForwardExtension asserts a
// single new-tip event projects to the new tip's height and pushes
// onto the channel; reorg notifier is NOT invoked.
func TestBridgeBSVClient_SubscribeNewBlocks_ForwardExtension(t *testing.T) {
	cht := chaintracks.NewInMemoryClient()
	mon := &recordingMonitor{}
	adapter, err := newBridgeBSVClient(cht, nil, nil, mon, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := adapter.SubscribeNewBlocks(ctx)
	if err != nil {
		t.Fatalf("SubscribeNewBlocks: %v", err)
	}

	// Seed two headers — chaintracks needs the new-tip header in its
	// view so HeaderByHash succeeds.
	prev := [32]byte{}
	parent := makeHeader(99, 0xaa, prev)
	cht.PutHeader(parent)
	next := makeHeader(100, 0xaa, parent.Hash)
	cht.PutHeader(next)

	// Forward extension: CommonAncestor == OldTip == parent.Hash.
	cht.EmitReorg(&chaintracks.ReorgEvent{
		CommonAncestor: parent.Hash,
		OldTip:         parent.Hash,
		NewTip:         next.Hash,
		NewChainLen:    1,
	})

	select {
	case h := <-ch:
		if h != 100 {
			t.Fatalf("got height %d, want 100", h)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for height")
	}
	if got := mon.snapshot(); len(got) != 0 {
		t.Fatalf("forward extension must not retract; got %v", got)
	}
}

// TestBridgeBSVClient_SubscribeNewBlocks_Reorg drives a reorg event
// through the adapter and asserts (a) RetractDepositsAbove is called
// with the common-ancestor height, and (b) the new tip's height is
// pushed onto the channel afterwards.
func TestBridgeBSVClient_SubscribeNewBlocks_Reorg(t *testing.T) {
	cht := chaintracks.NewInMemoryClient()
	mon := &recordingMonitor{}
	adapter, err := newBridgeBSVClient(cht, nil, nil, mon, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := adapter.SubscribeNewBlocks(ctx)
	if err != nil {
		t.Fatalf("SubscribeNewBlocks: %v", err)
	}

	// Topology: ancestor at h=10, old-tip at h=11, new-tip at h=12 on
	// a different fork. Reorg height = 10 (anything above must drop).
	zero := [32]byte{}
	ancestor := makeHeader(10, 0xab, zero)
	cht.PutHeader(ancestor)
	oldTip := makeHeader(11, 0xa1, ancestor.Hash)
	cht.PutHeader(oldTip)
	// New chain: height 11 + 12 on the OTHER fork. We only need the
	// new tip in chaintracks for HeaderByHash to resolve.
	newMid := makeHeader(11, 0xb1, ancestor.Hash)
	cht.PutHeader(newMid)
	newTip := makeHeader(12, 0xb2, newMid.Hash)
	cht.PutHeader(newTip)

	cht.EmitReorg(&chaintracks.ReorgEvent{
		CommonAncestor: ancestor.Hash,
		OldTip:         oldTip.Hash,
		NewTip:         newTip.Hash,
		NewChainLen:    2,
	})

	select {
	case h := <-ch:
		if h != 12 {
			t.Fatalf("got height %d, want 12", h)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for new-tip height after reorg")
	}

	got := mon.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected exactly one RetractDepositsAbove call, got %v", got)
	}
	if got[0] != 10 {
		t.Fatalf("retracted at height %d, want 10 (the common-ancestor height)", got[0])
	}
}

// TestBridgeBlockScanner_ProcessesDepositOnNewTip wires the full
// scanner against a real BridgeMonitor + a fake chaintracks/RPC pair.
// On the synthetic new tip, the scanner must fetch the block, parse
// the deposit, and persist it through PersistDeposit.
func TestBridgeBlockScanner_ProcessesDepositOnNewTip(t *testing.T) {
	bridgeScript := []byte{0x51, 0x52, 0x53, 0x54}
	const shardID uint32 = 7
	l2Addr := types.HexToAddress("0x2222222222222222222222222222222222222222")

	cfg := bridge.DefaultConfig()
	cfg.MinDepositSatoshis = 1
	cfg.BSVConfirmations = 1
	store := db.NewMemoryDB()
	monitor := bridge.NewBridgeMonitor(cfg, nil, nil, store)
	monitor.SetBridgeScriptHash(bridgeScript)
	monitor.SetLocalShardID(shardID)

	cht := chaintracks.NewInMemoryClient()
	prev := [32]byte{}
	parent := makeHeader(50, 0xaa, prev)
	cht.PutHeader(parent)
	tip := makeHeader(51, 0xaa, parent.Hash)
	cht.PutHeader(tip)

	const txidBE = "deadbeefcafef00d0011223344556677889900112233445566778899aabbccdd"
	body := makeVerboseBlock(txidBE, bridgeScript, shardID, l2Addr, 25_000)
	tipHashBE := hex.EncodeToString(reverseBytes(tip.Hash[:]))
	rpc := &fakeRPC{blocks: map[string]json.RawMessage{tipHashBE: body}}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	closer, err := startBridgeBlockScanner(ctx, monitor, cht, nil, rpc, slog.Default())
	if err != nil {
		t.Fatalf("startBridgeBlockScanner: %v", err)
	}
	if closer == nil {
		t.Fatal("expected non-nil closer")
	}
	defer func() { _ = closer() }()

	// Emit the new-tip event.
	cht.EmitReorg(&chaintracks.ReorgEvent{
		CommonAncestor: parent.Hash,
		OldTip:         parent.Hash,
		NewTip:         tip.Hash,
		NewChainLen:    1,
	})

	// Wait for ProcessBlock to land. PendingCount transitions from 0
	// to 1 once the deposit is persisted.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if monitor.PendingCount() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := monitor.PendingCount(); got != 1 {
		t.Fatalf("expected 1 pending deposit, got %d", got)
	}
}

// TestBridgeBSVClient_GetBlockHeight reads through chaintracks Tip().
func TestBridgeBSVClient_GetBlockHeight(t *testing.T) {
	cht := chaintracks.NewInMemoryClient()
	cht.PutHeader(makeHeader(42, 0xee, [32]byte{}))
	adapter, err := newBridgeBSVClient(cht, nil, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("newBridgeBSVClient: %v", err)
	}
	h, err := adapter.GetBlockHeight()
	if err != nil {
		t.Fatalf("GetBlockHeight: %v", err)
	}
	if h != 42 {
		t.Errorf("GetBlockHeight = %d, want 42", h)
	}
}

// TestBridgeBSVClient_RequiresChaintracks asserts the constructor
// rejects a nil chaintracks (the only required dependency).
func TestBridgeBSVClient_RequiresChaintracks(t *testing.T) {
	if _, err := newBridgeBSVClient(nil, nil, nil, nil, nil); err == nil {
		t.Fatal("expected error when chaintracks is nil")
	}
}

// TestStartBridgeBlockScanner_NilMonitorIsNoOp asserts the wiring
// helper degrades gracefully when no bridge is configured.
func TestStartBridgeBlockScanner_NilMonitorIsNoOp(t *testing.T) {
	closer, err := startBridgeBlockScanner(context.Background(), nil, chaintracks.NewInMemoryClient(), nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("startBridgeBlockScanner: %v", err)
	}
	if closer != nil {
		t.Fatal("expected nil closer when monitor is nil")
	}
}

// TestStartBridgeBlockScanner_NilChaintracksIsNoOp asserts the wiring
// helper degrades gracefully when the SPV anchor is missing.
func TestStartBridgeBlockScanner_NilChaintracksIsNoOp(t *testing.T) {
	cfg := bridge.DefaultConfig()
	mon := bridge.NewBridgeMonitor(cfg, nil, nil, db.NewMemoryDB())
	closer, err := startBridgeBlockScanner(context.Background(), mon, nil, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("startBridgeBlockScanner: %v", err)
	}
	if closer != nil {
		t.Fatal("expected nil closer when chaintracks is nil")
	}
}
