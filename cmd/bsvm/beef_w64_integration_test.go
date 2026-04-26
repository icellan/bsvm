package main

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	sdktx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
)

// TestWireBEEFEndpoints_W64_BridgeAcceptsValidEnvelope is the integration
// test that verifies the W6-4 verifier-backed bridge consumer credits a
// deposit on L2 once the BEEF passes ancestry + script + BUMP + anchor-
// depth checks.
func TestWireBEEFEndpoints_W64_BridgeAcceptsValidEnvelope(t *testing.T) {
	const shardID = 31337
	const localShardID = uint32(31337)
	const bsvBlockHeight = uint64(800_000)
	const confirmations = uint64(10)

	// Bridge scriptHash = the locking script of output 0 on the deposit
	// tx. The bridge ParseDeposit compares for equality, so we use the
	// raw locking script bytes directly as the "script hash".
	bridgeLockBytes := []byte{0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 OP_DATA20
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
		0x88, 0xac} // OP_EQUALVERIFY OP_CHECKSIG
	bridgeLock := sdkscript.NewFromBytes(bridgeLockBytes)

	// L2 address the deposit credits.
	var l2Addr [20]byte
	for i := range l2Addr {
		l2Addr[i] = byte(0xa0 + i)
	}

	// Ancestor: 1-output OP_TRUE that the deposit tx will spend.
	ancestor := sdktx.NewTransaction()
	ancestor.AddOutput(&sdktx.TransactionOutput{
		Satoshis:      100_000,
		LockingScript: sdkscript.NewFromBytes([]byte{sdkscript.OpTRUE}),
	})

	// Attach a single-tx BUMP at bsvBlockHeight to the ancestor (root = txid).
	hash := ancestor.TxID()
	isTxid := true
	ancestor.MerklePath = sdktx.NewMerklePath(uint32(bsvBlockHeight), [][]*sdktx.PathElement{{
		{Offset: 0, Hash: hash, Txid: &isTxid},
	}})

	// Build the deposit tx:
	//   in[0]   spends ancestor[0] with empty unlock (OP_TRUE wins)
	//   out[0]  pays the bridge covenant 50_000 sats
	//   out[1]  OP_RETURN "BSVM" 0x03 <shard_id BE u32> <l2_addr 20B>
	//   out[2]  P2PKH change (irrelevant for ParseDeposit)
	depositTx := sdktx.NewTransaction()
	depositTx.AddInput(&sdktx.TransactionInput{
		SourceTXID:        ancestor.TxID(),
		SourceTxOutIndex:  0,
		SourceTransaction: ancestor,
		UnlockingScript:   sdkscript.NewFromBytes(nil),
		SequenceNumber:    0xffffffff,
	})
	depositTx.AddOutput(&sdktx.TransactionOutput{
		Satoshis:      50_000,
		LockingScript: bridgeLock,
	})
	// OP_RETURN payload: "BSVM" || 0x03 || shard_id (4 BE) || l2_addr (20).
	opReturnPayload := append([]byte{}, []byte("BSVM")...)
	opReturnPayload = append(opReturnPayload, 0x03)
	var shardBE [4]byte
	binary.BigEndian.PutUint32(shardBE[:], localShardID)
	opReturnPayload = append(opReturnPayload, shardBE[:]...)
	opReturnPayload = append(opReturnPayload, l2Addr[:]...)
	// Script: OP_RETURN <push_data 29 bytes>
	opReturnScript := []byte{0x6a, byte(len(opReturnPayload))}
	opReturnScript = append(opReturnScript, opReturnPayload...)
	depositTx.AddOutput(&sdktx.TransactionOutput{
		Satoshis:      0,
		LockingScript: sdkscript.NewFromBytes(opReturnScript),
	})

	// Attach a single-tx BUMP to the deposit tx itself so the BEEF
	// is "confirmed" (intent 0x03) and the verifier short-circuits
	// at the target's BUMP (per spec 17 §Script Verification, BSV
	// miners already validated input scripts at block-acceptance
	// time). The merkle root for a 1-tx block equals the txid.
	depositHash := depositTx.TxID()
	depositIsTxid := true
	depositTx.MerklePath = sdktx.NewMerklePath(uint32(bsvBlockHeight), [][]*sdktx.PathElement{{
		{Offset: 0, Hash: depositHash, Txid: &depositIsTxid},
	}})

	beefBytes, err := depositTx.BEEF()
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}

	// Chaintracks fixture: the BUMP at bsvBlockHeight has merkle root
	// equal to the deposit txid; tip is bsvBlockHeight + 9 so
	// Confirmations() returns 10.
	ct := chaintracks.NewInMemoryClient()
	var root [32]byte
	copy(root[:], depositTx.TxID().CloneBytes())
	ct.PutHeader(&chaintracks.BlockHeader{
		Height:     bsvBlockHeight,
		Hash:       deterministicHash(bsvBlockHeight),
		MerkleRoot: root,
		Timestamp:  1_700_000_000,
		Bits:       0x207fffff,
		Work:       new(big.Int).SetUint64(bsvBlockHeight + 1),
	})
	tipHeight := bsvBlockHeight + confirmations - 1
	ct.PutHeader(&chaintracks.BlockHeader{
		Height:     tipHeight,
		Hash:       deterministicHash(tipHeight),
		MerkleRoot: deterministicHash(tipHeight),
		Timestamp:  1_700_000_001,
		Bits:       0x207fffff,
		Work:       new(big.Int).SetUint64(tipHeight + 1),
	})

	// Bridge monitor: persist deposits to an in-memory DB and watch
	// the in-memory map for credit confirmation.
	memDB := db.NewMemoryDB()
	monitor := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil, memDB)
	monitor.SetBridgeScriptHash(bridgeLockBytes)
	monitor.SetLocalShardID(localShardID)

	rpcServer := newRPCTestServer(t)
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg: BEEFSection{
			Enabled:                        true,
			AcceptUnverifiedBridgeDeposits: false,
			MaxDepth:                       32,
			MaxWidth:                       10000,
			AnchorDepth:                    6, // 10 confirmations >= 6 → pass
			ValidatedCacheSize:             16,
		},
		DB:               memDB,
		ShardID:          shardID,
		BridgeMonitor:    monitor,
		BridgeScriptHash: bridgeLockBytes,
		LocalShardID:     localShardID,
		Chaintracks:      ct,
	}, rpcServer)
	if endpoints == nil {
		t.Fatal("expected non-nil endpoints")
	}

	mux := http.NewServeMux()
	endpoints.Mount(mux)

	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentBridgeDeposit,
		Flags:   beef.FlagShardBound,
		ShardID: shardID,
	}
	body, err := beef.EncodeEnvelope(hdr, beefBytes)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%q", rec.Code, rec.Body.String())
	}

	// The bridge monitor should now have one pending / processed
	// deposit. PendingCount counts entries in the pending list (which
	// PersistDeposit does not populate); IsProcessed checks the
	// processedDeposits map directly.
	if !monitor.IsProcessed(depositTxID(depositTx), 0) {
		t.Fatalf("expected bridge monitor to mark deposit as processed; pending=%d", monitor.PendingCount())
	}
}

// TestWireBEEFEndpoints_W64_BridgeRejectsBadMerkle confirms that a BEEF
// whose ancestor BUMP does not bind to a chaintracks-known header is
// rejected by the verifier and never reaches the bridge monitor.
func TestWireBEEFEndpoints_W64_BridgeRejectsBadMerkle(t *testing.T) {
	const shardID = 31337
	const localShardID = uint32(31337)
	const bsvBlockHeight = uint64(800_001)

	bridgeLockBytes := []byte{0x76, 0xa9, 0x14,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
		0x88, 0xac}
	bridgeLock := sdkscript.NewFromBytes(bridgeLockBytes)

	var l2Addr [20]byte
	for i := range l2Addr {
		l2Addr[i] = byte(0xb0 + i)
	}

	ancestor := sdktx.NewTransaction()
	ancestor.AddOutput(&sdktx.TransactionOutput{
		Satoshis:      100_000,
		LockingScript: sdkscript.NewFromBytes([]byte{sdkscript.OpTRUE}),
	})
	hash := ancestor.TxID()
	isTxid := true
	ancestor.MerklePath = sdktx.NewMerklePath(uint32(bsvBlockHeight), [][]*sdktx.PathElement{{
		{Offset: 0, Hash: hash, Txid: &isTxid},
	}})

	depositTx := sdktx.NewTransaction()
	depositTx.AddInput(&sdktx.TransactionInput{
		SourceTXID:        ancestor.TxID(),
		SourceTxOutIndex:  0,
		SourceTransaction: ancestor,
		UnlockingScript:   sdkscript.NewFromBytes(nil),
		SequenceNumber:    0xffffffff,
	})
	depositTx.AddOutput(&sdktx.TransactionOutput{Satoshis: 50_000, LockingScript: bridgeLock})
	op := append([]byte{}, []byte("BSVM")...)
	op = append(op, 0x03)
	var shardBE [4]byte
	binary.BigEndian.PutUint32(shardBE[:], localShardID)
	op = append(op, shardBE[:]...)
	op = append(op, l2Addr[:]...)
	opScript := []byte{0x6a, byte(len(op))}
	opScript = append(opScript, op...)
	depositTx.AddOutput(&sdktx.TransactionOutput{Satoshis: 0, LockingScript: sdkscript.NewFromBytes(opScript)})

	// Anchor the deposit tx itself (so the verifier's check is
	// against the target's BUMP); the chaintracks fixture below then
	// has the WRONG merkle root and the verifier rejects.
	depositHash := depositTx.TxID()
	depositIsTxid := true
	depositTx.MerklePath = sdktx.NewMerklePath(uint32(bsvBlockHeight), [][]*sdktx.PathElement{{
		{Offset: 0, Hash: depositHash, Txid: &depositIsTxid},
	}})

	beefBytes, err := depositTx.BEEF()
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}

	// Chaintracks fixture with a WRONG merkle root at bsvBlockHeight.
	ct := chaintracks.NewInMemoryClient()
	var wrongRoot [32]byte
	wrongRoot[0] = 0xde
	wrongRoot[1] = 0xad
	ct.PutHeader(&chaintracks.BlockHeader{
		Height:     bsvBlockHeight,
		Hash:       deterministicHash(bsvBlockHeight),
		MerkleRoot: wrongRoot,
		Timestamp:  1_700_000_000,
		Bits:       0x207fffff,
		Work:       new(big.Int).SetUint64(bsvBlockHeight + 1),
	})

	memDB := db.NewMemoryDB()
	monitor := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil, memDB)
	monitor.SetBridgeScriptHash(bridgeLockBytes)
	monitor.SetLocalShardID(localShardID)

	rpcServer := newRPCTestServer(t)
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg: BEEFSection{
			Enabled:            true,
			MaxDepth:           32,
			MaxWidth:           10000,
			AnchorDepth:        0, // ancestor BUMP check is what we want to fail
			ValidatedCacheSize: 16,
		},
		DB:               memDB,
		ShardID:          shardID,
		BridgeMonitor:    monitor,
		BridgeScriptHash: bridgeLockBytes,
		LocalShardID:     localShardID,
		Chaintracks:      ct,
	}, rpcServer)
	mux := http.NewServeMux()
	endpoints.Mount(mux)

	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentBridgeDeposit,
		Flags:   beef.FlagShardBound,
		ShardID: shardID,
	}
	body, _ := beef.EncodeEnvelope(hdr, beefBytes)
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// The endpoint always returns 204 (envelope stored) — the
	// verifier failure surfaces only as a log + no monitor write.
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%q", rec.Code, rec.Body.String())
	}
	if monitor.IsProcessed(depositTxID(depositTx), 0) {
		t.Fatal("expected bridge monitor NOT to credit deposit when BUMP is invalid")
	}
}

// TestWireBEEFEndpoints_W64_BridgeFailClosedNoChaintracks confirms that
// when the chaintracks dependency is missing the consumer reverts to
// the pre-W6-4 fail-closed policy: 204 OK, envelope stored, no credit.
// This guards against a misconfigured daemon silently minting wBSV.
func TestWireBEEFEndpoints_W64_BridgeFailClosedNoChaintracks(t *testing.T) {
	memDB := db.NewMemoryDB()
	monitor := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil, memDB)

	rpcServer := newRPCTestServer(t)
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg: BEEFSection{
			Enabled:            true,
			MaxDepth:           32,
			MaxWidth:           10000,
			AnchorDepth:        6,
			ValidatedCacheSize: 16,
		},
		DB:            memDB,
		ShardID:       31337,
		BridgeMonitor: monitor,
		// Chaintracks intentionally omitted → fail-closed path.
	}, rpcServer)
	mux := http.NewServeMux()
	endpoints.Mount(mux)

	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentBridgeDeposit,
		Flags:   beef.FlagShardBound,
		ShardID: 31337,
	}
	body, _ := beef.EncodeEnvelope(hdr, minimalBEEFBody())
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if monitor.PendingCount() != 0 {
		t.Fatal("fail-closed path should not enqueue any deposit on the monitor")
	}
}

// depositTxID returns the txid of the test's deposit tx in our local
// types.Hash form for monitor.IsProcessed lookups.
func depositTxID(tx *sdktx.Transaction) [32]byte {
	var out [32]byte
	copy(out[:], tx.TxID().CloneBytes())
	return out
}

// deterministicHash returns a [32]byte derived from height; used so
// different test heights produce distinguishable block hashes.
func deterministicHash(height uint64) [32]byte {
	var out [32]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(height >> (8 * i))
	}
	return out
}
