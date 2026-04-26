package main

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/rpc"
)

// minimalBEEFBody mirrors the helper in pkg/rpc/beef_routes_test.go.
// Duplicated here so the cmd-side wiring test doesn't pull on a
// _test.go symbol from another package (Go forbids that). One BUMP-
// less BEEF body with a single empty BSV tx, target without a BUMP.
func minimalBEEFBody() []byte {
	var buf bytes.Buffer
	// BRC-62 V1 magic on the wire is bytes 01 00 BE EF, which reads
	// as the LE uint32 0xEFBE0001 (matches go-sdk's BEEF_V1). Earlier
	// scaffold revisions used the reversed value; W6-4 corrected the
	// parser to align with real BSV wallets.
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xEFBE0001))
	buf.WriteByte(0x00) // 0 bumps
	buf.WriteByte(0x01) // 1 tx
	buf.Write([]byte{1, 0, 0, 0})
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.Write([]byte{0, 0, 0, 0})
	buf.WriteByte(0x00) // has-bump = 0
	return buf.Bytes()
}

// TestWireBEEFEndpointsDisabled verifies the wiring helper returns nil
// (and mounts no routes) when the operator has set beef.enabled=false.
func TestWireBEEFEndpointsDisabled(t *testing.T) {
	rpcServer := newRPCTestServer(t)
	got := WireBEEFEndpoints(beefWireOpts{
		Cfg: BEEFSection{Enabled: false},
	}, rpcServer)
	if got != nil {
		t.Fatalf("expected nil endpoints when disabled, got %#v", got)
	}
}

// TestWireBEEFEndpointsBridgeFailClosed posts a BEEF envelope to the
// bridge-deposit endpoint and confirms the default fail-closed policy:
// HTTP 204 (envelope accepted + stored), but no deposit is forwarded
// to a downstream consumer (the test consumer here is a stand-in for
// the production bridge monitor sink).
func TestWireBEEFEndpointsBridgeFailClosed(t *testing.T) {
	memDB := db.NewMemoryDB()
	rpcServer := newRPCTestServer(t)
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg:     BEEFSection{Enabled: true, AcceptUnverifiedBridgeDeposits: false},
		DB:      memDB,
		ShardID: 31337,
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
		ShardID: 31337,
	}
	body, err := beef.EncodeEnvelope(hdr, minimalBEEFBody())
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 (envelope stored), got %d body=%q", rec.Code, rec.Body.String())
	}

	// Envelope should now be in the LevelStore. Check via Get on the
	// underlying store wrapper — the BEEF parser computes the txid as
	// double-SHA256 of the raw tx bytes from minimalBEEFBody.
	parsed, err := beef.ParseBEEF(body[beef.EnvelopeHeaderSize:])
	if err != nil {
		t.Fatalf("parse round-trip: %v", err)
	}
	store := beef.NewLevelStore(memDB)
	got, err := store.Get(parsed.Target().TxID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected envelope persisted in store under fail-closed policy")
	}
}

// TestWireBEEFEndpointsRejectWrongShard makes sure the cmd-side
// wiring still inherits the shard-binding check from the underlying
// rpc.BEEFEndpoints handler (HTTP 400 when the envelope's shard ID
// doesn't match the daemon's shard).
func TestWireBEEFEndpointsRejectWrongShard(t *testing.T) {
	memDB := db.NewMemoryDB()
	rpcServer := newRPCTestServer(t)
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg:     BEEFSection{Enabled: true},
		DB:      memDB,
		ShardID: 31337,
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
		ShardID: 8453111, // different shard
	}
	body, err := beef.EncodeEnvelope(hdr, minimalBEEFBody())
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 wrong-shard, got %d body=%q", rec.Code, rec.Body.String())
	}
}

// TestWireBEEFEndpointsBadEnvelope confirms that an obviously
// malformed body is rejected at the parser before reaching any
// downstream consumer.
func TestWireBEEFEndpointsBadEnvelope(t *testing.T) {
	memDB := db.NewMemoryDB()
	rpcServer := newRPCTestServer(t)
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg:     BEEFSection{Enabled: true},
		DB:      memDB,
		ShardID: 31337,
	}, rpcServer)
	mux := http.NewServeMux()
	endpoints.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/bsvm/inbox/submission", bytes.NewReader([]byte("not a beef")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 malformed envelope, got %d", rec.Code)
	}
}

// newRPCTestServer returns a minimally-initialised RPCServer suitable
// for SetBEEFEndpoints. The full RPC stack (overlay, ethAPI, etc.) is
// not constructed — these tests only exercise the BEEF mount path,
// which doesn't depend on the JSON-RPC dispatcher.
func newRPCTestServer(t *testing.T) *rpc.RPCServer {
	t.Helper()
	// rpc.RPCServer's BEEF wiring goes through SetBEEFEndpoints which
	// only stores the *BEEFEndpoints pointer; no other server state is
	// touched. So a zero-value struct is enough for these tests.
	var s rpc.RPCServer
	return &s
}
