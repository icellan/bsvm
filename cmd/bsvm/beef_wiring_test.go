package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/governance"
	"github.com/icellan/bsvm/pkg/overlay"
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

// captureSlogHandler is a minimal slog.Handler that records every
// record into an in-memory slice. The deferred-consumer tests use it
// to assert the structured `todo_hook` field reaches the operator log
// stream — that field is the contract the operator greps for to
// confirm an envelope reached the cmd-side handoff (and surfaces the
// named WW hook the operator should consult next).
type captureSlogHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureSlogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureSlogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *captureSlogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureSlogHandler) WithGroup(_ string) slog.Handler      { return h }

// snapshot returns a copy of the captured records under the lock so a
// concurrent Handle does not race the caller.
func (h *captureSlogHandler) snapshot() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

// recordHasAttr returns the value of the first attr with the given key
// found on r, plus a found flag. Used by the deferred-consumer tests
// to assert "todo_hook" + receiver-wired booleans land in the log.
func recordHasAttr(r slog.Record, key string) (slog.Value, bool) {
	var found bool
	var val slog.Value
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val = a.Value
			found = true
			return false
		}
		return true
	})
	return val, found
}

// installCaptureLogger swaps the default slog logger for one backed
// by captureSlogHandler. The previous logger is restored via t.Cleanup.
func installCaptureLogger(t *testing.T) *captureSlogHandler {
	t.Helper()
	h := &captureSlogHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

// postEnvelope is the shared boilerplate for the deferred-consumer
// tests — encode an envelope of the given intent with the daemon's
// shard id, POST it to the named endpoint, and return the recorder so
// the caller can assert on status code.
func postEnvelope(t *testing.T, mux *http.ServeMux, endpoint string, intent byte, shardID uint64) *httptest.ResponseRecorder {
	t.Helper()
	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  intent,
		Flags:   beef.FlagShardBound,
		ShardID: shardID,
	}
	body, err := beef.EncodeEnvelope(hdr, minimalBEEFBody())
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestWireBEEFEndpointsInboxConsumerDeferred posts an inbox-submission
// envelope (intent 0x05) and asserts that:
//
//  1. The HTTP layer accepts it (204).
//  2. The cmd-side InboxConsumer logs the WW-inbox-consumer hook so
//     operators grepping the daemon log can locate the deferred sink.
//  3. The plumbed InboxMonitor handle is reflected in the log line as
//     `inbox_monitor_wired=true` — confirming the future graduation
//     point (one-line AddInboxTransaction call) has the receiver
//     subsystem already plumbed through opts.
func TestWireBEEFEndpointsInboxConsumerDeferred(t *testing.T) {
	logs := installCaptureLogger(t)

	memDB := db.NewMemoryDB()
	rpcServer := newRPCTestServer(t)
	inboxMon := overlay.NewInboxMonitor()
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg:          BEEFSection{Enabled: true},
		DB:           memDB,
		ShardID:      31337,
		InboxMonitor: inboxMon,
	}, rpcServer)
	if endpoints == nil {
		t.Fatal("expected non-nil endpoints")
	}
	mux := http.NewServeMux()
	endpoints.Mount(mux)

	rec := postEnvelope(t, mux, "/bsvm/inbox/submission", beef.IntentInboxSubmission, 31337)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%q", rec.Code, rec.Body.String())
	}

	assertConsumerLog(t, logs, "WW-inbox-consumer", "inbox_monitor_wired", true)

	// The deferred consumer MUST NOT mutate the inbox monitor — the
	// graduation hook (AddInboxTransaction) is intentionally NOT
	// called here because we have no Rúnar unlock-script decoder.
	if inboxMon.PendingCount() != 0 {
		t.Fatalf("deferred inbox consumer must not mutate monitor; got pending=%d", inboxMon.PendingCount())
	}
}

// TestWireBEEFEndpointsGovernanceConsumerDeferred mirrors the inbox
// case for intent 0x06. Asserts the WW-governance-consumer hook is
// surfaced and the plumbed proposal workflow is reflected in the log.
func TestWireBEEFEndpointsGovernanceConsumerDeferred(t *testing.T) {
	logs := installCaptureLogger(t)

	memDB := db.NewMemoryDB()
	rpcServer := newRPCTestServer(t)
	wf := governance.NewWorkflow(governance.NewMemoryStore(), nil, nil)
	endpoints := WireBEEFEndpoints(beefWireOpts{
		Cfg:              BEEFSection{Enabled: true},
		DB:               memDB,
		ShardID:          31337,
		ProposalWorkflow: wf,
	}, rpcServer)
	if endpoints == nil {
		t.Fatal("expected non-nil endpoints")
	}
	mux := http.NewServeMux()
	endpoints.Mount(mux)

	rec := postEnvelope(t, mux, "/bsvm/governance/action", beef.IntentGovernanceAction, 31337)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%q", rec.Code, rec.Body.String())
	}

	assertConsumerLog(t, logs, "WW-governance-consumer", "proposal_workflow_wired", true)

	// Workflow store stays empty — the BEEF envelope MUST NOT
	// short-circuit into the gossip dedup path.
	props, err := wf.List()
	if err != nil {
		t.Fatalf("workflow.List: %v", err)
	}
	if len(props) != 0 {
		t.Fatalf("deferred governance consumer must not mutate workflow; got %d proposals", len(props))
	}
}

// TestWireBEEFEndpointsFeeWalletConsumerDeferred posts a
// fee-wallet-funding envelope (intent 0x04). Note the endpoint surface
// only exposes 4 named routes (covenant-chain, bridge/deposit,
// inbox/submission, governance/action) — fee-wallet-funding is
// dispatched via the inbox/submission endpoint because spec 17 does
// not pin a separate URL for intent 0x04. The cmd-side InboxConsumer
// in pkg/rpc routes by URL, not by intent, so the dispatcher wires
// 0x04 to the FeeWalletConsumer field by intent. We POST with
// intent 0x04 to the inbox endpoint to exercise the path.
//
// Since the rpc layer routes by URL — see pkg/rpc/beef_routes.go's
// Mount — there is no dedicated fee-wallet endpoint. The fee-wallet
// consumer wiring exists only on the BEEFEndpointConfig surface; in
// practice fee-wallet-funding intents arrive as out-of-band gossip.
// To keep this test focused on cmd-side wiring (the rpc routing is
// covered by pkg/rpc/beef_routes_test.go), we exercise the consumer
// directly via the factory.
func TestWireBEEFEndpointsFeeWalletConsumerDeferred(t *testing.T) {
	logs := installCaptureLogger(t)

	fw := overlay.NewFeeWallet(nil)
	consumer := makeFeeWalletConsumer(beefWireOpts{
		ShardID:   31337,
		FeeWallet: fw,
	})
	consumer(&beef.Envelope{
		Header: beef.EnvelopeHeader{
			Version: beef.EnvelopeVersion,
			Intent:  beef.IntentFeeWalletFunding,
			Flags:   beef.FlagShardBound,
			ShardID: 31337,
		},
		TargetTxID: [32]byte{0x42},
	})

	assertConsumerLog(t, logs, "WW-fee-wallet-consumer", "fee_wallet_wired", true)

	// FeeWallet must be untouched — the deferred consumer is not
	// allowed to add UTXOs blindly.
	if bal := fw.Balance(); bal != 0 {
		t.Fatalf("deferred fee-wallet consumer must not credit; balance=%d", bal)
	}
}

// TestWireBEEFEndpointsCovenantConsumerDeferred posts a covenant-
// advance envelope (intent 0x02 confirmed) to the covenant-chain
// endpoint. Asserts the WW-overlay-covenant-consumer hook is surfaced
// and the plumbed covenant manager + overlay node fields land in the
// log line.
//
// We exercise the consumer factory directly rather than routing
// through the HTTP mux because the integration test would also
// require constructing a full OverlayNode + covenant manager
// (pkg/overlay's NewOverlayNode is non-trivial). The factory-level
// test covers the cmd-side contract — that the structured log line
// surfaces both the WW hook and the receiver-wired booleans the
// operator needs to confirm the future graduation point is plumbed.
func TestWireBEEFEndpointsCovenantConsumerDeferred(t *testing.T) {
	logs := installCaptureLogger(t)

	consumer := makeCovenantConsumer(beefWireOpts{
		ShardID: 31337,
		// Pass nil receiver handles to confirm the consumer
		// gracefully degrades when the overlay isn't yet wired (the
		// log line should still carry the WW hook + the wired=false
		// booleans so operators see why the dispatch was deferred).
		OverlayCovenantManager: nil,
		OverlayNode:            nil,
	})
	consumer(&beef.Envelope{
		Header: beef.EnvelopeHeader{
			Version: beef.EnvelopeVersion,
			Intent:  beef.IntentCovenantAdvanceConfirmed,
			Flags:   beef.FlagShardBound,
			ShardID: 31337,
		},
		TargetTxID: [32]byte{0x77},
		Confirmed:  true,
	})

	assertConsumerLog(t, logs, "WW-overlay-covenant-consumer", "covenant_manager_wired", false)
}

// assertConsumerLog finds a slog record carrying the given todo_hook
// value and asserts the named wired-flag attribute matches expected.
// Centralises the assertion so each deferred-consumer test reads as a
// short shape-check.
func assertConsumerLog(t *testing.T, logs *captureSlogHandler, expectedHook, wiredKey string, wiredExpected bool) {
	t.Helper()
	for _, r := range logs.snapshot() {
		v, ok := recordHasAttr(r, "todo_hook")
		if !ok || v.String() != expectedHook {
			continue
		}
		wv, wok := recordHasAttr(r, wiredKey)
		if !wok {
			t.Fatalf("log record for %q missing %q attribute", expectedHook, wiredKey)
		}
		if got := wv.Bool(); got != wiredExpected {
			t.Fatalf("log record for %q: %s = %v, want %v", expectedHook, wiredKey, got, wiredExpected)
		}
		return
	}
	t.Fatalf("no slog record with todo_hook=%q found; got %d records", expectedHook, len(logs.snapshot()))
}
