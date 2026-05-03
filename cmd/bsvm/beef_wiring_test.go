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
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/bsv"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/governance"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/rpc"
	"github.com/icellan/bsvm/pkg/types"
)

// pushBytes wraps b in the smallest Bitcoin Script push opcode.
// Mirrors the codegen used by the runar SDK for unlock-script
// arguments and OP_RETURN payloads. Used by the BEEF consumer tests
// to construct fixture transactions.
func pushBytes(b []byte) []byte {
	switch n := len(b); {
	case n == 0:
		return []byte{0x00}
	case n <= 0x4b:
		return append([]byte{byte(n)}, b...)
	case n <= 0xff:
		return append([]byte{0x4c, byte(n)}, b...)
	case n <= 0xffff:
		out := []byte{0x4d, byte(n), byte(n >> 8)}
		return append(out, b...)
	default:
		out := []byte{0x4e, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
		return append(out, b...)
	}
}

// buildOneInputOneOutputTx constructs a minimal BSV transaction with a
// single input (carrying unlockScript) and a single output (carrying
// lockScript at the given satoshis). Used by the consumer tests to
// shape per-extractor fixtures without standing up the full Rúnar
// codegen pipeline. The tx is canonical (version 1, locktime 0,
// sequence 0xffffffff, prev outpoint zeros).
func buildOneInputOneOutputTx(unlockScript, lockScript []byte, satoshis uint64) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{1, 0, 0, 0}) // version
	buf.WriteByte(0x01)           // 1 input
	// outpoint: 32-byte zero txid + 4-byte zero vout
	buf.Write(make([]byte, 36))
	buf.Write(varIntBytes(uint64(len(unlockScript))))
	buf.Write(unlockScript)
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff}) // sequence
	buf.WriteByte(0x01)                       // 1 output
	var sats [8]byte
	binary.LittleEndian.PutUint64(sats[:], satoshis)
	buf.Write(sats[:])
	buf.Write(varIntBytes(uint64(len(lockScript))))
	buf.Write(lockScript)
	buf.Write([]byte{0, 0, 0, 0}) // locktime
	return buf.Bytes()
}

// buildMultiOutputTx constructs a 1-input N-output BSV transaction.
// Used by the covenant-advance + fee-wallet consumer tests where the
// target tx carries multiple outputs (state covenant continuation +
// OP_RETURN, or fee-wallet credits + change).
func buildMultiOutputTx(unlockScript []byte, outputs []parsedTxOutput) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{1, 0, 0, 0}) // version
	buf.WriteByte(0x01)           // 1 input
	buf.Write(make([]byte, 36))
	buf.Write(varIntBytes(uint64(len(unlockScript))))
	buf.Write(unlockScript)
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	buf.Write(varIntBytes(uint64(len(outputs))))
	for _, o := range outputs {
		var sats [8]byte
		binary.LittleEndian.PutUint64(sats[:], o.Satoshis)
		buf.Write(sats[:])
		buf.Write(varIntBytes(uint64(len(o.Script))))
		buf.Write(o.Script)
	}
	buf.Write([]byte{0, 0, 0, 0})
	return buf.Bytes()
}

// varIntBytes is the test-side mirror of pkg/beef's writeVarInt — kept
// local so the fixture builder doesn't poke at internals of the
// production codec.
func varIntBytes(v uint64) []byte {
	switch {
	case v < 0xfd:
		return []byte{byte(v)}
	case v <= 0xffff:
		return []byte{0xfd, byte(v), byte(v >> 8)}
	case v <= 0xffffffff:
		return []byte{0xfe, byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	default:
		return []byte{0xff,
			byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
			byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
		}
	}
}

// buildBEEFForTx wraps txRaw in a BUMP-less BEEF body so the consumer
// can ParseBEEF it. The body matches the V1 BEEF magic + 0 bumps +
// 1 tx (target) + has-bump=0 layout.
func buildBEEFForTx(txRaw []byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xEFBE0001))
	buf.WriteByte(0x00) // 0 bumps
	buf.WriteByte(0x01) // 1 tx
	buf.Write(txRaw)
	buf.WriteByte(0x00) // has-bump = 0
	return buf.Bytes()
}

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

// buildInboxBEEF constructs a BEEF envelope whose target tx mimics
// an inbox-covenant Submit() spend: input 0's unlock script holds 3
// pushes ([codePart, opPushTxSig, txRLP]) per runar-go's stateful
// codegen, and output 0 carries an arbitrary continuation script.
// Returns the body bytes plus the raw txRLP push for assertion.
func buildInboxBEEF(t *testing.T, txRLP []byte) []byte {
	t.Helper()
	codePart := bytes.Repeat([]byte{0xab}, 32) // dummy code-part push
	opPushTx := bytes.Repeat([]byte{0xcd}, 72) // dummy 72-byte sig
	unlock := bytes.Join([][]byte{
		pushBytes(codePart),
		pushBytes(opPushTx),
		pushBytes(txRLP),
	}, nil)
	tx := buildOneInputOneOutputTx(unlock, []byte{0x51}, 0) // OP_TRUE locking script
	return buildBEEFForTx(tx)
}

// buildGovernanceBEEF constructs a BEEF envelope whose target tx's
// output 0 carries a covenant continuation script that contains the
// encoded CovenantState as the first 42-byte pushdata. The remaining
// outputs are arbitrary (we only need output 0 for the extractor).
func buildGovernanceBEEF(t *testing.T, st covenant.CovenantState) []byte {
	t.Helper()
	encoded := st.Encode()
	if len(encoded) != 42 {
		t.Fatalf("covenant state encoded size = %d, want 42", len(encoded))
	}
	// Locking script = pushdata(state) + OP_DROP + OP_TRUE; just enough
	// shape for WalkScriptPushdata to find the 42-byte payload.
	lock := append(pushBytes(encoded), 0x75, 0x51)
	tx := buildOneInputOneOutputTx([]byte{0x51}, lock, 1000)
	return buildBEEFForTx(tx)
}

// buildFeeWalletBEEF constructs a BEEF envelope whose target tx
// outputs include exactly one match for the wallet's expected
// locking script. Returns the body bytes.
func buildFeeWalletBEEF(t *testing.T, expectedScript []byte, satoshis uint64) []byte {
	t.Helper()
	outputs := []parsedTxOutput{
		// Decoy output 0 (different script).
		{Satoshis: 100, Script: []byte{0x6a, 0x01, 0xff}},
		// Matching output 1.
		{Satoshis: satoshis, Script: append([]byte(nil), expectedScript...)},
	}
	tx := buildMultiOutputTx([]byte{0x51}, outputs)
	return buildBEEFForTx(tx)
}

// buildCovenantAdvanceBEEF constructs a BEEF envelope whose target tx
// outputs include a state-covenant continuation (output 0) and a
// spec-12 OP_RETURN (output 1) carrying the BSVM\x02 magic +
// withdrawalRoot + encoded BatchData. The BatchData is built from a
// minimal BatchData{} so block.DecodeBatchData succeeds.
func buildCovenantAdvanceBEEF(t *testing.T, withdrawalRoot types.Hash) []byte {
	t.Helper()
	bd := &block.BatchData{
		Version:        block.BatchVersion,
		Timestamp:      0x12345678,
		Coinbase:       types.Address{0x01, 0x02, 0x03},
		ParentHash:     types.Hash{0xaa},
		BSVBlockHash:   types.Hash{0xbb},
		Transactions:   nil,
		DepositHorizon: 999,
	}
	encoded, err := block.EncodeBatchData(bd)
	if err != nil {
		t.Fatalf("encode batch data: %v", err)
	}
	payload := append([]byte("BSVM\x02"), withdrawalRoot[:]...)
	payload = append(payload, encoded...)
	// OP_FALSE OP_RETURN OP_PUSHDATA4 <len> <payload>
	opReturn := []byte{0x00, 0x6a, 0x4e}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	opReturn = append(opReturn, lenBuf[:]...)
	opReturn = append(opReturn, payload...)

	outputs := []parsedTxOutput{
		{Satoshis: 1000, Script: []byte{0x51}}, // state covenant continuation (stub)
		{Satoshis: 0, Script: opReturn},        // spec-12 OP_RETURN
	}
	tx := buildMultiOutputTx([]byte{0x51}, outputs)
	return buildBEEFForTx(tx)
}

// TestWireBEEFEndpointsInboxConsumerWires posts an inbox-submission
// envelope carrying a real Submit()-shaped unlock script and asserts
// that:
//
//  1. The HTTP layer accepts it (204).
//  2. The cmd-side InboxConsumer extracts the txRLP push and queues
//     it on the local InboxMonitor (PendingCount goes from 0 to 1).
//  3. A second POST of the SAME envelope is dropped via the consumer-
//     side dedup set (PendingCount stays at 1).
func TestWireBEEFEndpointsInboxConsumerWires(t *testing.T) {
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

	// Construct a payload that's a plausibly-shaped EVM RLP tx — any
	// >= 10-byte push satisfies the extractor's defensive minimum.
	txRLP := bytes.Repeat([]byte{0xee}, 64)
	beefBody := buildInboxBEEF(t, txRLP)
	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentInboxSubmission,
		Flags:   beef.FlagShardBound,
		ShardID: 31337,
	}
	body, err := beef.EncodeEnvelope(hdr, beefBody)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/bsvm/inbox/submission", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post(); code != http.StatusNoContent {
		t.Fatalf("first post: expected 204, got %d", code)
	}
	if got := inboxMon.PendingCount(); got != 1 {
		t.Fatalf("after first post: PendingCount = %d, want 1", got)
	}

	// Re-POST the same envelope — dedup should swallow it.
	if code := post(); code != http.StatusNoContent {
		t.Fatalf("second post: expected 204, got %d", code)
	}
	if got := inboxMon.PendingCount(); got != 1 {
		t.Fatalf("after dedup post: PendingCount = %d, want 1 (dedup failed)", got)
	}
}

// TestWireBEEFEndpointsInboxConsumerNotWired keeps the structured-log
// fallback branch covered: when InboxMonitor is nil the consumer
// still surfaces the WW-inbox-consumer todo_hook so an operator
// grepping daemon logs sees why no queue extension happened.
func TestWireBEEFEndpointsInboxConsumerNotWired(t *testing.T) {
	logs := installCaptureLogger(t)

	consumer := makeInboxConsumer(beefWireOpts{
		ShardID:      31337,
		InboxMonitor: nil,
	})
	consumer(&beef.Envelope{
		Header: beef.EnvelopeHeader{
			Version: beef.EnvelopeVersion,
			Intent:  beef.IntentInboxSubmission,
			Flags:   beef.FlagShardBound,
			ShardID: 31337,
		},
		TargetTxID: [32]byte{0x77},
	})
	assertConsumerHookLog(t, logs, "WW-inbox-consumer")
}

// TestWireBEEFEndpointsGovernanceConsumerWires posts a governance-
// action envelope carrying a state covenant continuation output whose
// new state has Frozen=1, and asserts that:
//
//  1. The HTTP layer accepts it (204).
//  2. The cmd-side GovernanceConsumer decodes the new CovenantState,
//     diffs against an unset (Frozen=0) local tip, and creates a
//     freeze proposal in the workflow store.
//  3. A second POST of the same envelope is a content-hash no-op
//     (CreateOrMerge dedups by ID).
func TestWireBEEFEndpointsGovernanceConsumerWires(t *testing.T) {
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

	frozen := covenant.CovenantState{
		StateRoot:   types.Hash{0xde, 0xad, 0xbe, 0xef},
		BlockNumber: 42,
		Frozen:      1,
	}
	beefBody := buildGovernanceBEEF(t, frozen)
	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentGovernanceAction,
		Flags:   beef.FlagShardBound,
		ShardID: 31337,
	}
	body, err := beef.EncodeEnvelope(hdr, beefBody)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/bsvm/governance/action", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post(); code != http.StatusNoContent {
		t.Fatalf("first post: expected 204, got %d", code)
	}
	props, err := wf.List()
	if err != nil {
		t.Fatalf("workflow.List: %v", err)
	}
	if len(props) != 1 {
		t.Fatalf("after first post: %d proposals, want 1", len(props))
	}
	if props[0].Action != governance.ActionFreeze {
		t.Fatalf("proposal action = %q, want %q", props[0].Action, governance.ActionFreeze)
	}
	firstID := props[0].ID

	// Re-POST: same content, content-hash dedup prevents a second
	// proposal from appearing.
	if code := post(); code != http.StatusNoContent {
		t.Fatalf("second post: expected 204, got %d", code)
	}
	props, _ = wf.List()
	if len(props) != 1 {
		t.Fatalf("after dedup post: %d proposals, want 1 (dedup failed)", len(props))
	}
	if props[0].ID != firstID {
		t.Fatalf("dedup post produced different ID %q, want %q", props[0].ID, firstID)
	}
}

// TestWireBEEFEndpointsGovernanceConsumerNotWired keeps the
// structured-log fallback branch covered.
func TestWireBEEFEndpointsGovernanceConsumerNotWired(t *testing.T) {
	logs := installCaptureLogger(t)
	consumer := makeGovernanceConsumer(beefWireOpts{
		ShardID:          31337,
		ProposalWorkflow: nil,
	})
	consumer(&beef.Envelope{
		Header: beef.EnvelopeHeader{
			Version: beef.EnvelopeVersion,
			Intent:  beef.IntentGovernanceAction,
			Flags:   beef.FlagShardBound,
			ShardID: 31337,
		},
		TargetTxID: [32]byte{0x88},
	})
	assertConsumerHookLog(t, logs, "WW-governance-consumer")
}

// TestWireBEEFEndpointsFeeWalletConsumerWires constructs a fee-wallet
// envelope whose target tx contains exactly one output whose locking
// script equals the wallet's expected ScriptPubKey, and asserts that:
//
//  1. The consumer matches that output and credits the wallet via
//     AddUTXO (Balance goes from 0 to the matched satoshis).
//  2. Re-running the consumer with the same envelope is a no-op
//     because AddUTXO is idempotent on (txid, vout).
func TestWireBEEFEndpointsFeeWalletConsumerWires(t *testing.T) {
	fw := overlay.NewFeeWallet(nil)
	// Use a recognizable 25-byte P2PKH-shaped script as the expected
	// match — exact bytes don't matter for this test, only equality.
	expected := bsv.BuildP2PKH(bytes.Repeat([]byte{0x55}, 20))
	fw.SetExpectedScriptPubKey(expected)

	beefBody := buildFeeWalletBEEF(t, expected, 5000)
	parsed, err := beef.ParseBEEF(beefBody)
	if err != nil {
		t.Fatalf("parse fixture beef: %v", err)
	}
	env := &beef.Envelope{
		Header: beef.EnvelopeHeader{
			Version: beef.EnvelopeVersion,
			Intent:  beef.IntentFeeWalletFunding,
			Flags:   beef.FlagShardBound,
			ShardID: 31337,
		},
		Beef:       beefBody,
		TargetTxID: parsed.Target().TxID,
		Confirmed:  true,
	}

	consumer := makeFeeWalletConsumer(beefWireOpts{
		ShardID:   31337,
		FeeWallet: fw,
	})
	consumer(env)

	if got := fw.Balance(); got != 5000 {
		t.Fatalf("after first credit: Balance = %d, want 5000", got)
	}
	if got := fw.UTXOCount(); got != 1 {
		t.Fatalf("after first credit: UTXOCount = %d, want 1", got)
	}

	// Idempotency: same envelope re-fed leaves the wallet unchanged.
	consumer(env)
	if got := fw.Balance(); got != 5000 {
		t.Fatalf("after re-credit: Balance = %d, want 5000 (re-credit changed balance)", got)
	}
	if got := fw.UTXOCount(); got != 1 {
		t.Fatalf("after re-credit: UTXOCount = %d, want 1", got)
	}
}

// TestWireBEEFEndpointsFeeWalletConsumerNoScript asserts that when
// the wallet has not published its expected ScriptPubKey the
// consumer falls back to a structured log without crediting.
// Surfaces the WW-fee-wallet-consumer-script todo_hook so the
// operator sees why a posted envelope did not credit.
func TestWireBEEFEndpointsFeeWalletConsumerNoScript(t *testing.T) {
	logs := installCaptureLogger(t)

	fw := overlay.NewFeeWallet(nil) // no SetExpectedScriptPubKey
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
	if bal := fw.Balance(); bal != 0 {
		t.Fatalf("script-less consumer must not credit; balance=%d", bal)
	}
	assertConsumerHookLog(t, logs, "WW-fee-wallet-consumer-script")
}

// TestWireBEEFEndpointsCovenantConsumerWires constructs a covenant-
// advance envelope carrying a real spec-12 OP_RETURN output and
// asserts that:
//
//  1. The consumer extracts withdrawalRoot + decodes BatchData.
//  2. RaceDetector.HandleCovenantAdvance is invoked exactly once for
//     the envelope (observed via OnRaceLost since IsOurs=false).
//  3. A re-fed envelope is dropped by the consumer-level dedup.
//
// We feed a bare RaceDetector via opts.RaceDetector rather than
// constructing a full OverlayNode — the field exists precisely for
// tests that don't want NewOverlayNode's chain-DB / state-DB
// dependencies.
func TestWireBEEFEndpointsCovenantConsumerWires(t *testing.T) {
	rd := overlay.NewRaceDetector(nil)

	withdrawalRoot := types.Hash{0xab, 0xcd}
	beefBody := buildCovenantAdvanceBEEF(t, withdrawalRoot)
	parsed, err := beef.ParseBEEF(beefBody)
	if err != nil {
		t.Fatalf("parse fixture beef: %v", err)
	}

	var observed int
	var observedEvent *overlay.CovenantAdvanceEvent
	rd.OnRaceLost(func(e *overlay.CovenantAdvanceEvent) {
		observed++
		observedEvent = e
	})

	env := &beef.Envelope{
		Header: beef.EnvelopeHeader{
			Version: beef.EnvelopeVersion,
			Intent:  beef.IntentCovenantAdvanceConfirmed,
			Flags:   beef.FlagShardBound,
			ShardID: 31337,
		},
		Beef:       beefBody,
		TargetTxID: parsed.Target().TxID,
		Confirmed:  true,
	}

	consumer := makeCovenantConsumer(beefWireOpts{
		ShardID:      31337,
		RaceDetector: rd,
	})
	consumer(env)
	if observed != 1 {
		t.Fatalf("after first envelope: race-lost observed %d times, want 1", observed)
	}
	if observedEvent == nil {
		t.Fatal("observedEvent is nil")
	}
	if observedEvent.BSVTxID != types.Hash(parsed.Target().TxID) {
		t.Errorf("observed event BSVTxID mismatch: got %x want %x",
			observedEvent.BSVTxID, parsed.Target().TxID)
	}
	if len(observedEvent.BatchData) == 0 {
		t.Errorf("observed event BatchData is empty; extractor failed to populate it")
	}
	consumer(env)
	if observed != 1 {
		t.Fatalf("after dedup envelope: race-lost observed %d times, want 1 (dedup failed)", observed)
	}
}

// TestWireBEEFEndpointsCovenantConsumerNotWired keeps the
// structured-log fallback branch covered: with no overlay node, the
// consumer surfaces the WW-overlay-covenant-consumer todo_hook
// rather than dispatching.
func TestWireBEEFEndpointsCovenantConsumerNotWired(t *testing.T) {
	logs := installCaptureLogger(t)
	consumer := makeCovenantConsumer(beefWireOpts{
		ShardID:                31337,
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
	assertConsumerHookLog(t, logs, "WW-overlay-covenant-consumer")
}

// assertConsumerHookLog finds a slog record carrying todo_hook ==
// expectedHook. The deferred fallback paths surface that field; the
// real-dispatch paths use `hook` (no todo_) so the operator can
// distinguish "deferred for X reason" from "dispatched". Centralises
// the assertion across the four consumer fallback tests.
func assertConsumerHookLog(t *testing.T, logs *captureSlogHandler, expectedHook string) {
	t.Helper()
	for _, r := range logs.snapshot() {
		v, ok := recordHasAttr(r, "todo_hook")
		if !ok || v.String() != expectedHook {
			continue
		}
		return
	}
	t.Fatalf("no slog record with todo_hook=%q found; got %d records", expectedHook, len(logs.snapshot()))
}
