package rpc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/beef"
)

// buildMinimalBEEFBody constructs a syntactically-valid BEEF body
// (V1 magic, 0 BUMPs, 1 minimal tx, no target BUMP) so the route
// handlers can parse it.
func buildMinimalBEEFBody() []byte {
	var buf bytes.Buffer
	// BRC-62 V1 magic on the wire is bytes 01 00 BE EF, which reads
	// as the LE uint32 0xEFBE0001 (matches go-sdk's BEEF_V1 constant).
	binary.Write(&buf, binary.LittleEndian, uint32(0xEFBE0001))
	buf.WriteByte(0x00) // 0 bumps
	buf.WriteByte(0x01) // 1 tx
	// minimal tx: version + 0 inputs + 0 outputs + locktime
	buf.Write([]byte{1, 0, 0, 0})
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.Write([]byte{0, 0, 0, 0})
	buf.WriteByte(0x00) // has-bump = 0
	return buf.Bytes()
}

func TestBEEFEndpointAcceptsValidEnvelope(t *testing.T) {
	store := beef.NewMemoryStore()
	var mu sync.Mutex
	var seen []*beef.Envelope
	cfg := BEEFEndpointConfig{
		Store:   store,
		ShardID: 7,
		BridgeConsumer: func(env *beef.Envelope) {
			mu.Lock()
			seen = append(seen, env)
			mu.Unlock()
		},
	}
	ep := NewBEEFEndpoints(cfg)
	mux := http.NewServeMux()
	ep.Mount(mux)

	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentBridgeDeposit,
		Flags:   beef.FlagShardBound,
		ShardID: 7,
	}
	body, err := beef.EncodeEnvelope(hdr, buildMinimalBEEFBody())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("consumer not called: %d", len(seen))
	}
}

func TestBEEFEndpointRejectsWrongShard(t *testing.T) {
	store := beef.NewMemoryStore()
	ep := NewBEEFEndpoints(BEEFEndpointConfig{Store: store, ShardID: 7})
	mux := http.NewServeMux()
	ep.Mount(mux)

	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentBridgeDeposit,
		Flags:   beef.FlagShardBound,
		ShardID: 99,
	}
	body, _ := beef.EncodeEnvelope(hdr, buildMinimalBEEFBody())
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestBEEFEndpointMethodCheck(t *testing.T) {
	ep := NewBEEFEndpoints(BEEFEndpointConfig{Store: beef.NewMemoryStore()})
	mux := http.NewServeMux()
	ep.Mount(mux)
	req := httptest.NewRequest(http.MethodGet, "/bsvm/bridge/deposit", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestBEEFEndpointRejectsMalformedEnvelope(t *testing.T) {
	ep := NewBEEFEndpoints(BEEFEndpointConfig{Store: beef.NewMemoryStore()})
	mux := http.NewServeMux()
	ep.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/bsvm/inbox/submission", bytes.NewReader([]byte("garbage")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestBEEFEndpointStoreUnavailable(t *testing.T) {
	ep := NewBEEFEndpoints(BEEFEndpointConfig{ShardID: 1})
	mux := http.NewServeMux()
	ep.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/bsvm/bridge/deposit", bytes.NewReader([]byte{}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestBEEFEndpointGovernanceRoute(t *testing.T) {
	store := beef.NewMemoryStore()
	var seen int
	ep := NewBEEFEndpoints(BEEFEndpointConfig{
		Store:   store,
		ShardID: 1,
		GovernanceConsumer: func(env *beef.Envelope) {
			seen++
		},
	})
	mux := http.NewServeMux()
	ep.Mount(mux)
	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentGovernanceAction,
		Flags:   beef.FlagShardBound,
		ShardID: 1,
	}
	body, _ := beef.EncodeEnvelope(hdr, buildMinimalBEEFBody())
	req := httptest.NewRequest(http.MethodPost, "/bsvm/governance/action", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if seen != 1 {
		t.Fatalf("governance consumer called %d times", seen)
	}
}

// makeCovenantEnvelope builds a stored covenant-advance-confirmed
// envelope keyed by a deterministic txid derived from idx, anchored at
// the supplied receive timestamp so test assertions can rely on a
// stable iteration order.
func makeCovenantEnvelope(t *testing.T, idx byte, recvAt time.Time) *beef.Envelope {
	t.Helper()
	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentCovenantAdvanceConfirmed,
		Flags:   beef.FlagShardBound,
		ShardID: 1,
	}
	body := buildMinimalBEEFBody()
	encoded, err := beef.EncodeEnvelope(hdr, body)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	// We don't store the wire-encoded envelope; the store keeps the
	// header + BEEF body separately. Re-frame via DecodeEnvelopeHeader
	// to make sure we hit the same code path the receive handler uses.
	parsedHdr, beefBody, err := beef.DecodeEnvelopeHeader(encoded)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	var txid [32]byte
	for i := range txid {
		txid[i] = idx
	}
	return &beef.Envelope{
		Header:      parsedHdr,
		Beef:        beefBody,
		TargetTxID:  txid,
		Confirmed:   true,
		BlockHeight: 100 + uint64(idx),
		ReceivedAt:  recvAt,
	}
}

// parseFramedBody walks the length-prefixed concatenation of envelopes
// returned by GET /bsvm/beef/covenant-chain and returns the
// individual envelope byte slices.
func parseFramedBody(t *testing.T, body []byte) [][]byte {
	t.Helper()
	out := make([][]byte, 0)
	pos := 0
	for pos < len(body) {
		if pos+4 > len(body) {
			t.Fatalf("framing truncated at pos=%d len=%d", pos, len(body))
		}
		n := binary.BigEndian.Uint32(body[pos : pos+4])
		pos += 4
		if uint64(pos)+uint64(n) > uint64(len(body)) {
			t.Fatalf("envelope length %d overruns body (pos=%d, body=%d)", n, pos, len(body))
		}
		out = append(out, body[pos:pos+int(n)])
		pos += int(n)
	}
	return out
}

func mountCovenantChainTestServer(t *testing.T, store beef.Store) *http.ServeMux {
	t.Helper()
	ep := NewBEEFEndpoints(BEEFEndpointConfig{Store: store, ShardID: 1})
	mux := http.NewServeMux()
	ep.Mount(mux)
	return mux
}

func TestCovenantChainGETReturnsEnvelopesAfterCursor(t *testing.T) {
	store := beef.NewMemoryStore()
	t0 := time.Unix(1700000000, 0).UTC()
	envs := []*beef.Envelope{
		makeCovenantEnvelope(t, 0x01, t0),
		makeCovenantEnvelope(t, 0x02, t0.Add(time.Second)),
		makeCovenantEnvelope(t, 0x03, t0.Add(2*time.Second)),
		makeCovenantEnvelope(t, 0x04, t0.Add(3*time.Second)),
	}
	for _, e := range envs {
		if err := store.Put(e); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	mux := mountCovenantChainTestServer(t, store)

	cursor := hex.EncodeToString(envs[1].TargetTxID[:]) // start after envs[1]
	req := httptest.NewRequest(http.MethodGet, "/bsvm/beef/covenant-chain?from="+cursor, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("content-type = %q", got)
	}
	frames := parseFramedBody(t, rec.Body.Bytes())
	if len(frames) != 2 {
		t.Fatalf("expected 2 envelopes after cursor, got %d", len(frames))
	}
	// Each frame should round-trip through DecodeEnvelopeHeader and
	// the txids should match envs[2], envs[3] in oldest-first order.
	for i, frame := range frames {
		hdr, _, err := beef.DecodeEnvelopeHeader(frame)
		if err != nil {
			t.Fatalf("frame %d decode header: %v", i, err)
		}
		if hdr.Intent != beef.IntentCovenantAdvanceConfirmed {
			t.Fatalf("frame %d wrong intent 0x%02x", i, hdr.Intent)
		}
	}
}

func TestCovenantChainGETGenesisCursorIncludesAll(t *testing.T) {
	store := beef.NewMemoryStore()
	t0 := time.Unix(1700000000, 0).UTC()
	envs := []*beef.Envelope{
		makeCovenantEnvelope(t, 0x10, t0),
		makeCovenantEnvelope(t, 0x11, t0.Add(time.Second)),
	}
	for _, e := range envs {
		if err := store.Put(e); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	mux := mountCovenantChainTestServer(t, store)

	zero := strings.Repeat("00", 32)
	req := httptest.NewRequest(http.MethodGet, "/bsvm/beef/covenant-chain?from=0x"+zero, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	frames := parseFramedBody(t, rec.Body.Bytes())
	if len(frames) != 2 {
		t.Fatalf("expected 2 envelopes, got %d", len(frames))
	}
}

func TestCovenantChainGETMissingFrom(t *testing.T) {
	mux := mountCovenantChainTestServer(t, beef.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/bsvm/beef/covenant-chain", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "from query param required") {
		t.Fatalf("unexpected body %q", rec.Body.String())
	}
}

func TestCovenantChainGETMalformedFrom(t *testing.T) {
	mux := mountCovenantChainTestServer(t, beef.NewMemoryStore())
	cases := []string{
		"deadbeef",                      // too short
		"zz" + strings.Repeat("00", 31), // not hex
		"0x" + strings.Repeat("00", 33), // too long
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/bsvm/beef/covenant-chain?from="+c, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("from=%q: expected 400, got %d", c, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "from must be 32-byte hex txid") {
			t.Fatalf("from=%q: unexpected body %q", c, rec.Body.String())
		}
	}
}

func TestCovenantChainGETUnknownFrom(t *testing.T) {
	store := beef.NewMemoryStore()
	// Put a single envelope so the store isn't empty — the cursor we
	// query for is a different txid that does not exist.
	t0 := time.Unix(1700000000, 0).UTC()
	if err := store.Put(makeCovenantEnvelope(t, 0xaa, t0)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mux := mountCovenantChainTestServer(t, store)

	missing := strings.Repeat("ff", 32)
	req := httptest.NewRequest(http.MethodGet, "/bsvm/beef/covenant-chain?from="+missing, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "from txid not found") {
		t.Fatalf("unexpected body %q", rec.Body.String())
	}
}

func TestCovenantChainGETOversizedLimit(t *testing.T) {
	mux := mountCovenantChainTestServer(t, beef.NewMemoryStore())
	cursor := strings.Repeat("00", 32)
	req := httptest.NewRequest(http.MethodGet,
		"/bsvm/beef/covenant-chain?from="+cursor+"&limit=600", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "limit must be 1..500") {
		t.Fatalf("unexpected body %q", rec.Body.String())
	}
}

func TestCovenantChainGETLimitCapsResults(t *testing.T) {
	store := beef.NewMemoryStore()
	t0 := time.Unix(1700000000, 0).UTC()
	for i := 0; i < 5; i++ {
		if err := store.Put(makeCovenantEnvelope(t, byte(0x20+i), t0.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	mux := mountCovenantChainTestServer(t, store)

	cursor := strings.Repeat("00", 32) // genesis
	req := httptest.NewRequest(http.MethodGet,
		"/bsvm/beef/covenant-chain?from="+cursor+"&limit=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	frames := parseFramedBody(t, rec.Body.Bytes())
	if len(frames) != 2 {
		t.Fatalf("expected 2 envelopes (limit=2), got %d", len(frames))
	}
}

func TestCovenantChainGETEmptyBodyWhenNoSuccessors(t *testing.T) {
	store := beef.NewMemoryStore()
	t0 := time.Unix(1700000000, 0).UTC()
	env := makeCovenantEnvelope(t, 0x77, t0)
	if err := store.Put(env); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mux := mountCovenantChainTestServer(t, store)

	cursor := hex.EncodeToString(env.TargetTxID[:]) // tip — no successors
	req := httptest.NewRequest(http.MethodGet, "/bsvm/beef/covenant-chain?from="+cursor, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %d bytes", rec.Body.Len())
	}
}

func TestCovenantChainPOSTStillWorks(t *testing.T) {
	store := beef.NewMemoryStore()
	var seen int
	cfg := BEEFEndpointConfig{
		Store:   store,
		ShardID: 1,
		CovenantConsumer: func(env *beef.Envelope) {
			seen++
		},
	}
	ep := NewBEEFEndpoints(cfg)
	mux := http.NewServeMux()
	ep.Mount(mux)

	hdr := beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentCovenantAdvanceConfirmed,
		Flags:   beef.FlagShardBound,
		ShardID: 1,
	}
	body, _ := beef.EncodeEnvelope(hdr, buildMinimalBEEFBody())
	req := httptest.NewRequest(http.MethodPost, "/bsvm/beef/covenant-chain", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST status %d body %s", rec.Code, rec.Body.String())
	}
	if seen != 1 {
		t.Fatalf("covenant consumer called %d times", seen)
	}
}

func TestCovenantChainBadMethod(t *testing.T) {
	mux := mountCovenantChainTestServer(t, beef.NewMemoryStore())
	req := httptest.NewRequest(http.MethodPut, "/bsvm/beef/covenant-chain", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
