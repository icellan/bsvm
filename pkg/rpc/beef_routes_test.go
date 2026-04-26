package rpc

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

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
