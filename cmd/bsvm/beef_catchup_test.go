package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/icellan/bsvm/pkg/beef"
)

func TestBuildBEEFCatchUpURL(t *testing.T) {
	var cursor [32]byte
	cursor[31] = 0x42
	got, err := buildBEEFCatchUpURL("http://127.0.0.1:8545", cursor, 25)
	if err != nil {
		t.Fatalf("buildBEEFCatchUpURL: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if u.Path != "/bsvm/beef/covenant-chain" {
		t.Fatalf("path = %q, want catch-up endpoint", u.Path)
	}
	if u.Query().Get("from") != hex.EncodeToString(cursor[:]) {
		t.Fatalf("from query = %q, want cursor", u.Query().Get("from"))
	}
	if u.Query().Get("limit") != "25" {
		t.Fatalf("limit query = %q, want 25", u.Query().Get("limit"))
	}
}

func TestDecodeBEEFCovenantCatchUpStream(t *testing.T) {
	frame, env := buildCatchUpFrame(t, 7)
	got, err := decodeBEEFCovenantCatchUpStream(frame, 7)
	if err != nil {
		t.Fatalf("decodeBEEFCovenantCatchUpStream: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("decoded %d envelopes, want 1", len(got))
	}
	if got[0].TargetTxID != env.TargetTxID {
		t.Fatalf("target txid = %x, want %x", got[0].TargetTxID, env.TargetTxID)
	}
}

func TestRunBEEFCovenantCatchUpOnceFetchesAndConsumes(t *testing.T) {
	frame, env := buildCatchUpFrame(t, 7)
	var zero [32]byte
	var sawRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		if r.URL.Path != "/bsvm/beef/covenant-chain" {
			t.Errorf("path = %q, want catch-up endpoint", r.URL.Path)
		}
		if r.URL.Query().Get("from") != hex.EncodeToString(zero[:]) {
			t.Errorf("from = %q, want genesis cursor", r.URL.Query().Get("from"))
		}
		if r.URL.Query().Get("limit") != strconv.Itoa(defaultBEEFCatchUpLimit) {
			t.Errorf("limit = %q, want default", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(frame)
	}))
	defer server.Close()

	store := beef.NewMemoryStore()
	consumed := 0
	opts := beefCatchUpOptions{
		Store:            store,
		CovenantConsumer: func(*beef.Envelope) { consumed++ },
		PeerURLs:         []string{server.URL},
		ShardID:          7,
		HTTPClient:       server.Client(),
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	count, err := runBEEFCovenantCatchUpOnce(context.Background(), opts, zero)
	if err != nil {
		t.Fatalf("runBEEFCovenantCatchUpOnce: %v", err)
	}
	if !sawRequest {
		t.Fatal("server was not called")
	}
	if count != 1 || consumed != 1 {
		t.Fatalf("count=%d consumed=%d, want 1/1", count, consumed)
	}
	has, err := store.Has(env.TargetTxID)
	if err != nil {
		t.Fatalf("store.Has: %v", err)
	}
	if !has {
		t.Fatalf("store missing consumed txid %x", env.TargetTxID)
	}
}

func buildCatchUpFrame(t *testing.T, shardID uint64) ([]byte, *beef.Envelope) {
	t.Helper()
	encoded, err := beef.EncodeEnvelope(beef.EnvelopeHeader{
		Version: beef.EnvelopeVersion,
		Intent:  beef.IntentCovenantAdvanceConfirmed,
		Flags:   beef.FlagShardBound,
		ShardID: shardID,
	}, minimalBEEFBody())
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	env, err := decodeBEEFCovenantCatchUpEnvelope(encoded, shardID)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	out := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(out[:4], uint32(len(encoded)))
	copy(out[4:], encoded)
	return out, env
}
