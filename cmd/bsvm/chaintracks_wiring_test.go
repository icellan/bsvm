package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	sdktx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
)

// TestBuildChaintracksClient_NoProviders documents the soft-fail
// behaviour: no providers configured -> (nil, nil), so the daemon can
// still boot. Bridge deposits remain fail-closed in that mode.
func TestBuildChaintracksClient_NoProviders(t *testing.T) {
	got, err := BuildChaintracksClient(context.Background(), ChaintracksSection{}, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil client, got %T", got)
	}
}

// TestBuildChaintracksClient_AllDisabled also returns (nil, nil) —
// every entry is .Enabled=false so the live set is empty.
func TestBuildChaintracksClient_AllDisabled(t *testing.T) {
	cfg := ChaintracksSection{
		Providers: []ChaintracksProvider{
			{Name: "a", URL: "https://a.example", Enabled: false},
			{Name: "b", URL: "https://b.example", Enabled: false},
		},
	}
	got, err := BuildChaintracksClient(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil client when every provider disabled, got %T", got)
	}
}

// TestBuildChaintracksClient_SingleProvider builds a one-provider
// MultiClient and verifies it implements ChaintracksClient.
func TestBuildChaintracksClient_SingleProvider(t *testing.T) {
	srv := newFakeChaintracksServer(t, fakeChaintracksFixture{
		tipHeight: 800010,
		headers: map[uint64]fakeHeader{
			800000: {height: 800000, hash: deterministicHash(800000), merkle: deterministicHash(1)},
			800010: {height: 800010, hash: deterministicHash(800010), merkle: deterministicHash(2)},
		},
	})
	defer srv.Close()

	cfg := ChaintracksSection{
		Providers: []ChaintracksProvider{
			{Name: "primary", URL: srv.URL, Enabled: true, Timeout: "2s"},
		},
		QuorumM:         1,
		QuorumStrategy:  "hybrid",
		ResponseTimeout: "3s",
	}
	got, err := BuildChaintracksClient(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("BuildChaintracksClient: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil client")
	}
	defer got.Close()

	// Static-type check: the returned value satisfies ChaintracksClient.
	var _ chaintracks.ChaintracksClient = got

	// Smoke-call Tip — confirms the wiring talks to the fake server.
	tip, err := got.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Height != 800010 {
		t.Fatalf("expected tip height 800010, got %d", tip.Height)
	}
}

// TestBuildChaintracksClient_ThreeProviders_Quorum exercises the multi-
// provider quorum path: three fake servers, m=2, strategy=m_of_n. All
// three return the same tip, so quorum is trivially met.
func TestBuildChaintracksClient_ThreeProviders_Quorum(t *testing.T) {
	fixture := fakeChaintracksFixture{
		tipHeight: 800020,
		headers: map[uint64]fakeHeader{
			800020: {height: 800020, hash: deterministicHash(800020), merkle: deterministicHash(3)},
		},
	}
	a := newFakeChaintracksServer(t, fixture)
	defer a.Close()
	b := newFakeChaintracksServer(t, fixture)
	defer b.Close()
	c := newFakeChaintracksServer(t, fixture)
	defer c.Close()

	cfg := ChaintracksSection{
		Providers: []ChaintracksProvider{
			{Name: "a", URL: a.URL, Enabled: true},
			{Name: "b", URL: b.URL, Enabled: true},
			{Name: "c", URL: c.URL, Enabled: true},
		},
		QuorumM:        2,
		QuorumStrategy: "m_of_n",
	}
	got, err := BuildChaintracksClient(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("BuildChaintracksClient: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil client")
	}
	defer got.Close()

	tip, err := got.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Height != 800020 {
		t.Fatalf("expected tip height 800020, got %d", tip.Height)
	}
}

// TestBuildChaintracksClient_RejectsBadDuration confirms a malformed
// duration in the config is surfaced as an error (no silent default).
func TestBuildChaintracksClient_RejectsBadDuration(t *testing.T) {
	cfg := ChaintracksSection{
		Providers: []ChaintracksProvider{
			{Name: "a", URL: "https://a.example", Enabled: true},
		},
		ResponseTimeout: "not-a-duration",
	}
	_, err := BuildChaintracksClient(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for malformed response_timeout")
	}
	if !strings.Contains(err.Error(), "response_timeout") {
		t.Fatalf("expected error to mention response_timeout, got %v", err)
	}
}

// TestBuildChaintracksClient_RejectsBadDisagreementAction confirms that
// an invalid action string is rejected.
func TestBuildChaintracksClient_RejectsBadDisagreementAction(t *testing.T) {
	cfg := ChaintracksSection{
		Providers: []ChaintracksProvider{
			{Name: "a", URL: "https://a.example", Enabled: true},
		},
		DisagreementAction: "explode",
	}
	_, err := BuildChaintracksClient(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid disagreement_action")
	}
}

// TestWireBEEFEndpoints_FullWiringWithFakeChaintracks is the headline
// integration test: spins up a fake chaintracks server, builds a real
// MultiClient from the daemon's BuildChaintracksClient helper, posts a
// valid BEEF deposit envelope to the BEEF endpoint, and confirms the
// bridge monitor's PersistDeposit path fired.
//
// This is the end-to-end wire we were missing: cmd/bsvm chaintracks
// builder -> beef wiring -> verifier -> bridge consumer -> monitor.
func TestWireBEEFEndpoints_FullWiringWithFakeChaintracks(t *testing.T) {
	const shardID = 31337
	const localShardID = uint32(31337)
	const bsvBlockHeight = uint64(800_000)
	const confirmations = uint64(10)

	// Build the deposit tx + ancestor (mirrors the W6-4 integration
	// fixture).
	bridgeLockBytes := []byte{0x76, 0xa9, 0x14,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
		0x88, 0xac}
	bridgeLock := sdkscript.NewFromBytes(bridgeLockBytes)

	var l2Addr [20]byte
	for i := range l2Addr {
		l2Addr[i] = byte(0xc0 + i)
	}

	ancestor := sdktx.NewTransaction()
	ancestor.AddOutput(&sdktx.TransactionOutput{
		Satoshis:      100_000,
		LockingScript: sdkscript.NewFromBytes([]byte{sdkscript.OpTRUE}),
	})
	ancHash := ancestor.TxID()
	isTxid := true
	ancestor.MerklePath = sdktx.NewMerklePath(uint32(bsvBlockHeight), [][]*sdktx.PathElement{{
		{Offset: 0, Hash: ancHash, Txid: &isTxid},
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
	depositHash := depositTx.TxID()
	depositIsTxid := true
	depositTx.MerklePath = sdktx.NewMerklePath(uint32(bsvBlockHeight), [][]*sdktx.PathElement{{
		{Offset: 0, Hash: depositHash, Txid: &depositIsTxid},
	}})
	beefBytes, err := depositTx.BEEF()
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}

	// Fake chaintracks server returning a header at bsvBlockHeight whose
	// merkle root equals the deposit txid (single-tx block) and a tip 9
	// blocks later (10 confirmations).
	var depositTxIDBytes [32]byte
	copy(depositTxIDBytes[:], depositTx.TxID().CloneBytes())
	tipHeight := bsvBlockHeight + confirmations - 1
	srv := newFakeChaintracksServer(t, fakeChaintracksFixture{
		tipHeight: tipHeight,
		headers: map[uint64]fakeHeader{
			bsvBlockHeight: {
				height: bsvBlockHeight,
				hash:   deterministicHash(bsvBlockHeight),
				merkle: depositTxIDBytes,
			},
			tipHeight: {
				height: tipHeight,
				hash:   deterministicHash(tipHeight),
				merkle: deterministicHash(tipHeight),
			},
		},
	})
	defer srv.Close()

	// Drive the cmd-side wiring helper exactly as cmdRun would.
	chaintracksClient, err := BuildChaintracksClient(context.Background(), ChaintracksSection{
		Providers: []ChaintracksProvider{
			{Name: "fake", URL: srv.URL, Enabled: true},
		},
		QuorumM: 1,
	}, nil)
	if err != nil {
		t.Fatalf("BuildChaintracksClient: %v", err)
	}
	if chaintracksClient == nil {
		t.Fatal("expected non-nil chaintracks client")
	}
	defer chaintracksClient.Close()

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
			AnchorDepth:                    6,
			ValidatedCacheSize:             16,
		},
		DB:               memDB,
		ShardID:          shardID,
		BridgeMonitor:    monitor,
		BridgeScriptHash: bridgeLockBytes,
		LocalShardID:     localShardID,
		Chaintracks:      chaintracksClient,
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

	if !monitor.IsProcessed(depositTxIDBytes, 0) {
		t.Fatalf("expected bridge monitor to mark deposit as processed; pending=%d, calls observed: tip=%d header=%d",
			monitor.PendingCount(), srv.TipCalls(), srv.HeaderCalls())
	}
	if srv.HeaderCalls() == 0 {
		t.Fatal("expected the verifier to query the fake chaintracks server at least once")
	}
}

// fakeChaintracksFixture programs the fake server with a sparse map of
// height -> header data. Lookups for unknown heights return 404.
type fakeChaintracksFixture struct {
	tipHeight uint64
	headers   map[uint64]fakeHeader
}

type fakeHeader struct {
	height uint64
	hash   [32]byte
	merkle [32]byte
}

// fakeChaintracksServer is a minimal BRC-64 stand-in: it serves /tip,
// /header/height/{n}, /header/hash/{hex}, and /ping. Sufficient for the
// chaintracks RemoteClient to satisfy header lookups; the WS stream is
// not needed for the BEEF verifier hot path.
type fakeChaintracksServer struct {
	*httptest.Server
	mu          sync.Mutex
	fixture     fakeChaintracksFixture
	tipCalls    atomic.Int64
	headerCalls atomic.Int64
}

func newFakeChaintracksServer(t *testing.T, f fakeChaintracksFixture) *fakeChaintracksServer {
	t.Helper()
	s := &fakeChaintracksServer{fixture: f}
	mux := http.NewServeMux()
	mux.HandleFunc("/tip", func(w http.ResponseWriter, r *http.Request) {
		s.tipCalls.Add(1)
		s.mu.Lock()
		h, ok := s.fixture.headers[s.fixture.tipHeight]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "no tip", http.StatusInternalServerError)
			return
		}
		writeFakeHeader(w, h)
	})
	mux.HandleFunc("/header/height/", func(w http.ResponseWriter, r *http.Request) {
		s.headerCalls.Add(1)
		raw := strings.TrimPrefix(r.URL.Path, "/header/height/")
		var height uint64
		if _, err := fmt.Sscanf(raw, "%d", &height); err != nil {
			http.Error(w, "bad height", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		h, ok := s.fixture.headers[height]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeFakeHeader(w, h)
	})
	mux.HandleFunc("/header/hash/", func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Path, "/header/hash/")
		want, err := hex.DecodeString(raw)
		if err != nil || len(want) != 32 {
			http.Error(w, "bad hash", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, h := range s.fixture.headers {
			if string(h.hash[:]) == string(want) {
				writeFakeHeader(w, h)
				return
			}
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s.Server = httptest.NewServer(mux)
	return s
}

// TipCalls reports how many /tip calls the server received. Used by
// tests to assert the chaintracks adapter actually queried the server.
func (s *fakeChaintracksServer) TipCalls() int64 { return s.tipCalls.Load() }

// HeaderCalls reports the count of /header/height/* calls.
func (s *fakeChaintracksServer) HeaderCalls() int64 { return s.headerCalls.Load() }

func writeFakeHeader(w http.ResponseWriter, h fakeHeader) {
	w.Header().Set("Content-Type", "application/json")
	work := new(big.Int).SetUint64(h.height + 1)
	body := map[string]any{
		"height":     h.height,
		"hash":       hex.EncodeToString(h.hash[:]),
		"prevhash":   hex.EncodeToString(make([]byte, 32)),
		"merkleroot": hex.EncodeToString(h.merkle[:]),
		"timestamp":  uint32(1_700_000_000),
		"bits":       uint32(0x207fffff),
		"nonce":      uint32(0),
		"work":       work.Text(16),
	}
	_ = json.NewEncoder(w).Encode(body)
}
