package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubRPC is the sentinel the RPC dispatcher side is replaced with in
// tests — when the webui Handler correctly delegates a non-GET request,
// this handler responds with "rpc".
func stubRPC() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("rpc"))
	})
}

func TestHandler_GetRootReturnsIndex(t *testing.T) {
	h := Handler(stubRPC())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected html content-type, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "<title>BSVM Console</title>") {
		t.Errorf("index.html missing expected title marker")
	}
}

func TestHandler_PostDelegatesToRPC(t *testing.T) {
	h := Handler(stubRPC())
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: expected 200 from stub rpc, got %d", rec.Code)
	}
	if rec.Body.String() != "rpc" {
		t.Errorf("expected rpc delegation, got %q", rec.Body.String())
	}
}

func TestHandler_AssetExactMatch(t *testing.T) {
	cssPath := firstCSSAssetPath(t)
	h := Handler(stubRPC())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, cssPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: expected 200, got %d", cssPath, rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Errorf("%s served empty body", cssPath)
	}
}

func TestHandler_UnknownAssetReturns404(t *testing.T) {
	// Missing assets must 404, not silently resolve to index.html —
	// otherwise typos in the SPA bundle mask bugs that only surface in
	// production.
	h := Handler(stubRPC())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/nope.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /assets/nope.js: expected 404, got %d", rec.Code)
	}
}

func TestHandler_SPARouteFallsBackToIndex(t *testing.T) {
	// Arbitrary SPA-style paths must render index.html so client-side
	// routing can take over.
	h := Handler(stubRPC())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/block/1234", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /block/1234: expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<title>BSVM Console</title>") {
		t.Errorf("SPA route should fall back to index.html")
	}
}

// firstCSSAssetPath returns the first hashed CSS asset path emitted by the
// Vite build. The Vite manifest hashes filenames per build, so tests can't
// reference a fixed name; this helper walks the embedded `dist/assets/`
// directory and picks the first `.css`.
func firstCSSAssetPath(t *testing.T) string {
	t.Helper()
	root := FSRoot()
	if root == nil {
		t.Fatal("FSRoot returned nil")
	}
	entries, err := fs.ReadDir(root, "assets")
	if err != nil {
		t.Fatalf("reading dist/assets: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".css") {
			return "/assets/" + e.Name()
		}
	}
	t.Fatal("no .css asset found under dist/assets/")
	return ""
}

func TestHandler_MetricsDelegatesToRPC(t *testing.T) {
	// /metrics is owned by the promhttp handler mounted earlier in the
	// mux chain. Here we only check that the webui wrapper doesn't
	// swallow GET /metrics by serving index.html — it must delegate to
	// the downstream handler (which in the real server is the
	// Prometheus scrape endpoint, but here is our stub).
	h := Handler(stubRPC())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Body.String() != "rpc" {
		t.Errorf("expected /metrics to delegate to downstream handler, got %q", rec.Body.String())
	}
}
