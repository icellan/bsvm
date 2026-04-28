package arc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestARCBroadcastError_Classification verifies the
// IsTransient / IsPermanent decision matrix for the typed error.
func TestARCBroadcastError_Classification(t *testing.T) {
	cases := []struct {
		name      string
		err       *ARCBroadcastError
		transient bool
		permanent bool
	}{
		// HTTP-only signals.
		{"503 server error", &ARCBroadcastError{HTTPStatus: 503}, true, false},
		{"500 server error", &ARCBroadcastError{HTTPStatus: 500}, true, false},
		{"408 timeout", &ARCBroadcastError{HTTPStatus: 408}, true, false},
		{"429 rate limited", &ARCBroadcastError{HTTPStatus: 429}, true, false},
		{"400 bad request", &ARCBroadcastError{HTTPStatus: 400, TxStatus: "REJECTED"}, false, true},
		{"422 reject", &ARCBroadcastError{HTTPStatus: 422, Detail: "bad-txns"}, false, true},
		{"404 not found", &ARCBroadcastError{HTTPStatus: 404}, false, true},

		// Pre-response transport failure (HTTPStatus 0).
		{"connect refused", &ARCBroadcastError{Underlying: errors.New("connect: refused")}, true, false},

		// 200 + terminal txStatus.
		{"200 rejected", &ARCBroadcastError{HTTPStatus: 200, TxStatus: "REJECTED"}, false, true},
		{"200 double spend", &ARCBroadcastError{HTTPStatus: 200, TxStatus: "DOUBLE_SPEND_ATTEMPTED"}, false, true},
		{"200 orphan", &ARCBroadcastError{HTTPStatus: 200, TxStatus: "SEEN_IN_ORPHAN_MEMPOOL"}, false, true},

		// Detail-only signals (covenant rejections via 200 body).
		{"covenant-failed", &ARCBroadcastError{HTTPStatus: 200, Detail: "covenant-failed: bad witness"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.IsTransient(); got != tc.transient {
				t.Errorf("IsTransient() = %v, want %v", got, tc.transient)
			}
			if got := tc.err.IsPermanent(); got != tc.permanent {
				t.Errorf("IsPermanent() = %v, want %v", got, tc.permanent)
			}
		})
	}
}

// TestARCBroadcastError_ErrorsAs verifies errors.As pulls the typed
// shape out of a wrapped error chain — this is the primary classifier
// surface for pkg/bridge.
func TestARCBroadcastError_ErrorsAs(t *testing.T) {
	inner := &ARCBroadcastError{HTTPStatus: 503, Detail: "bad gateway"}
	wrapped := fmt.Errorf("withdrawer: claim broadcast: %w", inner)

	var got *ARCBroadcastError
	if !errors.As(wrapped, &got) {
		t.Fatalf("errors.As did not extract typed error from %v", wrapped)
	}
	if got.HTTPStatus != 503 {
		t.Errorf("HTTPStatus = %d, want 503", got.HTTPStatus)
	}
	if !got.IsTransient() {
		t.Error("expected transient")
	}
	if got.IsPermanent() {
		t.Error("expected NOT permanent")
	}
}

// TestARCBroadcastError_AsBroadcastErrorHelper covers the
// AsBroadcastError convenience wrapper.
func TestARCBroadcastError_AsBroadcastErrorHelper(t *testing.T) {
	if got := AsBroadcastError(nil); got != nil {
		t.Errorf("AsBroadcastError(nil) = %v, want nil", got)
	}
	plain := errors.New("nothing arc-shaped")
	if got := AsBroadcastError(plain); got != nil {
		t.Errorf("AsBroadcastError(plain) = %v, want nil", got)
	}
	wrapped := fmt.Errorf("ctx: %w", &ARCBroadcastError{HTTPStatus: 400})
	if got := AsBroadcastError(wrapped); got == nil || got.HTTPStatus != 400 {
		t.Errorf("AsBroadcastError(wrapped) = %v, want HTTPStatus=400", got)
	}
}

// TestARCBroadcastError_FormatPreservesLegacyPrefix verifies the
// "arc: broadcast status N" prefix is preserved exactly so the legacy
// regex-based extractHTTPStatus in pkg/bridge keeps working as a
// fallback for non-typed call sites.
func TestARCBroadcastError_FormatPreservesLegacyPrefix(t *testing.T) {
	e := &ARCBroadcastError{HTTPStatus: 503, Detail: "temporarily unavailable"}
	msg := e.Error()
	if !strings.HasPrefix(msg, "arc: broadcast status 503") {
		t.Errorf("Error() = %q, want prefix 'arc: broadcast status 503'", msg)
	}
	if !strings.Contains(msg, "temporarily unavailable") {
		t.Errorf("Error() = %q, missing detail", msg)
	}
}

// TestClientBroadcast_Returns4xxAsTypedError exercises the live HTTP
// path: a 422 from ARC must surface as *ARCBroadcastError so the
// withdrawer's classifier can branch via errors.As.
func TestClientBroadcast_Returns4xxAsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity) // 422
		w.Write([]byte(`{"txStatus":"REJECTED","extraInfo":"double-spend"}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Timeout: 2 * time.Second})
	_, err := c.Broadcast(context.Background(), []byte{0xde})
	if err == nil {
		t.Fatal("expected error")
	}
	arcErr := AsBroadcastError(err)
	if arcErr == nil {
		t.Fatalf("expected *ARCBroadcastError, got %T: %v", err, err)
	}
	if arcErr.HTTPStatus != 422 {
		t.Errorf("HTTPStatus = %d, want 422", arcErr.HTTPStatus)
	}
	if arcErr.TxStatus != string(StatusRejected) {
		t.Errorf("TxStatus = %q, want %q", arcErr.TxStatus, StatusRejected)
	}
	if !arcErr.IsPermanent() {
		t.Error("expected IsPermanent")
	}
	if arcErr.IsTransient() {
		t.Error("expected NOT IsTransient")
	}
}

// TestClientBroadcast_5xxIsTransient verifies the live path produces a
// transient typed error on a 5xx.
func TestClientBroadcast_5xxIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("upstream unavailable"))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Timeout: 2 * time.Second})
	_, err := c.Broadcast(context.Background(), []byte{0xde})
	arcErr := AsBroadcastError(err)
	if arcErr == nil {
		t.Fatalf("expected *ARCBroadcastError, got %T", err)
	}
	if !arcErr.IsTransient() || arcErr.IsPermanent() {
		t.Errorf("transient=%v permanent=%v, want transient", arcErr.IsTransient(), arcErr.IsPermanent())
	}
}

// TestClientBroadcast_200WithRejectedTxStatus exercises ARC's
// "200-but-actually-rejected" pattern. We must surface this as a
// permanent typed error so the withdrawer drops the claim instead of
// treating the 200 as success.
func TestClientBroadcast_200WithRejectedTxStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"txStatus":"REJECTED","extraInfo":"covenant verify-failed"}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Timeout: 2 * time.Second})
	_, err := c.Broadcast(context.Background(), []byte{0xde})
	if err == nil {
		t.Fatal("expected error")
	}
	arcErr := AsBroadcastError(err)
	if arcErr == nil {
		t.Fatalf("expected *ARCBroadcastError, got %T: %v", err, err)
	}
	if !arcErr.IsPermanent() {
		t.Error("expected IsPermanent for REJECTED txStatus")
	}
}
