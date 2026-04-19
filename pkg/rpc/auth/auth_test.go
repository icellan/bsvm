package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mockMode() string    { return "mock" }
func execMode() string    { return "execute" }
func proveMode() string   { return "prove" }
func missingMode() string { return "" }

func TestAuthorize_NoHeaderUnauthorized(t *testing.T) {
	c := Config{DevAuthSecret: "hunter2", ShardProvingMode: mockMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	if _, err := c.Authorize(req); err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAuthorize_DevBypassAcceptedInMockMode(t *testing.T) {
	c := Config{DevAuthSecret: "hunter2", ShardProvingMode: mockMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set("x-bsvm-dev-auth", "hunter2")
	sess, err := c.Authorize(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Kind != KindDevBypass {
		t.Errorf("expected KindDevBypass, got %s", sess.Kind)
	}
}

func TestAuthorize_DevBypassRejectedInProveMode(t *testing.T) {
	c := Config{DevAuthSecret: "hunter2", ShardProvingMode: proveMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set("x-bsvm-dev-auth", "hunter2")
	_, err := c.Authorize(req)
	if err != ErrDevAuthNotAllowed {
		t.Errorf("expected ErrDevAuthNotAllowed in prove mode, got %v", err)
	}
}

func TestAuthorize_DevBypassRejectedWhenModeMissing(t *testing.T) {
	// A shard without a reported proving mode MUST reject dev-bypass.
	// Anything else is a silent downgrade on production-like deployments.
	c := Config{DevAuthSecret: "hunter2", ShardProvingMode: missingMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set("x-bsvm-dev-auth", "hunter2")
	_, err := c.Authorize(req)
	if err != ErrDevAuthNotAllowed {
		t.Errorf("expected ErrDevAuthNotAllowed with missing mode, got %v", err)
	}
}

func TestAuthorize_WrongSecretUnauthorized(t *testing.T) {
	c := Config{DevAuthSecret: "hunter2", ShardProvingMode: mockMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set("x-bsvm-dev-auth", "wrong")
	_, err := c.Authorize(req)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAuthorize_EmptySecretDisablesBypass(t *testing.T) {
	// When no dev secret is configured, the dev header is still handled
	// (so clients get a clear 401) but must never grant access.
	c := Config{DevAuthSecret: "", ShardProvingMode: mockMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set("x-bsvm-dev-auth", "any")
	_, err := c.Authorize(req)
	if err != ErrUnauthorized {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAuthorize_ExecuteModeAcceptsDevBypass(t *testing.T) {
	c := Config{DevAuthSecret: "s", ShardProvingMode: execMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set("x-bsvm-dev-auth", "s")
	sess, err := c.Authorize(req)
	if err != nil || sess.Kind != KindDevBypass {
		t.Errorf("expected dev-bypass in execute mode; got sess=%v err=%v", sess, err)
	}
}

func TestAuthorize_BRC104WithoutSessionStoreRejects(t *testing.T) {
	c := Config{DevAuthSecret: "s", ShardProvingMode: mockMode}
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set("x-bsv-auth-signature", "sig")
	req.Header.Set("x-bsv-auth-identity-key", "02aa")
	_, err := c.Authorize(req)
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected 'not configured' error, got %v", err)
	}
}

func TestMiddleware_StatusCodes(t *testing.T) {
	c := Config{DevAuthSecret: "s", ShardProvingMode: mockMode}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := c.Middleware(inner)

	cases := []struct {
		name   string
		header map[string]string
		mode   ShardProvingModeFunc
		want   int
	}{
		{"no creds", nil, mockMode, http.StatusUnauthorized},
		{"valid dev bypass", map[string]string{"x-bsvm-dev-auth": "s"}, mockMode, http.StatusOK},
		{"bad dev secret", map[string]string{"x-bsvm-dev-auth": "x"}, mockMode, http.StatusUnauthorized},
		{"prove mode reject", map[string]string{"x-bsvm-dev-auth": "s"}, proveMode, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{DevAuthSecret: "s", ShardProvingMode: tc.mode}
			req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			c.Middleware(inner).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("%s: expected %d, got %d (body=%q)", tc.name, tc.want, rec.Code, rec.Body.String())
			}
		})
	}
	_ = mw
}

func TestHashIdentity_StableAndShort(t *testing.T) {
	h := HashIdentity("devnet-bypass")
	if !strings.HasPrefix(h, "0x") || len(h) != 14 {
		t.Errorf("unexpected hash shape: %q", h)
	}
	if HashIdentity("devnet-bypass") != h {
		t.Error("hash not stable across calls")
	}
	if HashIdentity("other") == h {
		t.Error("hash not sensitive to input")
	}
}

func TestClientIP_PrefersXForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	r.RemoteAddr = "10.0.0.1:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	if got := clientIP(r); got != "1.2.3.4" {
		t.Errorf("clientIP: expected 1.2.3.4, got %q", got)
	}
}

func TestClientIP_FallsBackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	r.RemoteAddr = "10.0.0.1:54321"
	if got := clientIP(r); got != "10.0.0.1" {
		t.Errorf("clientIP: expected 10.0.0.1, got %q", got)
	}
}
