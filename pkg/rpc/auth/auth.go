// Package auth implements the authentication layer that guards the
// admin JSON-RPC surface described in spec 15.
//
// Two authentication modes are supported:
//
//   - Dev-bypass: a shared secret passed via the `x-bsvm-dev-auth`
//     header, only accepted when the shard's proving mode is "mock"
//     or "execute". This is the path used by the spec 16 devnet and
//     by the `bsv-evm admin freeze|unfreeze` CLI in local mode.
//
//   - (Planned) BRC-100 wallet: a BRC-103 handshake followed by
//     BRC-104 signed headers. This is the production path used by the
//     explorer admin panel when connected to a Metanet Desktop / BSV
//     wallet. The package currently scaffolds the seams needed for
//     that work (IsGovernanceKey + Session) without shipping the full
//     state machine. Missing pieces are explicit stubs so callers see
//     clear "not yet supported" errors rather than silent auth
//     bypass.
//
// Security guardrails:
//
//   - Dev-bypass MUST check the shard's actual proving mode at
//     request time — not an environment variable — so a production
//     image cannot be tricked into accepting dev credentials by a
//     leaked env var.
//   - Every successful authentication carries a stable "identity"
//     string (either "devnet-bypass" or the hex-encoded governance
//     pubkey) that downstream admin handlers include in their audit
//     log lines.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// ErrUnauthorized is returned by Authorize when an incoming request
// lacks valid credentials. Middleware translates it to HTTP 401.
var ErrUnauthorized = errors.New("unauthorized")

// ErrDevAuthNotAllowed is returned when the dev-bypass header is
// presented on a shard whose proving mode is not mock / execute.
// Middleware treats it as 403 — the credentials are valid for *some*
// shard type, just not this one.
var ErrDevAuthNotAllowed = errors.New("dev-auth header not accepted in this proving mode")

// Kind classifies how a request authenticated. Admin handlers log it
// so operators can distinguish dev-bypass calls from wallet-signed
// ones in postmortems.
type Kind string

const (
	// KindDevBypass — x-bsvm-dev-auth header with a matching secret.
	KindDevBypass Kind = "dev-bypass"
	// KindBRC100 — BRC-103 session plus BRC-104 signed headers.
	// Reserved; not yet emitted.
	KindBRC100 Kind = "brc100"
)

// Session describes the authenticated principal behind an admin RPC
// request. The Identity field is opaque to the middleware but is
// expected to be usable as a log / audit key. For BRC-100 sessions it
// is the hex-encoded identity public key; for dev bypass it is the
// fixed string "devnet-bypass".
type Session struct {
	Kind      Kind
	Identity  string
	RemoteIP  string
	UserAgent string
}

// ShardProvingModeFunc returns the shard's current proving mode string
// ("mock", "execute", "prove"). The middleware queries this at every
// request — callers pass the live accessor, not a snapshot, so a shard
// that is upgraded in flight cannot leave stale credentials active.
type ShardProvingModeFunc func() string

// GovernanceKeyChecker reports whether a candidate compressed secp256k1
// public key belongs to the shard's governance set. Used by the
// (future) BRC-100 handshake; placing the interface here keeps the
// admin RPC package free of covenant imports.
type GovernanceKeyChecker interface {
	IsGovernanceKey(compressedPubKey []byte) bool
}

// Config drives Middleware. Zero-value fields are acceptable:
//   - When DevAuthSecret is empty, the dev-bypass path is disabled.
//   - When ShardProvingMode is nil, dev-bypass is rejected in every
//     mode (safer default for deployments that want wallet-only auth).
//   - When GovernanceChecker, ServerIdentity or SessionStore is nil,
//     BRC-100 wallet auth is disabled (handshake endpoint returns
//     503). Populate all three to turn it on.
type Config struct {
	DevAuthSecret     string
	ShardProvingMode  ShardProvingModeFunc
	GovernanceChecker GovernanceKeyChecker
	ServerIdentity    *ServerIdentity
	SessionStore      *SessionStore
}

// Middleware wraps an http.Handler with admin authentication.
// Requests that present a valid credential continue to next with an
// auth.Session attached to the context. Requests without credentials
// receive a 401; valid credentials for the wrong mode get 403.
func (c Config) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := c.Authorize(r)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrDevAuthNotAllowed) {
				status = http.StatusForbidden
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"` + err.Error() + `"}`))
			return
		}
		ctx := WithSession(r.Context(), sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Authorize inspects request headers and returns the session when the
// request should proceed. Callers can use it directly when they need
// to route authorized and unauthorized requests to different handlers
// rather than returning an HTTP error.
func (c Config) Authorize(r *http.Request) (*Session, error) {
	if sess, ok, err := c.tryDevBypass(r); ok {
		return sess, err
	}
	if sess, ok, err := c.tryBRC104(r); ok {
		return sess, err
	}
	return nil, ErrUnauthorized
}

// tryDevBypass handles the x-bsvm-dev-auth header. Returns (session,
// true, nil) on success, (nil, true, err) when the header was
// presented but rejected (wrong mode / wrong secret), and (nil,
// false, nil) when the header wasn't present at all.
func (c Config) tryDevBypass(r *http.Request) (*Session, bool, error) {
	supplied := r.Header.Get("x-bsvm-dev-auth")
	if supplied == "" {
		return nil, false, nil
	}
	if c.DevAuthSecret == "" {
		// Dev-bypass not configured on this node. Return auth error so
		// clients that incorrectly assume it's always on get a clear
		// signal, but treat the header as handled (no BRC-100 fallback).
		return nil, true, ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(c.DevAuthSecret)) != 1 {
		return nil, true, ErrUnauthorized
	}
	// Secret matched — now check the shard's live proving mode.
	if c.ShardProvingMode == nil {
		return nil, true, ErrDevAuthNotAllowed
	}
	mode := strings.ToLower(c.ShardProvingMode())
	if mode != "mock" && mode != "execute" {
		return nil, true, ErrDevAuthNotAllowed
	}
	return &Session{
		Kind:      KindDevBypass,
		Identity:  "devnet-bypass",
		RemoteIP:  clientIP(r),
		UserAgent: r.UserAgent(),
	}, true, nil
}

// (BRC-100 wallet authentication lives in brc104.go — tryBRC104.)

// ---------- Context helpers -----------------------------------------

type ctxKey struct{}

// WithSession returns a new context carrying the given session.
func WithSession(ctx context.Context, s *Session) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, s)
}

// FromContext returns the session attached by the middleware, or nil
// if the request was not authenticated. Handlers that can be reached
// by both authed and unauthed paths check for nil; admin handlers
// wrapped in Middleware always see a non-nil session.
func FromContext(ctx context.Context) *Session {
	if v, ok := ctx.Value(ctxKey{}).(*Session); ok {
		return v
	}
	return nil
}

// HashIdentity returns a short sha256 prefix of the given identity
// string, useful for log keys that shouldn't expose full public keys.
func HashIdentity(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "0x" + string(hexEncode(sum[:6]))
}

func hexEncode(b []byte) []byte {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return out
}

// clientIP extracts the request's remote address, preferring the
// first entry of X-Forwarded-For when present (common when the node
// sits behind a reverse proxy for TLS termination).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF is "client, proxy1, proxy2". First entry is the real client.
		if idx := strings.IndexByte(xff, ','); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	addr := r.RemoteAddr
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
