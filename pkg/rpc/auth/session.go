package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// sessionRecord is the server-side view of an active BRC-100 session.
// It is keyed in the SessionStore by the server-issued nonce so a
// BRC-104-authenticated request can locate its session via the
// `x-bsv-auth-your-nonce` header without an extra lookup.
type sessionRecord struct {
	// IdentityKey is the hex-encoded compressed secp256k1 public key
	// the client authenticated under. Carried through to the admin
	// handler via the auth.Session attached to the request context.
	IdentityKey string
	// ServerNonce is the base64-encoded 32-byte nonce this record is
	// keyed by. The client echoes it in `x-bsv-auth-your-nonce`.
	ServerNonce string
	// ClientNonce is the base64-encoded 32-byte nonce the client
	// supplied in its last request. The server rotates this on every
	// response (after verifying the inbound signature) so a replayed
	// request is rejected on the next round-trip.
	ClientNonce string
	// CreatedAt is the timestamp of the handshake.
	CreatedAt time.Time
	// LastSeen is updated on every authenticated request so we can
	// expire idle sessions.
	LastSeen time.Time
	// RemoteIP is the last-seen client IP. Included purely for the
	// audit log.
	RemoteIP string
}

// SessionStore keeps the active set of BRC-100 sessions, keyed by the
// server-issued nonce. The store expires records after
// `SessionIdleTTL` of inactivity — callers interact only via
// Create / Get / UpdateClientNonce / Delete.
type SessionStore struct {
	mu             sync.Mutex
	sessions       map[string]*sessionRecord
	idleTTL        time.Duration
	maxSessions    int
	nowFn          func() time.Time
	randReadFn     func([]byte) (int, error)
	sweepInterval  time.Duration
	stopSweep      chan struct{}
	sweeperStarted bool
}

// SessionIdleTTL is the default idle timeout. Spec 15 asks for one
// hour — a session that goes idle longer must re-handshake.
const SessionIdleTTL = time.Hour

// maxSessionsDefault caps in-memory session growth. An admin panel has
// at most a handful of concurrent operators; 1024 gives plenty of
// headroom without unbounded memory.
const maxSessionsDefault = 1024

// NewSessionStore constructs an empty store with default TTL / cap.
// Call Close when tearing the server down so the sweeper goroutine
// exits.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:      make(map[string]*sessionRecord),
		idleTTL:       SessionIdleTTL,
		maxSessions:   maxSessionsDefault,
		nowFn:         time.Now,
		randReadFn:    rand.Read,
		sweepInterval: 5 * time.Minute,
		stopSweep:     make(chan struct{}),
	}
}

// WithClock installs a deterministic clock and RNG. Intended for
// tests; production callers never need this.
func (s *SessionStore) WithClock(now func() time.Time, randRead func([]byte) (int, error)) *SessionStore {
	s.nowFn = now
	if randRead != nil {
		s.randReadFn = randRead
	}
	return s
}

// StartSweeper launches a background goroutine that periodically
// removes expired sessions. Idempotent — second call is a no-op.
// Call Close() to stop.
func (s *SessionStore) StartSweeper() {
	s.mu.Lock()
	if s.sweeperStarted {
		s.mu.Unlock()
		return
	}
	s.sweeperStarted = true
	s.mu.Unlock()

	go func() {
		t := time.NewTicker(s.sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.sweepExpired()
			case <-s.stopSweep:
				return
			}
		}
	}()
}

// Close signals the background sweeper to exit. Safe to call even if
// StartSweeper was never called; safe to call concurrently.
func (s *SessionStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sweeperStarted {
		return
	}
	select {
	case <-s.stopSweep:
		// already closed
	default:
		close(s.stopSweep)
	}
	s.sweeperStarted = false
}

// Create records a new session, returning the freshly-generated server
// nonce. The caller is expected to sign / transmit that nonce back to
// the client as part of the BRC-103 initialResponse.
func (s *SessionStore) Create(identityKey, clientNonce, remoteIP string) (*sessionRecord, error) {
	nonce, err := s.newNonce()
	if err != nil {
		return nil, err
	}
	now := s.nowFn()
	rec := &sessionRecord{
		IdentityKey: identityKey,
		ServerNonce: nonce,
		ClientNonce: clientNonce,
		CreatedAt:   now,
		LastSeen:    now,
		RemoteIP:    remoteIP,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.maxSessions {
		// Drop the oldest entry. Cheap O(n) scan; the cap is tiny.
		var oldestKey string
		var oldestAt time.Time
		for k, v := range s.sessions {
			if oldestKey == "" || v.LastSeen.Before(oldestAt) {
				oldestKey = k
				oldestAt = v.LastSeen
			}
		}
		if oldestKey != "" {
			delete(s.sessions, oldestKey)
		}
	}
	s.sessions[nonce] = rec
	return rec, nil
}

// Get returns the session identified by `serverNonce`. When the
// session does not exist or is expired, it returns nil and deletes
// any stale record.
func (s *SessionStore) Get(serverNonce string) *sessionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[serverNonce]
	if !ok {
		return nil
	}
	if s.nowFn().Sub(rec.LastSeen) > s.idleTTL {
		delete(s.sessions, serverNonce)
		return nil
	}
	return rec
}

// Rotate rotates a session's nonces after a successful authenticated
// request. Spec 15's sequence: client sends with previous
// server-nonce; server verifies; server issues a fresh server-nonce
// and echoes the new client-nonce. Previous keys are removed so the
// old server nonce cannot be re-used.
//
// Returns the fresh server nonce. The caller puts it in the
// `x-bsv-auth-nonce` response header.
func (s *SessionStore) Rotate(prevServerNonce, newClientNonce, remoteIP string) (*sessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sessions[prevServerNonce]
	if !ok {
		return nil, errSessionNotFound
	}
	if s.nowFn().Sub(rec.LastSeen) > s.idleTTL {
		delete(s.sessions, prevServerNonce)
		return nil, errSessionNotFound
	}

	delete(s.sessions, prevServerNonce)

	nextNonce, err := s.newNonce()
	if err != nil {
		return nil, err
	}
	now := s.nowFn()
	rotated := &sessionRecord{
		IdentityKey: rec.IdentityKey,
		ServerNonce: nextNonce,
		ClientNonce: newClientNonce,
		CreatedAt:   rec.CreatedAt,
		LastSeen:    now,
		RemoteIP:    remoteIP,
	}
	s.sessions[nextNonce] = rotated
	return rotated, nil
}

// Delete removes a session — called on explicit logout or when the
// handshake is aborted.
func (s *SessionStore) Delete(serverNonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, serverNonce)
}

// Len returns the current session count. Primarily a test / debug
// observable.
func (s *SessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// sweepExpired removes all sessions whose LastSeen is older than
// idleTTL.
func (s *SessionStore) sweepExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()
	for k, v := range s.sessions {
		if now.Sub(v.LastSeen) > s.idleTTL {
			delete(s.sessions, k)
		}
	}
}

// newNonce produces a fresh 32-byte random nonce, base64-encoded so
// it fits in an HTTP header without escaping.
func (s *SessionStore) newNonce() (string, error) {
	buf := make([]byte, 32)
	if _, err := s.randReadFn(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// errSessionNotFound is returned by Rotate when the key is unknown or
// expired. Separate from generic errors so callers can translate it
// to HTTP 401 directly.
var errSessionNotFound = brcError("session not found or expired")

// brcError is a tiny string-backed error to keep the sentinel values
// above free of external dependencies.
type brcError string

func (e brcError) Error() string { return string(e) }
