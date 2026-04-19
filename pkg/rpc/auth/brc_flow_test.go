package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// testGovernanceChecker authorises any key in the seed list and
// rejects everything else.
type testGovernanceChecker struct {
	allowed [][]byte
}

func (t *testGovernanceChecker) IsGovernanceKey(pub []byte) bool {
	for _, a := range t.allowed {
		if bytes.Equal(a, pub) {
			return true
		}
	}
	return false
}

// newTestFlowConfig constructs a complete Config with a freshly
// minted server identity and a session store, governance-locked to
// the supplied client pubkey.
func newTestFlowConfig(t *testing.T, clientPub *ec.PublicKey) Config {
	t.Helper()
	srv, err := NewEphemeralServerIdentity()
	if err != nil {
		t.Fatalf("NewEphemeralServerIdentity: %v", err)
	}
	store := NewSessionStore()
	checker := &testGovernanceChecker{allowed: [][]byte{clientPub.Compressed()}}
	return Config{
		GovernanceChecker: checker,
		ServerIdentity:    srv,
		SessionStore:      store,
		ShardProvingMode:  mockMode,
	}
}

// performHandshake drives the client side of the BRC-103 handshake.
// Returns the session's server nonce plus the raw response — tests
// assert against both.
func performHandshake(t *testing.T, c Config, clientPub *ec.PublicKey) (string, handshakeResponse) {
	t.Helper()
	clientNonceBytes := sha256.Sum256([]byte("client-nonce-for-test"))
	clientNonceB64 := base64.StdEncoding.EncodeToString(clientNonceBytes[:])

	body, _ := json.Marshal(handshakeRequest{
		Version:      "0.1",
		MessageType:  "initialRequest",
		IdentityKey:  hex.EncodeToString(clientPub.Compressed()),
		InitialNonce: clientNonceB64,
	})
	req := httptest.NewRequest(http.MethodPost, "/.well-known/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	c.HandshakeHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handshake: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp handshakeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	return resp.Nonce, resp
}

func TestHandshake_UnknownGovernanceKeyRejected(t *testing.T) {
	// The server only accepts keys in its governance set. A stranger
	// must get 401.
	clientPriv, _ := ec.NewPrivateKey()
	stranger, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())

	body, _ := json.Marshal(handshakeRequest{
		Version:      "0.1",
		MessageType:  "initialRequest",
		IdentityKey:  hex.EncodeToString(stranger.PubKey().Compressed()),
		InitialNonce: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	req := httptest.NewRequest(http.MethodPost, "/.well-known/auth", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	c.HandshakeHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown key: expected 401, got %d", rec.Code)
	}
}

func TestHandshake_MethodRestrictedToPost(t *testing.T) {
	clientPriv, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())
	req := httptest.NewRequest(http.MethodGet, "/.well-known/auth", nil)
	rec := httptest.NewRecorder()
	c.HandshakeHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rec.Code)
	}
}

func TestHandshake_SignatureVerifiesAgainstServerIdentity(t *testing.T) {
	// The initialResponse must carry a signature that a client can
	// verify against the advertised server identity key — otherwise a
	// MITM attacker could impersonate the server.
	clientPriv, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())
	_, resp := performHandshake(t, c, clientPriv.PubKey())

	// Rebuild the digest the server signed.
	clientNonceBytes, _ := base64.StdEncoding.DecodeString(resp.YourNonce)
	serverNonceBytes, _ := base64.StdEncoding.DecodeString(resp.Nonce)
	clientIDBytes := clientPriv.PubKey().Compressed()
	serverIDBytes, _ := hex.DecodeString(resp.IdentityKey)

	buf := make([]byte, 0, 32+32+33+33)
	buf = append(buf, clientNonceBytes...)
	buf = append(buf, serverNonceBytes...)
	buf = append(buf, clientIDBytes...)
	buf = append(buf, serverIDBytes...)
	digest := sha256.Sum256(buf)

	sigBytes, err := hex.DecodeString(resp.Signature)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	sigObj, err := ec.ParseDERSignature(sigBytes)
	if err != nil {
		t.Fatalf("parsing server DER sig: %v", err)
	}
	serverPub, err := ec.PublicKeyFromString(resp.IdentityKey)
	if err != nil {
		t.Fatalf("parsing server pubkey: %v", err)
	}
	// Same caveat as brc104.go — Verify hashes the input again; pass
	// the digest through sig.Verify directly.
	if !sigObj.Verify(digest[:], serverPub) {
		t.Errorf("server signature does not verify against advertised identity key")
	}
}

// buildSignedAdminRequest walks through: (1) handshake, (2) build a
// BRC-104 signed request using the client private key.
func buildSignedAdminRequest(t *testing.T, c Config, clientPriv *ec.PrivateKey, body []byte) (*http.Request, string) {
	t.Helper()
	serverNonce, _ := performHandshake(t, c, clientPriv.PubKey())

	// Fresh request-id + client nonce.
	reqIDBytes := sha256.Sum256([]byte("req-id-seed"))
	reqIDb64 := base64.StdEncoding.EncodeToString(reqIDBytes[:])
	clientNonceB := sha256.Sum256([]byte("client-per-req-nonce"))
	clientNonceB64 := base64.StdEncoding.EncodeToString(clientNonceB[:])

	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(brc104.HeaderVersion, "0.1")
	req.Header.Set(brc104.HeaderMessageType, "general")
	req.Header.Set(brc104.HeaderIdentityKey, hex.EncodeToString(clientPriv.PubKey().Compressed()))
	req.Header.Set(brc104.HeaderNonce, clientNonceB64)
	req.Header.Set(brc104.HeaderYourNonce, serverNonce)
	req.Header.Set(brc104.HeaderRequestID, reqIDb64)

	// Sign the canonical payload.
	cloneReq := req.Clone(req.Context())
	cloneReq.Body = io.NopCloser(bytes.NewReader(body))
	payload, err := authpayload.FromHTTPRequest(reqIDBytes[:], cloneReq)
	if err != nil {
		t.Fatalf("authpayload.FromHTTPRequest: %v", err)
	}
	digest := sha256.Sum256(payload)
	sig, err := clientPriv.Sign(digest[:])
	if err != nil {
		t.Fatalf("client sign: %v", err)
	}
	req.Header.Set(brc104.HeaderSignature, hex.EncodeToString(sig.Serialize()))

	return req, serverNonce
}

func TestBRC104_AcceptsValidSignedRequest(t *testing.T) {
	clientPriv, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())
	req, _ := buildSignedAdminRequest(t, c, clientPriv, []byte(`{"jsonrpc":"2.0","method":"admin_getConfig","id":1}`))

	sess, err := c.Authorize(req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if sess.Kind != KindBRC100 {
		t.Errorf("expected KindBRC100, got %s", sess.Kind)
	}
	if sess.Identity != hex.EncodeToString(clientPriv.PubKey().Compressed()) {
		t.Errorf("session identity mismatch: got %s", sess.Identity)
	}
}

func TestBRC104_TamperedBodyRejected(t *testing.T) {
	clientPriv, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())
	body := []byte(`{"jsonrpc":"2.0","method":"admin_getConfig","id":1}`)
	req, _ := buildSignedAdminRequest(t, c, clientPriv, body)
	// Replace the body post-signature — the server must re-derive the
	// digest from the new bytes and detect the mismatch.
	tampered := []byte(`{"jsonrpc":"2.0","method":"admin_pauseProving","id":1}`)
	req.Body = io.NopCloser(bytes.NewReader(tampered))

	if _, err := c.Authorize(req); err != ErrUnauthorized {
		t.Errorf("tampered body: expected ErrUnauthorized, got %v", err)
	}
}

func TestBRC104_ReplayIsRejected(t *testing.T) {
	clientPriv, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())
	body := []byte(`{"jsonrpc":"2.0","method":"admin_getConfig","id":1}`)
	req, _ := buildSignedAdminRequest(t, c, clientPriv, body)

	// Capture the body bytes so both the first and second Authorize
	// see them (the middleware consumes r.Body).
	origBody, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(origBody))

	if _, err := c.Authorize(req); err != nil {
		t.Fatalf("first Authorize: %v", err)
	}

	// Second Authorize against the same yourNonce must fail — the
	// session has rotated.
	req2 := httptest.NewRequest(http.MethodPost, "/admin/rpc", bytes.NewReader(origBody))
	for k, vs := range req.Header {
		for _, v := range vs {
			req2.Header.Add(k, v)
		}
	}
	if _, err := c.Authorize(req2); err != ErrUnauthorized {
		t.Errorf("replay: expected ErrUnauthorized, got %v", err)
	}
}

func TestBRC104_WrongIdentityKeyRejected(t *testing.T) {
	clientPriv, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())
	body := []byte(`{"jsonrpc":"2.0"}`)
	req, _ := buildSignedAdminRequest(t, c, clientPriv, body)

	// Swap in a different identity key header while keeping the
	// signature intact — the server must refuse.
	stranger, _ := ec.NewPrivateKey()
	req.Header.Set(brc104.HeaderIdentityKey, hex.EncodeToString(stranger.PubKey().Compressed()))

	if _, err := c.Authorize(req); err != ErrUnauthorized {
		t.Errorf("identity spoof: expected ErrUnauthorized, got %v", err)
	}
}

func TestBRC104_MissingHeaderFallsThroughToUnauthorized(t *testing.T) {
	clientPriv, _ := ec.NewPrivateKey()
	c := newTestFlowConfig(t, clientPriv.PubKey())
	req := httptest.NewRequest(http.MethodPost, "/admin/rpc", nil)
	req.Header.Set(brc104.HeaderSignature, "partial")
	// Missing identity-key header — inconsistent partial BRC-104 set.
	if _, err := c.Authorize(req); err != ErrUnauthorized {
		t.Errorf("partial headers: expected ErrUnauthorized, got %v", err)
	}
}

func TestSessionStore_RotationInvalidatesOldKey(t *testing.T) {
	store := NewSessionStore()
	rec, err := store.Create("02aa", "clientNonce", "127.0.0.1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := store.Get(rec.ServerNonce); got == nil {
		t.Fatalf("Get after Create: expected record, got nil")
	}
	rotated, err := store.Rotate(rec.ServerNonce, "nextClientNonce", "127.0.0.1")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got := store.Get(rec.ServerNonce); got != nil {
		t.Errorf("old key must not resolve after rotation")
	}
	if got := store.Get(rotated.ServerNonce); got == nil {
		t.Errorf("new key must resolve after rotation")
	}
}

// Stop compiler complaining about imports used only in subtle paths.
var _ = strings.TrimSpace
