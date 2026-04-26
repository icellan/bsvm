package arc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bsvmcrypto "github.com/icellan/bsvm/pkg/crypto"
)

func mustGenKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := bsvmcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := bsvmcrypto.CompressPubkey(&k.PublicKey)
	if pub == nil {
		t.Fatalf("CompressPubkey: nil")
	}
	return k, pub
}

func freshNonce(t *testing.T) string {
	t.Helper()
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(buf[:])
}

func TestBRC104VerifyOK(t *testing.T) {
	k, pub := mustGenKey(t)
	v, err := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc-1", PublicKey: pub}},
	})
	if err != nil {
		t.Fatalf("NewBRC104Verifier: %v", err)
	}
	body := []byte(`{"txid":"deadbeef"}`)
	headers, err := SignCallback(k, body, time.Now(), freshNonce(t))
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	id, err := v.VerifyCallback(CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: headers[HeaderBRC104Signature],
		VersionStr:   headers[HeaderBRC104Version],
		Body:         body,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id == nil || id.Name != "arc-1" {
		t.Fatalf("bad identity %+v", id)
	}
}

func TestBRC104VerifyExpired(t *testing.T) {
	k, pub := mustGenKey(t)
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities:      []BRC104Identity{{Name: "arc", PublicKey: pub}},
		TimestampWindow: 5 * time.Second,
	})
	body := []byte(`{}`)
	headers, _ := SignCallback(k, body, time.Now().Add(-2*time.Minute), freshNonce(t))
	_, err := v.VerifyCallback(CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: headers[HeaderBRC104Signature],
		VersionStr:   headers[HeaderBRC104Version],
		Body:         body,
	})
	if !errors.Is(err, ErrBRC104Expired) {
		t.Fatalf("want expired, got %v", err)
	}
}

func TestBRC104VerifyReplay(t *testing.T) {
	k, pub := mustGenKey(t)
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc", PublicKey: pub}},
	})
	body := []byte(`{}`)
	nonce := freshNonce(t)
	headers, _ := SignCallback(k, body, time.Now(), nonce)
	in := CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: headers[HeaderBRC104Signature],
		VersionStr:   headers[HeaderBRC104Version],
		Body:         body,
	}
	if _, err := v.VerifyCallback(in); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := v.VerifyCallback(in)
	if !errors.Is(err, ErrBRC104NonceReplay) {
		t.Fatalf("want replay, got %v", err)
	}
}

func TestBRC104VerifyBadSig(t *testing.T) {
	k, pub := mustGenKey(t)
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc", PublicKey: pub}},
	})
	body := []byte(`{"a":1}`)
	headers, _ := SignCallback(k, body, time.Now(), freshNonce(t))
	// Tamper the signature.
	tampered := []byte(headers[HeaderBRC104Signature])
	tampered[0] ^= 0x01
	_, err := v.VerifyCallback(CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: string(tampered),
		Body:         body,
	})
	if !errors.Is(err, ErrBRC104BadSignature) {
		t.Fatalf("want bad sig, got %v", err)
	}
}

func TestBRC104VerifyBadBody(t *testing.T) {
	k, pub := mustGenKey(t)
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc", PublicKey: pub}},
	})
	body := []byte(`{"a":1}`)
	headers, _ := SignCallback(k, body, time.Now(), freshNonce(t))
	// Verify with a different body.
	_, err := v.VerifyCallback(CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: headers[HeaderBRC104Signature],
		Body:         []byte(`{"a":2}`),
	})
	if !errors.Is(err, ErrBRC104BadSignature) {
		t.Fatalf("want bad sig (body tamper), got %v", err)
	}
}

func TestBRC104VerifyUnknownIdentity(t *testing.T) {
	k, _ := mustGenKey(t)
	_, otherPub := mustGenKey(t) // different key
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "trusted", PublicKey: otherPub}},
	})
	body := []byte(`{}`)
	headers, _ := SignCallback(k, body, time.Now(), freshNonce(t))
	_, err := v.VerifyCallback(CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: headers[HeaderBRC104Signature],
		Body:         body,
	})
	if !errors.Is(err, ErrBRC104UnknownIdentity) {
		t.Fatalf("want unknown identity, got %v", err)
	}
}

func TestBRC104VerifyMissingHeaders(t *testing.T) {
	_, pub := mustGenKey(t)
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc", PublicKey: pub}},
	})
	cases := []struct {
		name string
		in   CallbackAuthInputs
		want error
	}{
		{"no identity", CallbackAuthInputs{}, ErrBRC104MissingIdentity},
		{"no nonce", CallbackAuthInputs{IdentityHex: "00"}, ErrBRC104MissingNonce},
		{"no ts", CallbackAuthInputs{IdentityHex: "00", NonceHex: "1"}, ErrBRC104MissingTimestamp},
		{"no sig", CallbackAuthInputs{IdentityHex: "00", NonceHex: "1", TimestampStr: "1"}, ErrBRC104MissingSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.VerifyCallback(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestBRC104VerifyBadVersion(t *testing.T) {
	k, pub := mustGenKey(t)
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc", PublicKey: pub}},
	})
	body := []byte(`{}`)
	headers, _ := SignCallback(k, body, time.Now(), freshNonce(t))
	_, err := v.VerifyCallback(CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: headers[HeaderBRC104Signature],
		VersionStr:   "99",
		Body:         body,
	})
	if !errors.Is(err, ErrBRC104UnsupportedVersion) {
		t.Fatalf("want unsupported version, got %v", err)
	}
}

func TestBRC104VerifierConfigErrors(t *testing.T) {
	if _, err := NewBRC104Verifier(BRC104Config{}); err == nil {
		t.Fatalf("expected error: no identities")
	}
	if _, err := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "x", PublicKey: []byte{0x00, 0x01}}},
	}); err == nil {
		t.Fatalf("expected error: bad pubkey length")
	}
}

// TestCallbackHandlerBRC104Integration drives the full HTTP handler
// path with httptest, simulating an ARC server signing each callback.
func TestCallbackHandlerBRC104Integration(t *testing.T) {
	k, pub := mustGenKey(t)
	v, err := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc-prod", PublicKey: pub}},
	})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	var seen []*CallbackEvent
	h, err := NewBRC104CallbackHandler(v, nil, false, func(ev *CallbackEvent) {
		seen = append(seen, ev)
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := []byte(`{"txid":"` + strings.Repeat("aa", 32) + `","txStatus":"MINED","blockHeight":7}`)

	// Valid signed callback → 204.
	headers, _ := SignCallback(k, body, time.Now(), freshNonce(t))
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("good req: status %d", resp.StatusCode)
	}
	if len(seen) != 1 {
		t.Fatalf("seen %d events", len(seen))
	}

	// Missing BRC-104 headers → 401.
	req, _ = http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing headers: status %d", resp.StatusCode)
	}

	// Tampered body → 401.
	headers, _ = SignCallback(k, body, time.Now(), freshNonce(t))
	req, _ = http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader([]byte(`{"txid":"deadbeef"}`)))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered body: status %d", resp.StatusCode)
	}
}

func TestCallbackHandlerBRC104MigrationMode(t *testing.T) {
	k, pub := mustGenKey(t)
	v, _ := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "arc", PublicKey: pub}},
	})
	h, err := NewBRC104CallbackHandler(v, []string{"legacy"}, true, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := []byte(`{"txid":"` + strings.Repeat("aa", 32) + `","txStatus":"SEEN_ON_NETWORK"}`)

	// Legacy token alone — accepted because allowToken=true.
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("X-CallbackToken", "legacy")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("legacy token: %d", resp.StatusCode)
	}

	// Legacy with bad token → 401.
	req, _ = http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("X-CallbackToken", "wrong")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad legacy: %d", resp.StatusCode)
	}

	// BRC-104 path takes precedence; if BRC-104 headers present, they
	// must verify even if a legacy token is also present.
	headers, _ := SignCallback(k, body, time.Now(), freshNonce(t))
	headers[HeaderBRC104Signature] = "00" + headers[HeaderBRC104Signature][2:] // tamper
	req, _ = http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("X-CallbackToken", "legacy")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("brc-104 must not be downgradable, got %d", resp.StatusCode)
	}
}

func TestBRC104UncompressedPubkey(t *testing.T) {
	k, _ := mustGenKey(t)
	// Build uncompressed (65-byte) pubkey from the same key.
	xb := k.PublicKey.X.Bytes()
	yb := k.PublicKey.Y.Bytes()
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1+32-len(xb):33], xb)
	copy(uncompressed[33+32-len(yb):65], yb)
	v, err := NewBRC104Verifier(BRC104Config{
		Identities: []BRC104Identity{{Name: "u", PublicKey: uncompressed}},
	})
	if err != nil {
		t.Fatalf("uncompressed identity should be accepted: %v", err)
	}
	body := []byte(`x`)
	headers, _ := SignCallback(k, body, time.Now(), freshNonce(t))
	_, err = v.VerifyCallback(CallbackAuthInputs{
		IdentityHex:  headers[HeaderBRC104Identity],
		NonceHex:     headers[HeaderBRC104Nonce],
		TimestampStr: headers[HeaderBRC104Timestamp],
		SignatureHex: headers[HeaderBRC104Signature],
		Body:         body,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestBRC104CanonicalBytesStable pins the canonical-bytes format so a
// future change to formatting is caught by tests.
func TestBRC104CanonicalBytesStable(t *testing.T) {
	got := CanonicalCallbackBytes("123456", "abcdef", []byte("hello"))
	prefix := []byte("BRC104-ARC-CALLBACK-v1\n123456\nabcdef\n")
	if !bytes.HasPrefix(got, prefix) {
		t.Fatalf("canonical prefix mismatch:\n got %q\nwant %q", got[:len(prefix)], prefix)
	}
	if len(got) != len(prefix)+32 {
		t.Fatalf("canonical len = %d want %d", len(got), len(prefix)+32)
	}
}

// Sanity-check the wire format example so the spec note in brc104.go
// matches reality.
func TestBRC104CanonicalBytesExample(t *testing.T) {
	out := CanonicalCallbackBytes("0", "n", []byte{})
	if !strings.HasPrefix(string(out), fmt.Sprintf("BRC104-ARC-CALLBACK-v%s\n0\nn\n", BRC104CanonicalVersion)) {
		t.Fatalf("bad prefix: %q", out)
	}
}
