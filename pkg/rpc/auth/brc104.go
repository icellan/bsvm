package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// BRC-104 request signing — server-side verification.
//
// Signed admin requests MUST carry these headers:
//
//	x-bsv-auth-version        0.1
//	x-bsv-auth-message-type   general
//	x-bsv-auth-identity-key   <hex compressed secp256k1>
//	x-bsv-auth-nonce          <base64 client request nonce, 32 bytes>
//	x-bsv-auth-your-nonce     <base64 server session nonce from handshake>
//	x-bsv-auth-request-id     <base64 32 random bytes>
//	x-bsv-auth-signature      <hex ECDSA signature>
//
// The signature covers sha256(authpayload.FromHTTPRequest(requestID, req))
// — the canonical serialisation defined by the go-sdk that includes
// the method, path, query, headers, and body.
//
// On a valid request the server rotates its own nonce (delete old
// session key, issue a fresh one keyed by the new server nonce) and
// returns the new server nonce in `x-bsv-auth-nonce` so the client
// can chain subsequent requests. The old server nonce is invalid
// after the first successful request; replays are rejected.

// tryBRC104 handles the signed-request path. The flow:
//
//  1. Require every BRC-104 header; if any is missing signal that
//     this request doesn't use BRC-104 so Authorize can fall through
//     to the BRC-100 handshake stub / dev-bypass / unauthorized.
//  2. Look up the session by `x-bsv-auth-your-nonce`.
//  3. Validate the identity key matches the session owner.
//  4. Re-derive the canonical payload and verify the signature.
//  5. Rotate the server nonce and stash the new one on the request
//     context so the handler can put it in a response header.
//
// Replay protection comes from rotating the server nonce on every
// request; a replayed request carries an already-invalidated
// yourNonce and gets rejected at step (2).
func (c Config) tryBRC104(r *http.Request) (*Session, bool, error) {
	sig := r.Header.Get(brc104.HeaderSignature)
	identityHex := r.Header.Get(brc104.HeaderIdentityKey)
	if sig == "" && identityHex == "" {
		return nil, false, nil
	}
	if c.SessionStore == nil || c.ServerIdentity == nil {
		return nil, true, errors.New("BRC-100 wallet authentication is not configured on this node")
	}
	// After this point any missing piece is an authentication failure
	// (the caller gave us half the headers).

	yourNonce := r.Header.Get(brc104.HeaderYourNonce)
	nonce := r.Header.Get(brc104.HeaderNonce)
	reqIDb64 := r.Header.Get(brc104.HeaderRequestID)
	if sig == "" || identityHex == "" || yourNonce == "" || nonce == "" || reqIDb64 == "" {
		return nil, true, ErrUnauthorized
	}

	rec := c.SessionStore.Get(yourNonce)
	if rec == nil {
		return nil, true, ErrUnauthorized
	}
	if rec.IdentityKey != identityHex {
		return nil, true, ErrUnauthorized
	}

	reqIDBytes, err := base64.StdEncoding.DecodeString(reqIDb64)
	if err != nil || len(reqIDBytes) != brc104.RequestIDLength {
		return nil, true, ErrUnauthorized
	}

	// authpayload.FromHTTPRequest reads r.Body; re-populate it
	// afterwards so downstream handlers see the original body bytes.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, true, ErrUnauthorized
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// FromHTTPRequest consumes the body too; give it a fresh reader
	// that leaves our captured bytes untouched.
	cloneReq := r.Clone(r.Context())
	cloneReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	payload, err := authpayload.FromHTTPRequest(reqIDBytes, cloneReq)
	if err != nil {
		return nil, true, ErrUnauthorized
	}

	digest := sha256.Sum256(payload)
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return nil, true, ErrUnauthorized
	}
	sigObj, err := ec.ParseDERSignature(sigBytes)
	if err != nil {
		return nil, true, ErrUnauthorized
	}
	clientPub, err := ec.PublicKeyFromString(identityHex)
	if err != nil {
		return nil, true, ErrUnauthorized
	}
	// Use sig.Verify(digest, pub) — clientPub.Verify would apply
	// another sha256 on top of our already-hashed digest, causing
	// valid signatures to reject.
	if !sigObj.Verify(digest[:], clientPub) {
		return nil, true, ErrUnauthorized
	}

	// Signature good — rotate the server nonce. The rotated record is
	// keyed by the new nonce; the client must use it on the next
	// request.
	rotated, err := c.SessionStore.Rotate(yourNonce, nonce, clientIP(r))
	if err != nil {
		return nil, true, ErrUnauthorized
	}
	sess := &Session{
		Kind:      KindBRC100,
		Identity:  rec.IdentityKey,
		RemoteIP:  clientIP(r),
		UserAgent: r.UserAgent(),
	}
	// Attach the rotated server nonce so the admin handler can echo
	// it in the response headers.
	ctx := withRotatedNonce(r.Context(), rotated.ServerNonce)
	*r = *r.WithContext(ctx)
	return sess, true, nil
}

// ---- Response rotation helpers -------------------------------------

type rotatedNonceKey struct{}

func withRotatedNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, rotatedNonceKey{}, nonce)
}

// RotatedServerNonce returns the fresh server nonce produced by the
// most recent successful BRC-104 verification, if any. Admin HTTP
// handlers call this just before writing their response so the
// client sees the new nonce to use on its next request.
func RotatedServerNonce(ctx context.Context) string {
	if v, ok := ctx.Value(rotatedNonceKey{}).(string); ok {
		return v
	}
	return ""
}
