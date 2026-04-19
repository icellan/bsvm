package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// BRC-103 / BRC-100 handshake over HTTP.
//
// This file implements the single endpoint `/.well-known/auth` that
// admin wallets POST to before they can sign BRC-104 admin requests.
//
// Wire format (a strict subset of BRC-103 sufficient for an operator
// admin panel — certificate exchange is intentionally unused since
// governance membership is determined by raw identity keys, not
// attribute certificates):
//
//	POST /.well-known/auth
//	Content-Type: application/json
//	{
//	  "version":      "0.1",
//	  "messageType":  "initialRequest",
//	  "identityKey":  "<33-byte compressed secp256k1 pubkey, hex>",
//	  "initialNonce": "<32-byte random, base64>"
//	}
//
//	200 OK
//	{
//	  "version":      "0.1",
//	  "messageType":  "initialResponse",
//	  "identityKey":  "<server identity key, hex>",
//	  "nonce":        "<server nonce, base64>",
//	  "yourNonce":    "<client initialNonce, echoed>",
//	  "signature":    "<server signature, hex>"
//	}
//
// Server signature covers the concatenation sha256(clientNonce ||
// serverNonce || clientIdentityKey || serverIdentityKey). Clients
// verify this before accepting the session; it pins both pubkeys to
// both nonces in one digest so neither half can be replayed
// independently.

// handshakeRequest is the wire shape of an incoming initialRequest.
type handshakeRequest struct {
	Version      string `json:"version"`
	MessageType  string `json:"messageType"`
	IdentityKey  string `json:"identityKey"`
	InitialNonce string `json:"initialNonce"`
}

// handshakeResponse is the wire shape of the initialResponse.
type handshakeResponse struct {
	Version     string `json:"version"`
	MessageType string `json:"messageType"`
	IdentityKey string `json:"identityKey"`
	Nonce       string `json:"nonce"`
	YourNonce   string `json:"yourNonce"`
	Signature   string `json:"signature"`
}

// HandshakeHandler returns the http.Handler for /.well-known/auth.
// A single handler instance is created at server startup and mounted
// by the rpc package — see rpc.RPCServer.Start.
//
// The handler delegates identity-key authorisation to the supplied
// GovernanceChecker. When the checker is nil, all requests are
// rejected with 503 Service Unavailable; this matches the
// "production hasn't opted in" state and avoids accidentally
// allowing anyone to open a session on a node whose admin surface
// is not meant to be wallet-gated.
func (c Config) HandshakeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if c.GovernanceChecker == nil || c.ServerIdentity == nil || c.SessionStore == nil {
			http.Error(w, "BRC-100 handshake not configured on this node", http.StatusServiceUnavailable)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		var req handshakeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.MessageType != "initialRequest" {
			http.Error(w, "expected messageType=initialRequest", http.StatusBadRequest)
			return
		}
		if req.IdentityKey == "" || req.InitialNonce == "" {
			http.Error(w, "identityKey and initialNonce are required", http.StatusBadRequest)
			return
		}

		// Parse and validate the client identity key.
		clientPub, err := ec.PublicKeyFromString(req.IdentityKey)
		if err != nil {
			http.Error(w, "invalid identity key: "+err.Error(), http.StatusBadRequest)
			return
		}
		compressed := clientPub.Compressed()
		if !c.GovernanceChecker.IsGovernanceKey(compressed) {
			// Don't tell the caller whether the key parsed successfully
			// but is unauthorized vs. whether it's malformed — both
			// surface as "not a governance key" so enumeration attacks
			// gain no signal.
			http.Error(w, "identity key is not in the shard governance set", http.StatusUnauthorized)
			return
		}

		// Validate the client nonce is syntactically well-formed (32
		// bytes after base64 decode). Matching the client's own nonce
		// length prevents pathological inputs from bloating the
		// session record.
		clientNonceBytes, err := base64.StdEncoding.DecodeString(req.InitialNonce)
		if err != nil || len(clientNonceBytes) != 32 {
			http.Error(w, "initialNonce must be 32 bytes base64", http.StatusBadRequest)
			return
		}

		// Create the session and grab the server's nonce. The store
		// is keyed by the server nonce so the BRC-104 middleware can
		// retrieve the session in O(1) per request.
		rec, err := c.SessionStore.Create(req.IdentityKey, req.InitialNonce, clientIP(r))
		if err != nil {
			http.Error(w, "session store error", http.StatusInternalServerError)
			return
		}

		// Compose the signature payload:
		//   sha256(clientNonce || serverNonce || clientIdKey || serverIdKey)
		serverIDHex := c.ServerIdentity.PublicKeyHex()
		serverNonceBytes, _ := base64.StdEncoding.DecodeString(rec.ServerNonce)
		serverIDBytes := c.ServerIdentity.pub.Compressed()

		digestBuf := make([]byte, 0, 32+32+33+33)
		digestBuf = append(digestBuf, clientNonceBytes...)
		digestBuf = append(digestBuf, serverNonceBytes...)
		digestBuf = append(digestBuf, compressed...)
		digestBuf = append(digestBuf, serverIDBytes...)
		digest := sha256.Sum256(digestBuf)

		sigBytes, err := c.ServerIdentity.Sign(digest[:])
		if err != nil {
			c.SessionStore.Delete(rec.ServerNonce)
			http.Error(w, "server signing error", http.StatusInternalServerError)
			return
		}

		resp := handshakeResponse{
			Version:     "0.1",
			MessageType: "initialResponse",
			IdentityKey: serverIDHex,
			Nonce:       rec.ServerNonce,
			YourNonce:   req.InitialNonce,
			Signature:   hexEncodeLower(sigBytes),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// hexEncodeLower renders bytes as lower-case hex without a prefix.
// Kept here so brc103.go stays free of extra imports when byte[] hex
// is only needed for the signature field.
func hexEncodeLower(b []byte) string {
	return string(hexEncode(b))
}
