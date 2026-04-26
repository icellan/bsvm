// brc104.go: BRC-104 mutual-authentication primitives for ARC
// callbacks. BSV's BRC-104 specifies mutual authentication between a
// client and a server using BRC-3 (deterministic ECDSA over
// secp256k1) signatures over canonical request bytes, with replay
// protection via timestamps and nonces.
//
// In the ARC callback context the inbound (server → L2 node)
// signature is the load-bearing piece: the ARC server signs each
// callback with its registered identity key, and the L2 node verifies
// against the per-endpoint public key registered in the
// BRC104Verifier. Outbound response signing is supported via
// SignResponse for full-mutual deployments but is optional — many
// ARC operators only require the server-side signature.
package arc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	bsvmcrypto "github.com/icellan/bsvm/pkg/crypto"
)

// BRC-104 header names. We follow the BSV ecosystem convention of
// X-BSV-Auth-* prefixes; the value semantics are documented per-field
// below so an ARC operator can implement the signing side without
// reading our code.
const (
	// HeaderBRC104Identity is the hex-encoded 33-byte compressed
	// secp256k1 public key the ARC server claims as its identity.
	// Required.
	HeaderBRC104Identity = "X-BSV-Auth-Identity-Key"

	// HeaderBRC104Nonce is a per-callback random hex string supplied
	// by the ARC server. Used together with Timestamp to prevent
	// replay. Required.
	HeaderBRC104Nonce = "X-BSV-Auth-Nonce"

	// HeaderBRC104Timestamp is the ARC server's wall-clock time of
	// signature generation, formatted as Unix-millis decimal. The L2
	// node rejects callbacks where |now - timestamp| exceeds the
	// configured TimestampWindow. Required.
	HeaderBRC104Timestamp = "X-BSV-Auth-Timestamp"

	// HeaderBRC104Signature is the hex-encoded compact secp256k1
	// signature over the canonical request bytes. The signature
	// covers exactly the bytes returned by CanonicalCallbackBytes.
	// Required.
	HeaderBRC104Signature = "X-BSV-Auth-Signature"

	// HeaderBRC104Version pins the canonical-bytes / verification
	// algorithm version. Currently "1". Optional; defaults to "1".
	HeaderBRC104Version = "X-BSV-Auth-Version"
)

// BRC104CanonicalVersion is the only version of the canonical-bytes
// scheme this package recognises. Future protocol revisions should
// bump this constant and gate verification on the header value.
const BRC104CanonicalVersion = "1"

// Default replay-protection knobs. Operators can override either via
// BRC104Config when constructing a verifier.
const (
	// DefaultBRC104TimestampWindow is the maximum age of an accepted
	// callback timestamp. Spec 17 §"ARC callbacks are authenticated"
	// recommends a tight window; 60s leaves headroom for clock drift.
	DefaultBRC104TimestampWindow = 60 * time.Second

	// DefaultBRC104NonceCacheSize is the LRU bound for replay
	// suppression. ARC traffic per node is well below this volume,
	// so 8192 nonces (~256 KB) covers any realistic burst.
	DefaultBRC104NonceCacheSize = 8192
)

// BRC104Identity is a registered ARC server identity. The Name is
// purely cosmetic; PublicKey is the secp256k1 compressed key the
// server signs callbacks with. CompressedKey is preferred (33 bytes)
// but the verifier also accepts 65-byte uncompressed.
type BRC104Identity struct {
	Name      string
	PublicKey []byte
}

// BRC104Config configures a BRC104Verifier.
type BRC104Config struct {
	// Identities lists every ARC server identity the L2 node trusts.
	// At least one entry is required.
	Identities []BRC104Identity

	// TimestampWindow caps how old a callback timestamp may be.
	// Defaults to DefaultBRC104TimestampWindow when zero.
	TimestampWindow time.Duration

	// NonceCacheSize bounds the replay-suppression cache. Defaults
	// to DefaultBRC104NonceCacheSize when zero. Set negative to
	// disable replay caching (NOT recommended).
	NonceCacheSize int

	// Now overrides time.Now for tests. Production callers leave nil.
	Now func() time.Time
}

// BRC104Verifier authenticates ARC callbacks using BRC-104 mutual
// authentication. It is safe for concurrent use.
type BRC104Verifier struct {
	cfg        BRC104Config
	identities map[string]*BRC104Identity // key: hex(compressed pubkey)
	now        func() time.Time

	mu     sync.Mutex
	nonces map[string]time.Time
	order  []string
	cap    int
}

// NewBRC104Verifier constructs a BRC104Verifier. Returns an error if
// no identities are configured or any identity public key is
// malformed.
func NewBRC104Verifier(cfg BRC104Config) (*BRC104Verifier, error) {
	if len(cfg.Identities) == 0 {
		return nil, errors.New("arc: BRC-104 verifier requires at least one identity")
	}
	if cfg.TimestampWindow <= 0 {
		cfg.TimestampWindow = DefaultBRC104TimestampWindow
	}
	if cfg.NonceCacheSize == 0 {
		cfg.NonceCacheSize = DefaultBRC104NonceCacheSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	v := &BRC104Verifier{
		cfg:        cfg,
		identities: make(map[string]*BRC104Identity, len(cfg.Identities)),
		now:        cfg.Now,
		nonces:     make(map[string]time.Time),
		order:      make([]string, 0, 64),
		cap:        cfg.NonceCacheSize,
	}
	for i, id := range cfg.Identities {
		key, err := normalisePubKey(id.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("arc: identity %d (%s): %w", i, id.Name, err)
		}
		copyID := id
		copyID.PublicKey = key
		v.identities[hex.EncodeToString(key)] = &copyID
	}
	return v, nil
}

// CanonicalCallbackBytes returns the byte string an ARC server signs
// over for a callback. The format is documented as the BRC-104
// canonical form for ARC v1:
//
//	"BRC104-ARC-CALLBACK-v1\n" || timestampMillis || "\n" ||
//	    nonce || "\n" || sha256(body)
//
// Where:
//   - timestampMillis is the decimal Unix-millis timestamp.
//   - nonce is the hex-encoded random nonce string.
//   - body is the raw HTTP request body.
//
// All three header values MUST be the literal header strings the ARC
// server sent (no normalisation), so the verifier hashes byte-for-byte
// the same input the signer hashed.
func CanonicalCallbackBytes(timestamp, nonce string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	out := make([]byte, 0, 32+len(timestamp)+len(nonce)+len(bodyHash)*2+8)
	out = append(out, "BRC104-ARC-CALLBACK-v"...)
	out = append(out, BRC104CanonicalVersion...)
	out = append(out, '\n')
	out = append(out, timestamp...)
	out = append(out, '\n')
	out = append(out, nonce...)
	out = append(out, '\n')
	out = append(out, bodyHash[:]...)
	return out
}

// SignCallback produces the BRC-104 headers for a callback request.
// Useful for ARC simulators in tests and for operators implementing
// outbound response signing in mutual-auth-strict deployments. The
// returned map contains every header documented in the file-level
// HeaderBRC104* constants.
func SignCallback(priv *ecdsa.PrivateKey, body []byte, ts time.Time, nonce string) (map[string]string, error) {
	if priv == nil {
		return nil, errors.New("arc: BRC-104 sign: nil key")
	}
	if nonce == "" {
		return nil, errors.New("arc: BRC-104 sign: empty nonce")
	}
	timestamp := strconv.FormatInt(ts.UTC().UnixMilli(), 10)
	canonical := CanonicalCallbackBytes(timestamp, nonce, body)
	digest := sha256.Sum256(canonical)
	sig, err := bsvmcrypto.Sign(digest[:], priv)
	if err != nil {
		return nil, fmt.Errorf("arc: BRC-104 sign: %w", err)
	}
	pub := bsvmcrypto.CompressPubkey(&priv.PublicKey)
	if pub == nil {
		return nil, errors.New("arc: BRC-104 sign: compress pubkey failed")
	}
	// Strip the trailing recovery byte; verification uses [R||S] and
	// the registered public key directly.
	rawSig := sig[:64]
	return map[string]string{
		HeaderBRC104Identity:  hex.EncodeToString(pub),
		HeaderBRC104Nonce:     nonce,
		HeaderBRC104Timestamp: timestamp,
		HeaderBRC104Signature: hex.EncodeToString(rawSig),
		HeaderBRC104Version:   BRC104CanonicalVersion,
	}, nil
}

// CallbackAuthInputs is the per-request data the verifier needs.
// Callers (CallbackHandler.ServeHTTP) populate this from request
// headers + body before invoking VerifyCallback.
type CallbackAuthInputs struct {
	IdentityHex  string
	NonceHex     string
	TimestampStr string
	SignatureHex string
	VersionStr   string
	Body         []byte
}

// VerifyCallback authenticates a callback. Returns nil on success, or
// a structured error describing why verification failed (bad
// signature, expired timestamp, replayed nonce, unknown identity,
// version mismatch).
func (v *BRC104Verifier) VerifyCallback(in CallbackAuthInputs) (*BRC104Identity, error) {
	if in.IdentityHex == "" {
		return nil, ErrBRC104MissingIdentity
	}
	if in.NonceHex == "" {
		return nil, ErrBRC104MissingNonce
	}
	if in.TimestampStr == "" {
		return nil, ErrBRC104MissingTimestamp
	}
	if in.SignatureHex == "" {
		return nil, ErrBRC104MissingSignature
	}
	if in.VersionStr != "" && in.VersionStr != BRC104CanonicalVersion {
		return nil, fmt.Errorf("%w: %s", ErrBRC104UnsupportedVersion, in.VersionStr)
	}

	// 1. Identity must match a registered key. We compare on the
	//    decoded compressed-pubkey bytes after normalisation so a
	//    server that submits an uncompressed key still matches.
	rawID, err := hex.DecodeString(in.IdentityHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBRC104BadIdentity, err)
	}
	normID, err := normalisePubKey(rawID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBRC104BadIdentity, err)
	}
	id, ok := v.identities[hex.EncodeToString(normID)]
	if !ok {
		return nil, ErrBRC104UnknownIdentity
	}

	// 2. Timestamp window.
	ms, err := strconv.ParseInt(in.TimestampStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBRC104BadTimestamp, err)
	}
	ts := time.UnixMilli(ms).UTC()
	now := v.now().UTC()
	delta := now.Sub(ts)
	if delta < 0 {
		delta = -delta
	}
	if delta > v.cfg.TimestampWindow {
		return nil, fmt.Errorf("%w: |now-ts|=%s window=%s",
			ErrBRC104Expired, delta, v.cfg.TimestampWindow)
	}

	// 3. Nonce replay.
	if !v.acceptNonce(in.NonceHex, ts) {
		return nil, ErrBRC104NonceReplay
	}

	// 4. Signature verify.
	sig, err := hex.DecodeString(in.SignatureHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBRC104BadSignature, err)
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("%w: want 64 bytes, got %d", ErrBRC104BadSignature, len(sig))
	}
	canonical := CanonicalCallbackBytes(in.TimestampStr, in.NonceHex, in.Body)
	digest := sha256.Sum256(canonical)
	if !bsvmcrypto.VerifySignature(id.PublicKey, digest[:], sig) {
		return nil, ErrBRC104BadSignature
	}
	return id, nil
}

// acceptNonce returns true and records the nonce on first sight;
// false if the nonce was already seen within the cache window.
// Eviction is FIFO bounded by cap; expired entries (older than
// 2*TimestampWindow) are also pruned opportunistically on each call.
func (v *BRC104Verifier) acceptNonce(nonce string, ts time.Time) bool {
	if v.cap < 0 {
		return true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, seen := v.nonces[nonce]; seen {
		return false
	}
	// Opportunistic prune of expired entries.
	cutoff := v.now().Add(-2 * v.cfg.TimestampWindow)
	if len(v.order) > 0 {
		dropped := 0
		for dropped < len(v.order) {
			n := v.order[dropped]
			if t, ok := v.nonces[n]; ok && t.After(cutoff) {
				break
			}
			delete(v.nonces, n)
			dropped++
		}
		if dropped > 0 {
			v.order = append(v.order[:0], v.order[dropped:]...)
		}
	}
	if len(v.order) >= v.cap && v.cap > 0 {
		evict := v.order[0]
		v.order = v.order[1:]
		delete(v.nonces, evict)
	}
	v.nonces[nonce] = ts
	v.order = append(v.order, nonce)
	return true
}

// Errors returned by VerifyCallback. They unwrap to canonical
// ErrBRC104* sentinels so callers can switch on errors.Is.
var (
	// ErrBRC104MissingIdentity is returned when no identity header is set.
	ErrBRC104MissingIdentity = errors.New("arc: BRC-104 missing identity header")
	// ErrBRC104MissingNonce is returned when no nonce header is set.
	ErrBRC104MissingNonce = errors.New("arc: BRC-104 missing nonce header")
	// ErrBRC104MissingTimestamp is returned when no timestamp header is set.
	ErrBRC104MissingTimestamp = errors.New("arc: BRC-104 missing timestamp header")
	// ErrBRC104MissingSignature is returned when no signature header is set.
	ErrBRC104MissingSignature = errors.New("arc: BRC-104 missing signature header")
	// ErrBRC104UnsupportedVersion is returned when the version header
	// doesn't match BRC104CanonicalVersion.
	ErrBRC104UnsupportedVersion = errors.New("arc: BRC-104 unsupported version")
	// ErrBRC104BadIdentity is returned when the identity header is not
	// a valid hex pubkey.
	ErrBRC104BadIdentity = errors.New("arc: BRC-104 bad identity")
	// ErrBRC104UnknownIdentity is returned when the identity is not
	// in the configured trust list.
	ErrBRC104UnknownIdentity = errors.New("arc: BRC-104 unknown identity")
	// ErrBRC104BadTimestamp is returned when the timestamp header is
	// not a valid Unix-millis decimal.
	ErrBRC104BadTimestamp = errors.New("arc: BRC-104 bad timestamp")
	// ErrBRC104Expired is returned when the timestamp falls outside
	// the configured TimestampWindow.
	ErrBRC104Expired = errors.New("arc: BRC-104 timestamp expired")
	// ErrBRC104NonceReplay is returned when a nonce repeats within
	// the cache window.
	ErrBRC104NonceReplay = errors.New("arc: BRC-104 nonce replay")
	// ErrBRC104BadSignature is returned when the signature is
	// malformed or fails to verify against the canonical bytes under
	// the registered public key.
	ErrBRC104BadSignature = errors.New("arc: BRC-104 bad signature")
)

// normalisePubKey accepts a 33-byte compressed or 65-byte
// uncompressed secp256k1 public key and returns the compressed form.
// Other lengths return an error.
func normalisePubKey(in []byte) ([]byte, error) {
	switch len(in) {
	case 33:
		// Validate it parses; we don't need the parsed value beyond
		// the round-trip, since downstream verification re-parses.
		if _, err := bsvmcrypto.DecompressPubkey(in); err != nil {
			return nil, fmt.Errorf("invalid compressed pubkey: %w", err)
		}
		out := make([]byte, 33)
		copy(out, in)
		return out, nil
	case 65:
		if in[0] != 0x04 {
			return nil, fmt.Errorf("uncompressed pubkey must start with 0x04, got 0x%02x", in[0])
		}
		x := new(big.Int).SetBytes(in[1:33])
		y := new(big.Int).SetBytes(in[33:65])
		pub := &ecdsa.PublicKey{Curve: bsvmcrypto.S256(), X: x, Y: y}
		comp := bsvmcrypto.CompressPubkey(pub)
		if comp == nil {
			return nil, errors.New("compress failed")
		}
		// Round-trip to confirm the point is on-curve.
		if _, err := bsvmcrypto.DecompressPubkey(comp); err != nil {
			return nil, fmt.Errorf("invalid uncompressed pubkey: %w", err)
		}
		return comp, nil
	default:
		return nil, fmt.Errorf("unsupported pubkey length %d (want 33 or 65)", len(in))
	}
}
