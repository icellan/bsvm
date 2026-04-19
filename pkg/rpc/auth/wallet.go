package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ServerIdentity wraps the persistent secp256k1 identity key the
// BSVM admin server uses for BRC-103 handshakes and BRC-104 response
// signing. The private key is generated on first use and stored as
// hex at `<datadir>/admin_identity.hex` with 0600 permissions. On
// subsequent startups the file is loaded verbatim — operators who
// rotate the key simply delete the file.
//
// The identity is scoped to admin auth. It is NOT the shard
// governance key (which lives on an operator wallet) and NOT a
// prover-level key. Keeping it scoped means a compromise of the
// admin identity affects only active admin sessions, not covenant
// spending authority.
type ServerIdentity struct {
	priv *ec.PrivateKey
	pub  *ec.PublicKey
}

// LoadOrCreateServerIdentity returns the server's admin identity,
// reading it from `<dir>/admin_identity.hex` when present and
// generating+persisting a fresh key when not.
func LoadOrCreateServerIdentity(dir string) (*ServerIdentity, error) {
	if dir == "" {
		return nil, fmt.Errorf("server identity directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating identity dir: %w", err)
	}

	path := filepath.Join(dir, "admin_identity.hex")
	raw, err := os.ReadFile(path)
	if err == nil {
		priv, err := ec.PrivateKeyFromHex(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		return &ServerIdentity{priv: priv, pub: priv.PubKey()}, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	// First-time generation.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generating identity key: %w", err)
	}
	hexKey := hex.EncodeToString(buf)
	priv, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		return nil, fmt.Errorf("loading generated key: %w", err)
	}
	// 0600 because this key signs admin responses; leaking it lets an
	// attacker impersonate the server to an authenticated wallet.
	if err := os.WriteFile(path, []byte(hexKey), 0o600); err != nil {
		return nil, fmt.Errorf("persisting identity key to %s: %w", path, err)
	}
	return &ServerIdentity{priv: priv, pub: priv.PubKey()}, nil
}

// NewEphemeralServerIdentity returns a server identity backed by a
// freshly generated key that is NOT persisted. Used in tests to
// avoid touching the filesystem.
func NewEphemeralServerIdentity() (*ServerIdentity, error) {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return &ServerIdentity{priv: priv, pub: priv.PubKey()}, nil
}

// PublicKeyHex returns the compressed secp256k1 public key in
// lower-case hex (33 bytes → 66 chars). Matches the hex encoding
// BRC-103 clients expect in the `identityKey` field of the
// handshake envelope.
func (s *ServerIdentity) PublicKeyHex() string {
	return hex.EncodeToString(s.pub.Compressed())
}

// Sign signs the given digest with the server identity key. The
// returned bytes are the DER-encoded ECDSA signature — the same
// format BRC-3 verification expects.
func (s *ServerIdentity) Sign(digest []byte) ([]byte, error) {
	sig, err := s.priv.Sign(digest)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

// PrivateKey exposes the raw key for callers that need the go-sdk
// wallet adapter (BRC-100 certificate exchange, future). Guarded by
// this helper so the field itself can stay unexported.
func (s *ServerIdentity) PrivateKey() *ec.PrivateKey {
	return s.priv
}
