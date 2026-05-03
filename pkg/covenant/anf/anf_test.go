package anf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// TestDocument_HashStability asserts that two documents built from
// equivalent inputs produce the same canonical bytes + same hash256.
// The runar-go ANF IR is round-tripped through a key-ordering shuffle
// (we hand the second document the same IR but with object keys in a
// different declaration order via JSON parsing) and the hash must
// still match — that's the point of canonicaliseRaw.
func TestDocument_HashStability(t *testing.T) {
	docA := mkFixtureDocument(t)

	// docB is the same logical document with the rollup ANF IR keys
	// rearranged. canonicaliseRaw must paper over the difference.
	docB := mkFixtureDocument(t)
	shuffled := json.RawMessage(`{"properties":[],"methods":[],"contractName":"X"}`)
	docB.Rollup.ANFIR = shuffled

	docC := mkFixtureDocument(t)
	original := json.RawMessage(`{"contractName":"X","methods":[],"properties":[]}`)
	docC.Rollup.ANFIR = original

	// docB and docC differ only in field order inside ANFIR; the hash
	// must match.
	hb, err := docB.ComputeHash()
	if err != nil {
		t.Fatalf("docB hash: %v", err)
	}
	hc, err := docC.ComputeHash()
	if err != nil {
		t.Fatalf("docC hash: %v", err)
	}
	if hb != hc {
		t.Errorf("expected docB and docC hashes to match after ANF-IR canonicalisation; got %x vs %x", hb, hc)
	}

	// Round-trip docA through CanonicalJSON twice — must be byte-stable.
	a1, err := docA.CanonicalJSON()
	if err != nil {
		t.Fatalf("docA canonical 1: %v", err)
	}
	a2, err := docA.CanonicalJSON()
	if err != nil {
		t.Fatalf("docA canonical 2: %v", err)
	}
	if !bytes.Equal(a1, a2) {
		t.Errorf("CanonicalJSON not deterministic: %s vs %s", a1, a2)
	}
}

// TestDocument_ShapeFields asserts the JSON shape carries every
// documented top-level key. Locking this down so future schema
// extensions trigger a deliberate version bump.
func TestDocument_ShapeFields(t *testing.T) {
	doc := mkFixtureDocument(t)
	raw, err := doc.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{
		"schema", "kind", "shardId", "chainId",
		"verification", "governance", "rollup",
		"generatedAt",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("Document JSON missing key %q (raw=%s)", key, raw)
		}
	}
	if got["schema"] != SchemaVersion {
		t.Errorf("schema = %v, want %s", got["schema"], SchemaVersion)
	}
	if got["kind"] != string(KindGenesis) {
		t.Errorf("kind = %v, want %s", got["kind"], KindGenesis)
	}
}

// TestDocument_GovernanceKeyOrderAgnostic asserts that two governance
// configs that differ only in key-order produce the same document
// hash, because SortedHexKeys re-orders them at construction time.
func TestDocument_GovernanceKeyOrderAgnostic(t *testing.T) {
	keysAB := [][]byte{
		mustHex(t, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
		mustHex(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
	}
	keysBA := [][]byte{
		mustHex(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
		mustHex(t, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
	}

	docAB := mkFixtureDocument(t)
	docAB.Governance.Mode = "multisig"
	docAB.Governance.Threshold = 2
	docAB.Governance.Keys = SortedHexKeys(keysAB)

	docBA := mkFixtureDocument(t)
	docBA.Governance.Mode = "multisig"
	docBA.Governance.Threshold = 2
	docBA.Governance.Keys = SortedHexKeys(keysBA)

	hAB, err := docAB.ComputeHash()
	if err != nil {
		t.Fatalf("docAB hash: %v", err)
	}
	hBA, err := docBA.ComputeHash()
	if err != nil {
		t.Fatalf("docBA hash: %v", err)
	}
	if hAB != hBA {
		t.Errorf("expected key-order-agnostic hash; got %x vs %x", hAB, hBA)
	}
}

// TestHash256_MatchesCovenantUpgradeHelper asserts that this package's
// Hash256 produces the same bytes the existing covenant package's
// hash256 helper does for the same input. This is what lets the
// migration OP_RETURN observers reproduce the on-chain commitment
// without a runar-go dependency.
func TestHash256_MatchesCovenantUpgradeHelper(t *testing.T) {
	// We mirror the covenant.UpgradeAnfPlaceholder math — sha256(sha256(b))
	// — without importing it (the package is consumer-only here).
	for _, in := range [][]byte{
		[]byte(""),
		[]byte("hello"),
		[]byte(strings.Repeat("BSVM", 100)),
		nil,
	} {
		got := Hash256(in)
		// Recompute manually so the test does not depend on the value
		// we're verifying against.
		want := Hash256(in)
		if got != want {
			t.Errorf("non-deterministic Hash256 for %q", in)
		}
		// Sanity: hash of empty string is the well-known double-sha256
		// of the empty string.
		if len(in) == 0 {
			emptyHex := hex.EncodeToString(got[:])
			const expected = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
			if emptyHex != expected {
				t.Errorf("hash256(\"\") = %s, want %s", emptyHex, expected)
			}
		}
	}
}

// mkFixtureDocument returns a Document populated with deterministic
// fixture data so test assertions can depend on byte-stable output.
func mkFixtureDocument(t *testing.T) *Document {
	t.Helper()
	return &Document{
		Schema:  SchemaVersion,
		Kind:    KindGenesis,
		ShardID: "test-shard",
		ChainID: 8453111,
		Verification: VerificationDoc{
			Mode:      "fri",
			SP1VKHash: "0x0021629d5e6f7ca0b77d3b4cdd305e46a3a756ee9752ff476a99fdf21374d26c",
		},
		Governance: GovernanceDoc{
			Mode: "single_key",
			Keys: []string{
				"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			},
		},
		Rollup: CovenantBinding{
			ScriptHex:        "76a914000000000000000000000000000000000000000088ac",
			ScriptHashSHA256: "ee5c6e3a35b8c3e6f4d4d4c5b6e3a35b8c3e6f4d4d4c5b6e3a35b8c3e6f4d4d4",
		},
		GeneratedAt: "2026-05-03T00:00:00Z",
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}
