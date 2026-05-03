// Package anf builds the canonical Atomic Network Format (ANF)
// inscription document that BSVM publishes alongside every covenant
// genesis and rotation. Spec 10 §"Migration OP_RETURN" mandates that
// every advance / upgrade bind the new covenant identity into a
// published ANF JSON document inscribed on BSV (BRC-100/BRC-62 style)
// so that any observer can fetch it via a BSV indexer and verify the
// hash matches the on-chain commitment in pv[240..272).
//
// The ANF document is the audit-grade bundle: script bytes, runar-go
// ANF IR (when available), governance config, chain id, verification
// mode, SP1 verifying-key hash, and a small envelope of metadata. The
// canonical hash is BSV's hash256 (sha256(sha256(json))) over the
// JSON-Marshal output produced with deterministic key ordering.
//
// TODO(WW-anf-runar): runar-go does not yet publish a first-class ANF
// inscription emitter. When upstream lands a `runar.PublishANF` /
// `runar.ANFInscriptionPayload` API, replace BuildDocument's body with
// a thin wrapper that delegates to it. Until then this package is the
// authoritative ANF emitter for BSVM. The Document shape is stable
// (version-tagged) so replaying older ANFs from BSV continues to verify
// against on-chain commitments after the upstream wiring lands.
package anf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// SchemaVersion is the on-disk schema tag baked into every ANF
// document. Bump only on a breaking shape change; observers parse
// against the version they understand.
const SchemaVersion = "bsvm.anf/1"

// Kind discriminates the document subtype. ANF documents accompany
// either a covenant genesis or a covenant rotation; the on-chain
// commitment shape is identical (a 32-byte hash256) so the kind tag
// is purely descriptive.
type Kind string

const (
	// KindGenesis marks an ANF emitted alongside the first genesis
	// transaction for a shard. Carries the full bridge + rollup script
	// pair (the deploy tool publishes both at once).
	KindGenesis Kind = "genesis"

	// KindRotation marks an ANF emitted alongside a covenant upgrade
	// (rotate-vk). Carries only the new rollup script — the bridge is
	// deliberately not auto-rotated; see deploy/covenant/rotate-vk.go's
	// package doc for the rationale.
	KindRotation Kind = "rotation"
)

// VerificationDoc captures the verification-mode binding the document
// records. The Mode string mirrors the operator config alphabet
// ("fri" | "groth16" | "groth16-wa" | "devkey").
type VerificationDoc struct {
	Mode       string `json:"mode"`
	SP1VKHash  string `json:"sp1VkHash"`            // hex, 0x-prefixed
	SP1VKBytes string `json:"sp1VkBytes,omitempty"` // hex, optional raw VK pre-image
}

// GovernanceDoc captures the governance binding the document records.
// Mode mirrors the on-chain GovernanceMode string ("none" | "single_key"
// | "multisig"). Keys are hex-encoded compressed pubkeys, sorted lex
// so the canonical form is independent of operator key-order.
type GovernanceDoc struct {
	Mode      string   `json:"mode"`
	Threshold int      `json:"threshold,omitempty"`
	Keys      []string `json:"keys,omitempty"`
}

// CovenantBinding records the locking-script and ANF-IR pair for one
// covenant in the document. RollupScript is required; BridgeScript is
// populated only on KindGenesis. ANFIR is optional — the runar-go
// compiler emits it for stateful contracts but a future template that
// disables ANF emission can still produce a valid Document.
type CovenantBinding struct {
	// ScriptHex is the locking script bytes, lower-case hex, no prefix.
	ScriptHex string `json:"scriptHex"`
	// ScriptHashSHA256 is the single sha256 of the script bytes, lower-
	// case hex. Useful for cross-checking against the on-chain
	// rollupScriptHash field in summaries.
	ScriptHashSHA256 string `json:"scriptHashSha256"`
	// ANFIR is the runar-go ANFProgram serialised as JSON, if available.
	// Stored as json.RawMessage so the canonical document round-trips
	// the upstream shape unchanged.
	ANFIR json.RawMessage `json:"anfIR,omitempty"`
}

// Document is the canonical ANF inscription payload. Marshal it via
// CanonicalJSON (or call ComputeHash) — DO NOT call json.Marshal on
// it directly when you need a hash-stable form, because Go's default
// emitter does not guarantee key ordering across versions for
// json.RawMessage embedded objects.
type Document struct {
	// Schema is the version tag — always SchemaVersion. Lets observers
	// reject documents minted under an incompatible shape.
	Schema string `json:"schema"`
	// Kind is "genesis" or "rotation". Descriptive only — the on-chain
	// commitment ignores this field.
	Kind Kind `json:"kind"`
	// ShardID is the operator-supplied human label.
	ShardID string `json:"shardId"`
	// ChainID is the EIP-155 chain identifier.
	ChainID uint64 `json:"chainId"`
	// Verification carries the SP1 VK hash + verification mode binding.
	Verification VerificationDoc `json:"verification"`
	// Governance carries the freeze/unfreeze/upgrade key set binding.
	Governance GovernanceDoc `json:"governance"`
	// Rollup is the rollup covenant binding. Required.
	Rollup CovenantBinding `json:"rollup"`
	// Bridge is the bridge covenant binding. Populated on KindGenesis,
	// nil on KindRotation.
	Bridge *CovenantBinding `json:"bridge,omitempty"`
	// PreviousAnfHashHex, when non-empty, links this document to the
	// previous ANF in the shard's history. KindRotation populates it
	// with the hash of the live shard's last published ANF; KindGenesis
	// leaves it empty.
	PreviousAnfHashHex string `json:"previousAnfHashHex,omitempty"`
	// GeneratedAt is RFC 3339 UTC. Cosmetic — observers ignore it for
	// hash purposes (it's covered by the canonical JSON, but a stale
	// timestamp does not invalidate the on-chain binding).
	GeneratedAt string `json:"generatedAt"`
}

// CanonicalJSON marshals d into a deterministic byte form suitable
// for hash256.
//
// We rely on Go's encoding/json sort-by-field-tag-name behaviour for
// the top-level struct AND we sort map / slice contents that Go does
// not order for us (governance.keys is sorted by the caller before
// it lands in d). The ANF IR is stored as json.RawMessage and is
// re-canonicalised inline by parsing it into a generic map and re-
// marshalling with sorted keys — this is what makes the document
// hash-stable even if the upstream runar-go compiler tweaks its key
// ordering between releases.
func (d *Document) CanonicalJSON() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("nil document")
	}
	// Re-canonicalise the embedded ANF IR if present.
	out := *d
	if len(out.Rollup.ANFIR) > 0 {
		canon, err := canonicaliseRaw(out.Rollup.ANFIR)
		if err != nil {
			return nil, fmt.Errorf("canonicalise rollup ANF IR: %w", err)
		}
		out.Rollup.ANFIR = canon
	}
	if out.Bridge != nil && len(out.Bridge.ANFIR) > 0 {
		canon, err := canonicaliseRaw(out.Bridge.ANFIR)
		if err != nil {
			return nil, fmt.Errorf("canonicalise bridge ANF IR: %w", err)
		}
		out.Bridge.ANFIR = canon
	}
	// json.Marshal sorts struct fields by declaration order (NOT
	// alphabetically), so the field declaration order in Document is
	// load-bearing for hash stability. Adding new fields requires a
	// schema bump.
	return json.Marshal(&out)
}

// ComputeHash returns hash256(CanonicalJSON(d)) — BSV's standard
// double-sha256 over the canonical bytes. This is the value baked
// into pv[240..272) of the rotation's publicValues blob and into
// UpgradeRequest.NewCovenantAnfHash.
func (d *Document) ComputeHash() ([32]byte, error) {
	raw, err := d.CanonicalJSON()
	if err != nil {
		return [32]byte{}, err
	}
	return Hash256(raw), nil
}

// Hash256 returns sha256(sha256(b)) — BSV's standard double-sha256.
func Hash256(b []byte) [32]byte {
	a := sha256.Sum256(b)
	return sha256.Sum256(a[:])
}

// HexHash256 is a convenience wrapper that returns the lowercase hex
// form of Hash256(b).
func HexHash256(b []byte) string {
	h := Hash256(b)
	return hex.EncodeToString(h[:])
}

// SortedHexKeys returns hex-encoded compressed pubkeys sorted
// lexicographically. Used by callers building GovernanceDoc.Keys so
// the canonical form is independent of operator key-order.
func SortedHexKeys(keys [][]byte) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = hex.EncodeToString(k)
	}
	sort.Strings(out)
	return out
}

// FormatGeneratedAt returns t in RFC 3339 UTC, the format expected by
// Document.GeneratedAt. Exposed so callers can use the same conversion
// the document builder applies internally when comparing timestamps.
func FormatGeneratedAt(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// canonicaliseRaw parses raw JSON into a generic value and re-marshals
// it with sorted object keys at every depth. Used to make sure embedded
// ANF IR survives upstream key-ordering reshuffles without breaking the
// document hash.
func canonicaliseRaw(raw json.RawMessage) (json.RawMessage, error) {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return marshalSorted(v)
}

// marshalSorted returns the JSON encoding of v with object keys sorted
// at every nesting depth. Strings, numbers, booleans, and null are
// unchanged; arrays preserve their input order.
func marshalSorted(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf = append(buf, kb...)
			buf = append(buf, ':')
			vb, err := marshalSorted(t[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil
	case []interface{}:
		buf := []byte{'['}
		for i, el := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			vb, err := marshalSorted(el)
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, ']')
		return buf, nil
	default:
		return json.Marshal(v)
	}
}
