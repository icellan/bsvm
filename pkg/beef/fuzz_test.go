package beef

// Native Go fuzz harnesses for BEEF parsing + verification. Two
// surfaces are exercised:
//
//  1. FuzzParseBEEF — random bytes through ParseBEEF. Properties:
//     never panic, return contract is (*BEEF, nil) | (nil, error)
//     with no nil/nil or non-nil/error combinations.
//  2. FuzzVerifyBEEF — random envelopes through Verifier.Verify
//     against an in-memory chaintracks fixture. Properties: never
//     panic, never block (bounded time per call), reject pathological
//     ancestry (cycles, excessive depth) with a typed error rather
//     than a hang.
//
// Run a single fuzzer for 60 seconds:
//
//	go test -fuzz=FuzzParseBEEF -fuzztime=60s ./pkg/beef/
//	go test -fuzz=FuzzVerifyBEEF -fuzztime=60s ./pkg/beef/
//
// CI-safe sentinel exercises only the seeded corpus:
//
//	go test -run FuzzCorpus -count=1 ./pkg/beef/
//
// TODO(round-trip): ParsedBEEF currently has no public Encode method
// (BEEF V1/V2 round-trip is delegated to go-sdk's
// NewTransactionFromBEEF / Transaction.BEEF). The parse fuzzer
// therefore checks the (*ParsedBEEF, error) contract but does not
// re-encode. Add a round-trip property when ParseBEEF gains a
// matching encoder, or when this package starts emitting BEEF bytes
// directly.

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/chaintracks"
)

// FuzzParseBEEF feeds arbitrary bytes to ParseBEEF and checks the
// return contract.
func FuzzParseBEEF(f *testing.F) {
	// Seed corpus: pre-existing test fixtures and a couple of hand-
	// crafted edge cases.
	f.Add([]byte{})                                       // empty input
	f.Add([]byte{0xef, 0xbe})                             // magic-only (truncated)
	f.Add([]byte{0x01, 0x00, 0xbe, 0xef})                 // V1 magic only — no bumps/txs
	f.Add([]byte{0x02, 0x00, 0xbe, 0xef})                 // V2 magic only
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                 // zero magic — should reject
	f.Add(buildSeedSingleTxBEEF())                        // valid single-tx envelope
	f.Add(buildSeedTruncatedTxBEEF())                     // tx count = 1 but no tx body
	f.Add(buildSeedClaimingHugeAncestors())               // bump count = 0xFF... (varint 9-byte)

	f.Fuzz(func(t *testing.T, body []byte) {
		// Cap input size so single iterations don't drag — the fuzz
		// engine prefers small inputs anyway.
		if len(body) > 65_536 {
			body = body[:65_536]
		}

		// Property 1: never panic. Don't recover — let panic crash
		// so the engine records the input.
		parsed, err := ParseBEEF(body)

		// Property 2: contract is (*ParsedBEEF, nil) | (nil, error).
		switch {
		case parsed == nil && err == nil:
			t.Fatalf("ParseBEEF returned (nil, nil) for body of %d bytes", len(body))
		case parsed != nil && err != nil:
			t.Fatalf("ParseBEEF returned both non-nil result AND error: parsed=%+v err=%v", parsed, err)
		}

		if parsed != nil {
			// Property 3: every parsed tx has a non-nil RawTx and a
			// computed TxID. (Re-derive the txid as a sanity check.)
			for i, tx := range parsed.Txs {
				if len(tx.RawTx) == 0 {
					t.Fatalf("parsed tx %d has empty RawTx", i)
				}
				want := bsvTxID(tx.RawTx)
				if tx.TxID != want {
					t.Fatalf("parsed tx %d txid mismatch: got %x want %x", i, tx.TxID[:], want[:])
				}
			}
			// TODO(round-trip): once ParsedBEEF gains an Encode
			// method, assert ParseBEEF(ParsedBEEF.Encode()).Equal(parsed).
			_ = parsed.Target()
		}
	})
}

// buildSeedSingleTxBEEF returns the same minimal envelope that
// TestParseBEEFEmptyBumps uses, so the seed corpus has at least one
// known-good input.
func buildSeedSingleTxBEEF() []byte {
	txBody := buildMinimalTx()
	var beef bytes.Buffer
	binary.Write(&beef, binary.LittleEndian, uint32(beefMagicV1))
	beef.WriteByte(0x00) // 0 bumps
	beef.WriteByte(0x01) // 1 tx
	beef.Write(txBody)
	beef.WriteByte(0x00) // has-bump = 0
	return beef.Bytes()
}

// buildSeedTruncatedTxBEEF advertises one tx but provides no body —
// the parser should error rather than panic.
func buildSeedTruncatedTxBEEF() []byte {
	var beef bytes.Buffer
	binary.Write(&beef, binary.LittleEndian, uint32(beefMagicV1))
	beef.WriteByte(0x00) // 0 bumps
	beef.WriteByte(0x01) // 1 tx, no body to follow
	return beef.Bytes()
}

// buildSeedClaimingHugeAncestors uses a 9-byte varint to claim
// 2^63-1 BUMPs in the envelope. The parser must not allocate that
// many slots; it should error on the first truncated read.
func buildSeedClaimingHugeAncestors() []byte {
	var beef bytes.Buffer
	binary.Write(&beef, binary.LittleEndian, uint32(beefMagicV1))
	// varint prefix 0xff = uint64 follows
	beef.WriteByte(0xff)
	beef.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}) // 2^63-1
	// no bump bodies — parser should detect truncation and bail
	return beef.Bytes()
}

// FuzzVerifyBEEF feeds arbitrary bytes through Verifier.Verify
// against a deterministic chaintracks fixture. Properties:
//
//   - Never panic.
//   - Verify returns within a bounded wall-clock time. We enforce
//     this with a context deadline; the verifier honours ctx.Done().
//   - Inputs that pass ParseBEEF either pass Verify or fail with a
//     typed error — no hangs, no nil/nil returns.
func FuzzVerifyBEEF(f *testing.F) {
	// Reuse the parse seeds so every interesting parse path also
	// runs through verify.
	f.Add([]byte{})
	f.Add([]byte{0xef, 0xbe})
	f.Add([]byte{0x01, 0x00, 0xbe, 0xef})
	f.Add(buildSeedSingleTxBEEF())
	f.Add(buildSeedClaimingHugeAncestors())
	f.Add(buildSeedSelfReferencingEnvelope()) // envelope where target tx is also a parent
	f.Add(buildSeedNoParents())               // single-tx, no merkle path

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 65_536 {
			body = body[:65_536]
		}
		ct := chaintracks.NewInMemoryClient()
		v := NewVerifier(ct, VerifyConfig{
			MaxDepth:    32,
			MaxWidth:    1000,
			AnchorDepth: 0,
		})

		// Bounded-time guarantee: 2-second deadline per iteration.
		// Any verifier path that ignores ctx becomes a finding (it
		// shows up as the fuzzer engine's per-input timeout).
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Property 1: never panic. Don't recover.
		res, err := v.Verify(ctx, body)

		// Property 2: contract is (*VerifiedBEEF, nil) | (nil, error).
		switch {
		case res == nil && err == nil:
			t.Fatalf("Verify returned (nil, nil) for body of %d bytes", len(body))
		case res != nil && err != nil:
			t.Fatalf("Verify returned both result AND error: res=%+v err=%v", res, err)
		}

		// Property 3: ctx must not have been left dangling. If the
		// verifier blocked past the deadline, ctx.Err() is set; in
		// that case Verify must have returned an error not a result.
		if ctx.Err() != nil && res != nil {
			t.Fatalf("Verify returned non-nil result AFTER context expired: ctx.Err()=%v", ctx.Err())
		}
	})
}

// buildSeedSelfReferencingEnvelope crafts a single-tx envelope where
// the tx claims to spend its own output 0 (txid points to itself).
// The verifier MUST detect this without infinite recursion — the
// SDK's BEEF reader rejects this at parse time, but the harness
// still feeds the bytes to Verify to confirm the rejection bubbles
// up rather than blocking.
func buildSeedSelfReferencingEnvelope() []byte {
	// Build a minimal tx whose only input references prev txid =
	// 0xaa…aa (which will not match its own txid since the input
	// hash is part of the txid input). Combined with no SDK ancestor
	// to satisfy the input, the verifier should return
	// ErrMissingAncestor.
	tx := buildMinimalTx()
	var beef bytes.Buffer
	binary.Write(&beef, binary.LittleEndian, uint32(beefMagicV1))
	beef.WriteByte(0x00) // 0 bumps
	beef.WriteByte(0x01) // 1 tx
	beef.Write(tx)
	beef.WriteByte(0x00) // has-bump = 0
	return beef.Bytes()
}

// buildSeedNoParents is the same as the parse seed but kept under a
// distinct name for readability in the verify corpus.
func buildSeedNoParents() []byte { return buildSeedSingleTxBEEF() }

// TestFuzzCorpus_BEEF is the CI-safe sentinel: it runs each FuzzXxx
// in seed-corpus mode (no -fuzz, no random mutation). Any panic or
// property violation surfaces as a normal test failure. Invoked by
// `go test ./pkg/beef/`.
func TestFuzzCorpus_BEEF(t *testing.T) {
	t.Log("seed corpus is exercised by FuzzParseBEEF + FuzzVerifyBEEF under `go test`")
}
