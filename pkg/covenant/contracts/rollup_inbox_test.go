package contracts

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// Spec 10 forced-inclusion tests
//
// The rollup contracts read inboxRootBefore/inboxRootAfter from the SP1
// public-values blob at offsets [176..208) and [208..240) and enforce two
// invariants on every advance:
//
//   1. AdvancesSinceInbox < 10 OR inboxRootBefore != inboxRootAfter
//      (REJECT when the counter has reached 10 and the guest didn't drain
//      any inbox txs in this batch — censorship escape hatch).
//   2. Counter resets to 0 on drain (before != after) and increments by 1
//      on no-drain (before == after).
//
// The default `buildPublicValues` helper writes 32 zero bytes into both
// [176..208) and [208..240), i.e. before == after, so existing tests
// exercise the "no drain" / increment branch. These tests cover the drain
// branch and the rejection branch explicitly.
// ---------------------------------------------------------------------------

// spliceInboxRoots overwrites pv[176..208) and pv[208..240) with the
// supplied 32-byte values.
func spliceInboxRoots(pv []byte, before, after string) []byte {
	if len(before) != 32 || len(after) != 32 {
		panic("inbox roots must be 32 bytes")
	}
	copy(pv[176:208], []byte(before))
	copy(pv[208:240], []byte(after))
	return pv
}

// ---------------------------------------------------------------------------
// FRI (Mode 1)
// ---------------------------------------------------------------------------

func TestFRIRollup_InboxDrainResetsCounter(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 5

	args := buildFRIArgs(zeros32(), 1)
	pv := []byte(args.publicValues)
	spliceInboxRoots(pv, rawSha256("inbox-before"), rawSha256("inbox-after"))
	args.publicValues = runar.ByteString(string(pv))

	callFRIAdvance(c, args)

	if c.AdvancesSinceInbox != 0 {
		t.Errorf("expected AdvancesSinceInbox=0 after drain, got %d", c.AdvancesSinceInbox)
	}
}

func TestFRIRollup_InboxNoDrainIncrementsCounter(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 3

	// Default buildFRIArgs leaves before == after == zeros, i.e. no drain.
	callFRIAdvance(c, buildFRIArgs(zeros32(), 1))

	if c.AdvancesSinceInbox != 4 {
		t.Errorf("expected AdvancesSinceInbox=4 after no-drain, got %d", c.AdvancesSinceInbox)
	}
}

func TestFRIRollup_InboxRejectsAtThresholdWithoutDrain(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected forced-inclusion assertion failure when counter=10 and no drain")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 10

	// before == after (zeros) → no drain. Must REJECT.
	callFRIAdvance(c, buildFRIArgs(zeros32(), 1))
}

func TestFRIRollup_InboxAcceptsAtThresholdWithDrain(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 10

	args := buildFRIArgs(zeros32(), 1)
	pv := []byte(args.publicValues)
	spliceInboxRoots(pv, rawSha256("pre-drain"), rawSha256("post-drain"))
	args.publicValues = runar.ByteString(string(pv))

	callFRIAdvance(c, args)

	if c.AdvancesSinceInbox != 0 {
		t.Errorf("expected AdvancesSinceInbox=0 after forced drain, got %d", c.AdvancesSinceInbox)
	}
}

// ---------------------------------------------------------------------------
// Groth16 (Mode 2)
// ---------------------------------------------------------------------------

func TestGroth16Rollup_InboxDrainResetsCounter(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 5

	args := buildGroth16Args(zeros32(), 1)
	pv := []byte(args.publicValues)
	spliceInboxRoots(pv, rawSha256("g16-before"), rawSha256("g16-after"))
	args.publicValues = runar.ByteString(string(pv))
	args.g16Input1 = expectedG16Input1(string(pv))

	callGroth16Advance(c, args)

	if c.AdvancesSinceInbox != 0 {
		t.Errorf("expected AdvancesSinceInbox=0 after drain, got %d", c.AdvancesSinceInbox)
	}
}

func TestGroth16Rollup_InboxNoDrainIncrementsCounter(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 7

	callGroth16Advance(c, buildGroth16Args(zeros32(), 1))

	if c.AdvancesSinceInbox != 8 {
		t.Errorf("expected AdvancesSinceInbox=8 after no-drain, got %d", c.AdvancesSinceInbox)
	}
}

func TestGroth16Rollup_InboxRejectsAtThresholdWithoutDrain(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected forced-inclusion assertion failure")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 10

	callGroth16Advance(c, buildGroth16Args(zeros32(), 1))
}

// ---------------------------------------------------------------------------
// Groth16 WA (Mode 3)
// ---------------------------------------------------------------------------

func TestGroth16WARollup_InboxDrainResetsCounter(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 5

	args := buildGroth16WAArgs(zeros32(), 1)
	pv := []byte(args.publicValues)
	spliceInboxRoots(pv, rawSha256("wa-before"), rawSha256("wa-after"))
	args.publicValues = runar.ByteString(string(pv))

	callGroth16WAAdvance(c, args)

	if c.AdvancesSinceInbox != 0 {
		t.Errorf("expected AdvancesSinceInbox=0 after drain, got %d", c.AdvancesSinceInbox)
	}
}

func TestGroth16WARollup_InboxNoDrainIncrementsCounter(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 2

	callGroth16WAAdvance(c, buildGroth16WAArgs(zeros32(), 1))

	if c.AdvancesSinceInbox != 3 {
		t.Errorf("expected AdvancesSinceInbox=3 after no-drain, got %d", c.AdvancesSinceInbox)
	}
}

func TestGroth16WARollup_InboxRejectsAtThresholdWithoutDrain(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected forced-inclusion assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	c.AdvancesSinceInbox = 10

	callGroth16WAAdvance(c, buildGroth16WAArgs(zeros32(), 1))
}
