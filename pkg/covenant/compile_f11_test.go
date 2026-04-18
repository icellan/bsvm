package covenant

import (
	"testing"
)

// F11 defence-in-depth tests for assertGovernanceKeysShape.
//
// Finding F11: buildSharedConstructorArgs must reject any zero-prefixed
// bytes in an active governance-key slot, regardless of whether
// GovernanceConfig.Validate() was called first. The current call graph
// validates before compiling, but a future refactor that forgets to call
// Validate must not silently produce a covenant whose CheckSig /
// CheckMultiSig slots carry a zero pubkey — that would compile cleanly
// and then lock governance out forever because no signature can satisfy
// a zero-prefix key.
//
// These tests exercise the assertGovernanceKeysShape helper directly so
// the defence-in-depth path can be checked without having to route
// through the full Rúnar compile pipeline (and without Validate's prior
// rejection masking the check).

// TestAssertGovernanceKeysShape_NonePositive verifies that the happy
// path for GovernanceNone — zero keys, zero threshold — passes the
// defence-in-depth check.
func TestAssertGovernanceKeysShape_NonePositive(t *testing.T) {
	cfg := GovernanceConfig{Mode: GovernanceNone}
	if err := assertGovernanceKeysShape(cfg); err != nil {
		t.Fatalf("GovernanceNone with no keys must pass, got %v", err)
	}
}

// TestAssertGovernanceKeysShape_SingleKeyPositive verifies that a
// single-key config with a valid 0x02-prefixed compressed pubkey passes.
func TestAssertGovernanceKeysShape_SingleKeyPositive(t *testing.T) {
	cfg := GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	if err := assertGovernanceKeysShape(cfg); err != nil {
		t.Fatalf("GovernanceSingleKey with a valid key must pass, got %v", err)
	}
}

// TestAssertGovernanceKeysShape_MultiSigPositive verifies that a 2-of-2
// multisig with two valid compressed pubkeys passes. Slot 2 stays the
// zero placeholder and is not checked (it's unused).
func TestAssertGovernanceKeysShape_MultiSigPositive(t *testing.T) {
	cfg := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), testKey(2)},
		Threshold: 2,
	}
	if err := assertGovernanceKeysShape(cfg); err != nil {
		t.Fatalf("2-of-2 multisig with valid keys must pass, got %v", err)
	}
}

// TestAssertGovernanceKeysShape_SingleKeyZero verifies that a
// single-key config whose only key is 33 zero bytes is rejected by
// the defence-in-depth check. This is the core F11 regression: without
// this check, a caller that bypasses Validate would bake a dead
// CheckSig slot into the covenant.
func TestAssertGovernanceKeysShape_SingleKeyZero(t *testing.T) {
	cfg := GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{make([]byte, 33)},
	}
	err := assertGovernanceKeysShape(cfg)
	if err == nil {
		t.Fatal("zero-byte single key must be rejected")
	}
	if !containsSubstring(err.Error(), "slot 0 invalid") {
		t.Errorf("error %q should mention slot 0", err.Error())
	}
}

// TestAssertGovernanceKeysShape_MultiSigZeroSlot verifies that a
// multisig with slot 1 stuffed with zero bytes (threshold 2, 3 keys
// total) is rejected. Slot 1 is active (inside 0..len(Keys)-1) and
// must carry a real pubkey.
func TestAssertGovernanceKeysShape_MultiSigZeroSlot(t *testing.T) {
	cfg := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1), make([]byte, 33), testKey(3)},
		Threshold: 2,
	}
	err := assertGovernanceKeysShape(cfg)
	if err == nil {
		t.Fatal("multisig with zero bytes in active slot 1 must be rejected")
	}
	if !containsSubstring(err.Error(), "slot 1 invalid") {
		t.Errorf("error %q should mention slot 1", err.Error())
	}
}

// TestAssertGovernanceKeysShape_WrongPrefix verifies that a key with
// a non-compressed prefix (0x04, uncompressed) is rejected.
func TestAssertGovernanceKeysShape_WrongPrefix(t *testing.T) {
	uncompressed := make([]byte, 33)
	uncompressed[0] = 0x04 // uncompressed pubkey prefix
	for i := 1; i < 33; i++ {
		uncompressed[i] = 0xaa
	}
	cfg := GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{uncompressed},
	}
	err := assertGovernanceKeysShape(cfg)
	if err == nil {
		t.Fatal("0x04 uncompressed prefix must be rejected")
	}
	if !containsSubstring(err.Error(), "0x04") {
		t.Errorf("error %q should mention the bad prefix byte", err.Error())
	}
}

// TestAssertGovernanceKeysShape_NoneWithKeys verifies that GovernanceNone
// with any keys present is rejected — none mode means no keys at all.
func TestAssertGovernanceKeysShape_NoneWithKeys(t *testing.T) {
	cfg := GovernanceConfig{
		Mode: GovernanceNone,
		Keys: [][]byte{testKey(1)},
	}
	err := assertGovernanceKeysShape(cfg)
	if err == nil {
		t.Fatal("GovernanceNone with keys must be rejected")
	}
	if !containsSubstring(err.Error(), "must have no keys") {
		t.Errorf("error %q should mention no keys required", err.Error())
	}
}

// TestAssertGovernanceKeysShape_MultiSigTooFewKeys verifies that
// multisig with fewer than 2 keys is rejected (covers the len < 2
// guard).
func TestAssertGovernanceKeysShape_MultiSigTooFewKeys(t *testing.T) {
	cfg := GovernanceConfig{
		Mode:      GovernanceMultiSig,
		Keys:      [][]byte{testKey(1)},
		Threshold: 1,
	}
	err := assertGovernanceKeysShape(cfg)
	if err == nil {
		t.Fatal("multisig with 1 key must be rejected")
	}
}

// TestBuildSharedConstructorArgs_PropagatesShapeError verifies that a
// bad governance shape surfaces as a returned error from
// buildSharedConstructorArgs — not a silent zero-key bake. This is the
// integration-level F11 check: the error must actually reach the
// caller, so Compile* entry points can fail loudly instead of emitting
// a broken covenant.
func TestBuildSharedConstructorArgs_PropagatesShapeError(t *testing.T) {
	sp1VK := []byte("test-sp1-verifying-key")
	cfg := GovernanceConfig{
		Mode: GovernanceSingleKey,
		Keys: [][]byte{make([]byte, 33)}, // zero-prefixed, bypasses Validate
	}
	args, err := buildSharedConstructorArgs(sp1VK, 42, cfg)
	if err == nil {
		t.Fatal("expected error from buildSharedConstructorArgs on zero key")
	}
	if args != nil {
		t.Fatal("args must be nil on error")
	}
}
