package contracts

import (
	"math/big"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Adversarial coverage for the P0 fixes applied in rollup_groth16.runar.go
// (F01, F04) and rollup_groth16_wa.runar.go (F04, F05). Each test names
// its attack class in the doc comment.
//
// Go-mock caveat: Bn254MultiPairing4 always returns true and Bn254G1OnCurve
// accepts (0,0). These tests exercise contract STRUCTURE (ordering +
// presence + rejection of non-pairing invariants), not pairing soundness.

// ---------------------------------------------------------------------------
// F01 — SP1 public input bindings (Mode 2 generic)
// ---------------------------------------------------------------------------

// TestGroth16Rollup_F01_AcceptsMatchingInputs — positive control.
func TestGroth16Rollup_F01_AcceptsMatchingInputs(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)
	if c.BlockNumber != 1 {
		t.Fatalf("expected block 1 after advance, got %d", c.BlockNumber)
	}
}

// TestGroth16Rollup_F01_RejectsWrongVkeyHash pins the binding between
// g16Input0 and the covenant's pinned SP1ProgramVkHashScalar.
//
// Attack class: arbitrary SP1 guest program substitution.
func TestGroth16Rollup_F01_RejectsWrongVkeyHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on mismatched g16Input0")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input0 = new(big.Int).Add(testSP1ProgramVkHashScalar, big.NewInt(1))
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F01_RejectsWrongPvDigest pins the binding between
// g16Input1 and the reduced sha256 of publicValues.
//
// Attack class: publicValues decoupled from proof.
func TestGroth16Rollup_F01_RejectsWrongPvDigest(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on mismatched g16Input1")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input1 = new(big.Int).Add(args.g16Input1, big.NewInt(1))
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F01_RejectsTamperedPublicValues verifies swapping
// bytes in publicValues (without updating g16Input1) is rejected because
// the on-chain reduction picks up the tampered bytes.
//
// Attack class: pv bytes tamper after prover commitment.
//
// The last byte of publicValues lands at LE index 0 after ReverseBytes,
// which is the lowest-order byte Bin2Num reads, so flipping it changes
// the truncated int64 digest under the Go mock. Real Script sha256 means
// any flip changes the digest.
func TestGroth16Rollup_F01_RejectsTamperedPublicValues(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on tampered publicValues")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	pv := []byte(args.publicValues)
	pv[len(pv)-1] ^= 0xFF
	args.publicValues = runar.ByteString(string(pv))
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F01_RejectsNonzeroExitCode pins g16Input2 == 0.
//
// Attack class: failed-guest proof accepted.
func TestGroth16Rollup_F01_RejectsNonzeroExitCode(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on non-zero exitCode")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input2 = big.NewInt(1)
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F01_RejectsNonzeroVkRoot pins g16Input4 == 0.
//
// Attack class: multi-program vk-root substitution.
func TestGroth16Rollup_F01_RejectsNonzeroVkRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on non-zero vkRoot")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input4 = big.NewInt(7)
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F01_ProofNonceUnconstrained documents that g16Input3
// is intentionally left unconstrained per SP1 convention.
func TestGroth16Rollup_F01_ProofNonceUnconstrained(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input3 = big.NewInt(0xDEADBEEF)
	callGroth16Advance(c, args)
	if c.BlockNumber != 1 {
		t.Fatalf("expected block 1, got %d", c.BlockNumber)
	}
}

// TestGroth16Rollup_F01_UpgradeEnforcesBindings verifies F01 also applies
// on the Upgrade* paths — compromised governance cannot tunnel a proof
// for a different SP1 guest via Upgrade.
func TestGroth16Rollup_F01_UpgradeEnforcesBindings(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on upgrade with mismatched vkey hash")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	newScript := runar.ByteString("new_script")
	args := buildGroth16UpgradeArgs(c, newScript)
	args.g16Input0 = new(big.Int).Add(testSP1ProgramVkHashScalar, big.NewInt(1))
	c.UpgradeSingleKey(
		sig, newScript,
		args.publicValues, args.batchData, args.proofBlob,
		args.proofA, args.proofBX0, args.proofBX1, args.proofBY0, args.proofBY1, args.proofC,
		args.g16Input0, args.g16Input1, args.g16Input2, args.g16Input3, args.g16Input4,
		args.newBlockNum,
	)
}

// ---------------------------------------------------------------------------
// F01 — SP1 public input bindings (Mode 3 WA, via Groth16PublicInput)
// ---------------------------------------------------------------------------
//
// Rúnar's Go-mock `Groth16PublicInput(i)` always returns 0, so Mode 3
// happy-path tests pin SP1ProgramVkHashScalar = 0 and Bn254ScalarMask = 1
// (any x mod 1 = 0). These adversarial tests flip each binding away
// from that zero baseline and verify the contract rejects the advance.
// Integration tests exercise the compiled-Script pub_i wiring with real
// values.

// TestGroth16WARollup_F01_AcceptsMatchingInputs — positive control.
func TestGroth16WARollup_F01_AcceptsMatchingInputs(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)
	if c.BlockNumber != 1 {
		t.Fatalf("expected block 1 after advance, got %d", c.BlockNumber)
	}
}

// TestGroth16WARollup_F01_RejectsMismatchedVkeyHash pins the g16Input0
// binding: Groth16PublicInput(0) (mock: 0) must equal
// c.SP1ProgramVkHashScalar. Flipping the pinned value to non-zero makes
// the assertion fire.
//
// Attack class: arbitrary SP1 guest program substitution.
func TestGroth16WARollup_F01_RejectsMismatchedVkeyHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when SP1ProgramVkHashScalar != 0 under Go mock")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	c.SP1ProgramVkHashScalar = 1 // mismatch the mock's pub_0 = 0
	callGroth16WAAdvance(c, buildGroth16WAArgs(zeros32(), 1))
}

// TestGroth16WARollup_F01_RejectsMismatchedPvDigest pins the g16Input1
// binding: Groth16PublicInput(1) (mock: 0) must equal
// reducePublicValuesToScalarWA(publicValues). Bumping the mask above 1
// makes the reduction non-zero (modulo low64(sha256(pv))) and
// non-matching.
//
// Attack class: publicValues decoupled from proof.
func TestGroth16WARollup_F01_RejectsMismatchedPvDigest(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when publicValues reduction != 0 under Go mock")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	// Bump mask so reducePublicValuesToScalarWA no longer always yields 0.
	// low64(sha256(pv)) % (1<<20) is almost certainly non-zero for
	// deterministic test publicValues.
	c.Bn254ScalarMask = 1 << 20
	callGroth16WAAdvance(c, buildGroth16WAArgs(zeros32(), 1))
}

// TestGroth16WARollup_F01_BindingsApplyAfterPreamble pins a sanity check:
// the F01 assertions come AFTER `AssertGroth16WitnessAssistedWithMSM()`
// in source order. A value mismatch still fires because the preamble is
// a no-op in Go and control reaches the F01 assertions normally.
func TestGroth16WARollup_F01_BindingsApplyAfterPreamble(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	c.SP1ProgramVkHashScalar = 42 // any non-zero value triggers
	callGroth16WAAdvance(c, buildGroth16WAArgs(zeros32(), 1))
}

// TestGroth16WARollup_F08_RejectsOutOfRangePubInput pins the Bn254
// scalar range check in Mode 3. Set Bn254ScalarOrder = 0 — every
// scalar >= 0 fails `Groth16PublicInput(i) < c.Bn254ScalarOrder`
// because 0 < 0 is false.
//
// Attack class: unreduced scalar reaching the MSM.
func TestGroth16WARollup_F08_RejectsOutOfRangePubInput(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when pub_i >= Bn254ScalarOrder")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 0)
	c.Bn254ScalarOrder = 0 // forces `0 < 0` → false on every pub_i
	callGroth16WAAdvance(c, buildGroth16WAArgs(zeros32(), 1))
}

// ---------------------------------------------------------------------------
// F05 — Mode 3 WA Upgrade migration-hash binding
// ---------------------------------------------------------------------------

// TestGroth16WARollup_F05_UpgradeAcceptsMatchingHash — positive control.
func TestGroth16WARollup_F05_UpgradeAcceptsMatchingHash(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	newScript := runar.ByteString("legit-new-script")
	migHash := runar.ByteString(rawHash256(string(newScript)))

	c.UpgradeSingleKey(sig, newScript, migHash, 1)

	if c.Frozen != 0 {
		t.Errorf("expected frozen=0 after upgrade, got %d", c.Frozen)
	}
	if c.BlockNumber != 1 {
		t.Errorf("expected block 1 after upgrade, got %d", c.BlockNumber)
	}
}

// TestGroth16WARollup_F05_UpgradeRejectsMismatchedHash pins the F05
// migration-hash binding.
//
// Attack class: governance signs upgrade-to-X but unlock carries Y.
func TestGroth16WARollup_F05_UpgradeRejectsMismatchedHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on mismatched migrationHash")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	newScript := runar.ByteString("the-actual-script")
	otherScript := runar.ByteString("a-different-script")
	migHash := runar.ByteString(rawHash256(string(otherScript)))

	c.UpgradeSingleKey(sig, newScript, migHash, 1)
}

// TestGroth16WARollup_F05_UpgradeRejectsAllZeroHash blocks the trivial
// all-zero-migrationHash bypass.
func TestGroth16WARollup_F05_UpgradeRejectsAllZeroHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on zero migrationHash")
		}
	}()
	c := newGroth16WARollup(zeros32(), 0, 1)
	sig := runar.SignTestMessage(runar.Alice.PrivKey)
	newScript := runar.ByteString("any-new-script")
	zeroHash := runar.ByteString(string(make([]byte, 32)))

	c.UpgradeSingleKey(sig, newScript, zeroHash, 1)
}

// TestGroth16WARollup_F05_UpgradeMultiSig2EnforcesHash — same check on
// 2-of-3 path.
func TestGroth16WARollup_F05_UpgradeMultiSig2EnforcesHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on multisig upgrade with bad migrationHash")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob}
	c := newGroth16WARollupMultiSig(zeros32(), 0, 1, keys, 2)
	sig1 := runar.SignTestMessage(runar.Alice.PrivKey)
	sig2 := runar.SignTestMessage(runar.Bob.PrivKey)
	newScript := runar.ByteString("multisig-new-script")
	wrongHash := runar.ByteString(rawHash256("NOT-the-new-script"))

	c.UpgradeMultiSig2(sig1, sig2, newScript, wrongHash, 1)
}

// TestGroth16WARollup_F05_UpgradeMultiSig3EnforcesHash — same on 3-of-3.
func TestGroth16WARollup_F05_UpgradeMultiSig3EnforcesHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on multisig3 upgrade with bad migrationHash")
		}
	}()
	keys := []runar.TestKeyPair{runar.Alice, runar.Bob, runar.Charlie}
	c := newGroth16WARollupMultiSig(zeros32(), 0, 1, keys, 3)
	sig1 := runar.SignTestMessage(runar.Alice.PrivKey)
	sig2 := runar.SignTestMessage(runar.Bob.PrivKey)
	sig3 := runar.SignTestMessage(runar.Charlie.PrivKey)
	newScript := runar.ByteString("3of3-new-script")
	wrongHash := runar.ByteString(rawHash256("still-not-the-new-script"))

	c.UpgradeMultiSig3(sig1, sig2, sig3, newScript, wrongHash, 1)
}
