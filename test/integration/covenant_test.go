//go:build integration

// Package integration tests: covenant invariant suite.
//
// These tests verify structural properties of the rollup covenant that are
// independent of proof verification: unlimited unconfirmed chain depth,
// freeze/unfreeze governance, frozen-shard-rejects-advance, and satoshi
// preservation across advances.
package integration

import (
	"testing"
)

// TestCovenant_UnlimitedUnconfirmedChain chains 15 Basefold advances
// back-to-back WITHOUT mining any BSV blocks between them. Every advance
// spends an unconfirmed UTXO. Verifies the covenant places no
// confirmation-depth requirement.
func TestCovenant_UnlimitedUnconfirmedChain(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	z32 := hexZeros32()
	pre := z32
	const chainLen = 15
	for block := int64(1); block <= chainLen; block++ {
		args := buildFRIAdvanceArgs(pre, block)
		_, _, err := contract.Call("advanceState", args, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d (unconfirmed input): %v", block, err)
		}
		pre = hexStateRoot(int(block))
	}
	t.Logf("chained %d advances without mining — all accepted", chainLen)
}

// TestCovenant_FreezeRejectsAdvance freezes the shard using single-key
// governance, then attempts a valid advance — should be rejected because
// Frozen == 1.
func TestCovenant_FreezeRejectsAdvance(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	// Freeze
	// Sig params accept nil — the SDK auto-computes the signature from the signer.
	_, _, err := contract.Call("freezeSingleKey", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	// Advance should fail
	z32 := hexZeros32()
	args := buildFRIAdvanceArgs(z32, 1)
	_, _, err = contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for advance on frozen shard")
	}
	t.Logf("correctly rejected advance on frozen shard: %v", err)
}

// TestCovenant_FreezeUnfreezeLifecycle freezes the shard, unfreezes it,
// then verifies that advance succeeds after unfreeze.
//
// Note: the advance-while-frozen rejection is tested separately in
// TestCovenant_FreezeRejectsAdvance. This test does NOT attempt an
// advance between freeze and unfreeze because a failed contract.Call
// can leave the Rúnar SDK's internal UTXO tracker in a stale state.
func TestCovenant_FreezeUnfreezeLifecycle(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	// 1. Freeze.
	_, _, err := contract.Call("freezeSingleKey", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	// 2. Unfreeze.
	_, _, err = contract.Call("unfreezeSingleKey", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("unfreeze: %v", err)
	}
	// 3. Advance should succeed now.
	z32 := hexZeros32()
	args := buildFRIAdvanceArgs(z32, 1)
	_, _, err = contract.Call("advanceState", args, provider, signer, nil)
	if err != nil {
		t.Fatalf("advance after unfreeze: %v", err)
	}
	t.Logf("freeze → unfreeze → accept: lifecycle complete")
}

// TestCovenant_SatoshiPreservation verifies the covenant output carries
// exactly the same satoshi value across 5 advances.
func TestCovenant_SatoshiPreservation(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	deploySats := contract.GetCurrentUtxo().Satoshis
	if deploySats == 0 {
		t.Fatal("deploy UTXO has zero satoshis")
	}
	t.Logf("deploy sats: %d", deploySats)
	z32 := hexZeros32()
	pre := z32
	const numAdvances = 5
	for block := int64(1); block <= numAdvances; block++ {
		args := buildFRIAdvanceArgs(pre, block)
		_, _, err := contract.Call("advanceState", args, provider, signer, nil)
		if err != nil {
			t.Fatalf("advance to block %d: %v", block, err)
		}
		pre = hexStateRoot(int(block))
		curSats := contract.GetCurrentUtxo().Satoshis
		if curSats != deploySats {
			t.Errorf("block %d: satoshis = %d, want %d", block, curSats, deploySats)
		}
	}
	t.Logf("satoshis preserved at %d across %d advances", deploySats, numAdvances)
}

// TestCovenant_DoubleFreezeRejected verifies that calling freezeSingleKey
// on an already-frozen shard is rejected. The contract checks
// Assert(c.Frozen == 0) which fails if already frozen.
func TestCovenant_DoubleFreezeRejected(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	// First freeze — succeeds.
	_, _, err := contract.Call("freezeSingleKey", []interface{}{nil}, provider, signer, nil)
	if err != nil {
		t.Fatalf("first freeze: %v", err)
	}
	// Second freeze — should be rejected (already frozen).
	_, _, err = contract.Call("freezeSingleKey", []interface{}{nil}, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for double freeze")
	}
	t.Logf("correctly rejected double freeze: %v", err)
}

// TestCovenant_DoubleUnfreezeRejected verifies that calling
// unfreezeSingleKey on an already-active (unfrozen) shard is rejected.
// The contract checks Assert(c.Frozen == 1) which fails if already active.
func TestCovenant_DoubleUnfreezeRejected(t *testing.T) {
	contract, provider, signer, _ := deployFRIRollupLifecycle(t)
	// Shard starts active (Frozen = 0). Unfreeze should fail immediately.
	_, _, err := contract.Call("unfreezeSingleKey", []interface{}{nil}, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for unfreeze on active shard")
	}
	t.Logf("correctly rejected unfreeze on active shard: %v", err)
}
