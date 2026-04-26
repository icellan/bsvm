package beef

import (
	"context"
	"errors"
	"math/big"
	"testing"

	sdkhash "github.com/bsv-blockchain/go-sdk/chainhash"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	sdktx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/icellan/bsvm/pkg/chaintracks"
)

// makeAlwaysTrueLockScript returns a locking script that pushes OP_TRUE
// — any unlocking script that ends with TRUE on the stack will satisfy
// it under standard BSV consensus. Used to build synthetic ancestor
// outputs the verifier can re-execute deterministically without
// touching ECDSA / sighash code.
func makeAlwaysTrueLockScript(t *testing.T) *sdkscript.Script {
	t.Helper()
	s := sdkscript.NewFromBytes([]byte{sdkscript.OpTRUE})
	return s
}

// buildAncestorTx constructs a 1-output transaction whose locking
// script is OP_TRUE. The tx has no inputs (a synthetic "coinbase-like"
// node — fine for the verifier because the BUMP marks it as the trust
// boundary; the verifier never descends past a BUMPed ancestor).
func buildAncestorTx(t *testing.T, satoshis uint64) *sdktx.Transaction {
	t.Helper()
	tx := sdktx.NewTransaction()
	lock := makeAlwaysTrueLockScript(t)
	tx.AddOutput(&sdktx.TransactionOutput{Satoshis: satoshis, LockingScript: lock})
	return tx
}

// buildSpendingTx constructs a transaction that spends ancestorTx's
// output 0 with an empty unlocking script (which lands OP_TRUE on the
// stack from the locking side, satisfying it). The result is a
// fully-validated parent → child pair the SDK script interpreter
// accepts under WithAfterGenesis + WithForkID.
func buildSpendingTx(t *testing.T, ancestor *sdktx.Transaction) *sdktx.Transaction {
	t.Helper()
	emptyUnlock := sdkscript.NewFromBytes(nil)
	tx := sdktx.NewTransaction()
	tx.AddInput(&sdktx.TransactionInput{
		SourceTXID:        ancestor.TxID(),
		SourceTxOutIndex:  0,
		SourceTransaction: ancestor,
		UnlockingScript:   emptyUnlock,
		SequenceNumber:    0xffffffff,
	})
	// Output is irrelevant for verification; satoshis must be ≤ source.
	src := ancestor.Outputs[0]
	out := src.Satoshis - 1
	if out > src.Satoshis {
		out = 0
	}
	tx.AddOutput(&sdktx.TransactionOutput{Satoshis: out, LockingScript: makeAlwaysTrueLockScript(t)})
	return tx
}

// attachSingleTxBUMP wraps tx in a synthetic BRC-74 BUMP that treats
// it as the only transaction in its block (so the merkle root equals
// the txid). Returns the height the BUMP commits to.
func attachSingleTxBUMP(t *testing.T, tx *sdktx.Transaction, height uint32) {
	t.Helper()
	hash := tx.TxID()
	isTxid := true
	mp := sdktx.NewMerklePath(height, [][]*sdktx.PathElement{
		{
			{Offset: 0, Hash: hash, Txid: &isTxid},
		},
	})
	tx.MerklePath = mp
}

// seedChaintracksForTx registers a BlockHeader at height with a
// merkle root equal to tx.TxID() (matches the synthetic 1-tx BUMP),
// at depth confirmations below the chain tip. Returns the seeded
// header.
func seedChaintracksForTx(
	t *testing.T,
	ct *chaintracks.InMemoryClient,
	tx *sdktx.Transaction,
	height uint64,
	confirmations uint64,
) *chaintracks.BlockHeader {
	t.Helper()
	var root [32]byte
	copy(root[:], tx.TxID().CloneBytes())
	hdr := &chaintracks.BlockHeader{
		Height:     height,
		Hash:       deterministicBlockHash(height),
		MerkleRoot: root,
		Timestamp:  1_700_000_000,
		Bits:       0x207fffff,
		Nonce:      0,
		Work:       new(big.Int).SetUint64(height + 1),
	}
	ct.PutHeader(hdr)
	// Tip = height + confirmations - 1 so Confirmations(height) = confs.
	if confirmations > 1 {
		tipHeight := height + confirmations - 1
		ct.PutHeader(&chaintracks.BlockHeader{
			Height:     tipHeight,
			Hash:       deterministicBlockHash(tipHeight),
			MerkleRoot: deterministicBlockHash(tipHeight),
			Timestamp:  1_700_000_000,
			Bits:       0x207fffff,
			Nonce:      0,
			Work:       new(big.Int).SetUint64(tipHeight + 1),
		})
	}
	return hdr
}

// deterministicBlockHash returns a [32]byte derived from height; used
// only so different heights produce distinguishable hashes in tests.
func deterministicBlockHash(height uint64) [32]byte {
	var out [32]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(height >> (8 * i))
	}
	return out
}

// buildValidBEEF returns the BEEF bytes for a target tx that spends a
// BUMPed ancestor at the given height with the given confirmation
// depth. The chaintracks fixture is wired so the verifier accepts the
// envelope.
func buildValidBEEF(t *testing.T, height uint64, confs uint64) ([]byte, *chaintracks.InMemoryClient, *sdktx.Transaction) {
	t.Helper()
	ct := chaintracks.NewInMemoryClient()
	ancestor := buildAncestorTx(t, 1000)
	attachSingleTxBUMP(t, ancestor, uint32(height))
	seedChaintracksForTx(t, ct, ancestor, height, confs)
	target := buildSpendingTx(t, ancestor)
	beefBytes, err := target.BEEF()
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}
	return beefBytes, ct, target
}

func TestVerifier_HappyPath(t *testing.T) {
	beefBytes, ct, target := buildValidBEEF(t, 800_000, 10)
	v := NewVerifier(ct, VerifyConfig{AnchorDepth: 0}) // target is unconfirmed (no BUMP on it)
	res, err := v.Verify(context.Background(), beefBytes)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if res == nil {
		t.Fatal("verify returned nil result")
	}
	wantTxID := target.TxID()
	got := sdkhash.Hash(res.TargetTxID)
	if !got.IsEqual(wantTxID) {
		t.Fatalf("wrong target txid: got %x want %x", res.TargetTxID, wantTxID.CloneBytes())
	}
	if res.AncestorCount < 1 {
		t.Fatalf("expected at least 1 ancestor walked, got %d", res.AncestorCount)
	}
}

func TestVerifier_AnchorDepthOnTargetBUMP(t *testing.T) {
	// Build a "self-confirmed" envelope: the target itself carries a
	// BUMP at the given height. We use a no-input target (synthetic
	// coinbase) so the verifier short-circuits on the target's BUMP
	// and never tries to walk inputs.
	ct := chaintracks.NewInMemoryClient()
	target := buildAncestorTx(t, 5000)
	attachSingleTxBUMP(t, target, 800_000)
	seedChaintracksForTx(t, ct, target, 800_000, 10)
	beefBytes, err := target.BEEF()
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}

	// Anchor depth = 6: 10 confirmations >= 6 → pass.
	v := NewVerifier(ct, VerifyConfig{AnchorDepth: 6})
	res, err := v.Verify(context.Background(), beefBytes)
	if err != nil {
		t.Fatalf("expected pass at depth 10 vs threshold 6, got %v", err)
	}
	if res.Confirmations < 6 {
		t.Fatalf("confirmations %d below threshold; verifier should have rejected", res.Confirmations)
	}

	// Anchor depth = 100: 10 confirmations < 100 → ErrAnchorTooShallow.
	v = NewVerifier(ct, VerifyConfig{AnchorDepth: 100})
	if _, err := v.Verify(context.Background(), beefBytes); !errors.Is(err, ErrAnchorTooShallow) {
		t.Fatalf("expected ErrAnchorTooShallow, got %v", err)
	}
}

func TestVerifier_BadMerkleProof(t *testing.T) {
	// Build a valid envelope, then corrupt chaintracks so the merkle
	// root the BUMP commits to doesn't match the header's recorded
	// root.
	beefBytes, ct, ancestor := buildValidBEEF(t, 800_001, 10)
	hdr, err := ct.HeaderByHeight(context.Background(), 800_001)
	if err != nil {
		t.Fatalf("setup header: %v", err)
	}
	// Flip a bit in the merkle root.
	corrupted := *hdr
	corrupted.MerkleRoot[0] ^= 0xff
	ct.PutHeader(&corrupted)

	v := NewVerifier(ct, VerifyConfig{})
	if _, err := v.Verify(context.Background(), beefBytes); !errors.Is(err, ErrBUMP) {
		t.Fatalf("expected ErrBUMP, got %v", err)
	}
	_ = ancestor
}

func TestVerifier_BrokenScript(t *testing.T) {
	// Build an ancestor whose locking script is OP_FALSE (always
	// fails). The target's empty unlocking script will leave OP_FALSE
	// on the stack and the interpreter rejects.
	ct := chaintracks.NewInMemoryClient()
	ancestor := sdktx.NewTransaction()
	bad := sdkscript.NewFromBytes([]byte{sdkscript.OpFALSE})
	ancestor.AddOutput(&sdktx.TransactionOutput{Satoshis: 1000, LockingScript: bad})
	attachSingleTxBUMP(t, ancestor, 800_002)
	seedChaintracksForTx(t, ct, ancestor, 800_002, 10)

	emptyUnlock := sdkscript.NewFromBytes(nil)
	target := sdktx.NewTransaction()
	target.AddInput(&sdktx.TransactionInput{
		SourceTXID:        ancestor.TxID(),
		SourceTxOutIndex:  0,
		SourceTransaction: ancestor,
		UnlockingScript:   emptyUnlock,
		SequenceNumber:    0xffffffff,
	})
	target.AddOutput(&sdktx.TransactionOutput{Satoshis: 0, LockingScript: makeAlwaysTrueLockScript(t)})

	beefBytes, err := target.BEEF()
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}

	v := NewVerifier(ct, VerifyConfig{})
	if _, err := v.Verify(context.Background(), beefBytes); !errors.Is(err, ErrScript) {
		t.Fatalf("expected ErrScript, got %v", err)
	}
}

func TestVerifier_MissingAncestor(t *testing.T) {
	// Build a target that references an ancestor we then drop from the
	// BEEF before re-encoding. We can simulate this by manually
	// crafting a BEEF body whose target tx points at a txid not
	// included as an ancestor; the SDK reader will still succeed but
	// the input's SourceTransaction will be nil → ErrMissingAncestor.
	ancestor := buildAncestorTx(t, 1000)
	attachSingleTxBUMP(t, ancestor, 800_003)
	target := buildSpendingTx(t, ancestor)
	// Detach the SourceTransaction so collectAncestors does not
	// include the ancestor in the BEEF body.
	target.Inputs[0].SourceTransaction = nil

	// We can't call target.BEEF() with no SourceTransaction (it
	// errors), so manually craft a minimal V1 BEEF: 0 BUMPs, 1 tx
	// (target only), no merkle proof on the target.
	beefBytes := encodeMinimalSingleTxBEEF(t, target)

	ct := chaintracks.NewInMemoryClient()
	v := NewVerifier(ct, VerifyConfig{})
	if _, err := v.Verify(context.Background(), beefBytes); !errors.Is(err, ErrMissingAncestor) {
		t.Fatalf("expected ErrMissingAncestor, got %v", err)
	}
}

// encodeMinimalSingleTxBEEF writes a V1 BEEF body that contains only
// `tx` (no BUMPs, no ancestors). Used by tests that need to simulate a
// truncated or missing-ancestor envelope. The version is BEEF_V1
// (4022206465 = 0xEFBE0001 → little-endian wire bytes 01 00 BE EF).
func encodeMinimalSingleTxBEEF(t *testing.T, tx *sdktx.Transaction) []byte {
	t.Helper()
	out := []byte{0x01, 0x00, 0xbe, 0xef} // BEEF_V1 little-endian wire form
	out = append(out, 0x00)               // 0 bumps (BSV varint <0xfd)
	out = append(out, 0x01)               // 1 tx
	out = append(out, tx.Bytes()...)
	out = append(out, 0x00) // has-bump = 0
	return out
}

func TestVerifier_TooDeep(t *testing.T) {
	// Build a chain of 5 BUMPed ancestors each spending the previous
	// one without a BUMP between them (so depth > BUMP-anchor distance).
	// The simplest deep-rejection test is to construct a 5-deep chain
	// where only the bottom is BUMPed and verify with MaxDepth = 2.
	ct := chaintracks.NewInMemoryClient()
	bottom := buildAncestorTx(t, 100_000)
	attachSingleTxBUMP(t, bottom, 800_004)
	seedChaintracksForTx(t, ct, bottom, 800_004, 10)
	mid := buildSpendingTx(t, bottom)
	for i := 0; i < 4; i++ {
		mid = buildSpendingTx(t, mid)
	}
	beefBytes, err := mid.BEEF()
	if err != nil {
		t.Fatalf("build BEEF: %v", err)
	}
	v := NewVerifier(ct, VerifyConfig{MaxDepth: 2})
	if _, err := v.Verify(context.Background(), beefBytes); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("expected ErrTooDeep, got %v", err)
	}
}

func TestVerifier_NoChaintracks(t *testing.T) {
	v := NewVerifier(nil, VerifyConfig{})
	if _, err := v.Verify(context.Background(), []byte{0xef, 0xbe, 0x00, 0x01, 0x00, 0x00}); !errors.Is(err, ErrNoChaintracks) {
		t.Fatalf("expected ErrNoChaintracks, got %v", err)
	}
}

func TestVerifier_EmptyBEEF(t *testing.T) {
	ct := chaintracks.NewInMemoryClient()
	v := NewVerifier(ct, VerifyConfig{})
	if _, err := v.Verify(context.Background(), nil); !errors.Is(err, ErrEmptyBEEF) {
		t.Fatalf("expected ErrEmptyBEEF, got %v", err)
	}
}

func TestVerifier_ParseError(t *testing.T) {
	ct := chaintracks.NewInMemoryClient()
	v := NewVerifier(ct, VerifyConfig{})
	if _, err := v.Verify(context.Background(), []byte("not a beef body")); !errors.Is(err, ErrParse) {
		t.Fatalf("expected ErrParse, got %v", err)
	}
}

func TestValidatedCache_LRU(t *testing.T) {
	c := newValidatedCache(2)
	var a, b, d [32]byte
	a[0] = 1
	b[0] = 2
	d[0] = 3
	c.add(a)
	c.add(b)
	if !c.has(a) || !c.has(b) {
		t.Fatal("a,b should be present")
	}
	c.add(d) // evicts a
	if c.has(a) {
		t.Fatal("expected a to be evicted")
	}
	if !c.has(b) || !c.has(d) {
		t.Fatal("b and d should still be present")
	}
	c.add(b) // dedup, no eviction
	if !c.has(d) {
		t.Fatal("d should still be present after dedup add")
	}
}
