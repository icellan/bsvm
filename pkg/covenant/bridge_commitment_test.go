package covenant

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// hash256 is a local copy of the BSV double-SHA256 used by the bridge
// covenant contract (runar.Hash256) for computing withdrawal nullifiers
// and the running commitment chain. Kept local to the test so a
// regression in a hypothetical production helper cannot mask a
// regression in the commitment logic itself — the test must assert the
// byte-for-byte definition.
func hash256(data []byte) types.Hash {
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(h1[:])
	return types.Hash(h2)
}

// expectedCommitmentAfter computes the expected running commitment
// chain given a sequence of withdrawals. It mirrors the Rúnar bridge
// contract's step:
//
//	newCommitment = hash256(prevCommitment || nullifier)
//
// where nullifier = hash256(bsvAddress || amountBE8 || nonceBE8).
func expectedCommitmentAfter(start types.Hash, steps []struct {
	addr   []byte
	amount uint64
	nonce  uint64
}) types.Hash {
	c := start
	for _, s := range steps {
		buf := make([]byte, 0, len(s.addr)+16)
		buf = append(buf, s.addr...)
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], s.amount)
		buf = append(buf, be[:]...)
		binary.BigEndian.PutUint64(be[:], s.nonce)
		buf = append(buf, be[:]...)
		nullifier := hash256(buf)
		c = hash256(append(c[:], nullifier[:]...))
	}
	return c
}

// TestBridgeCovenantWithdrawalsCommitmentChain asserts that the
// BridgeManager folds a running hash-chain commitment over every
// applied withdrawal, that the commitment is initialized to the zero
// hash at genesis, and that RollbackWithdrawal does NOT roll back the
// commitment (consistent with the anti-replay / tamper-evident log
// invariant).
func TestBridgeCovenantWithdrawalsCommitmentChain(t *testing.T) {
	const (
		initialBalance = uint64(1_000_000_000)
		startNonce     = uint64(0)
	)
	initial := BridgeState{
		Balance:         initialBalance,
		WithdrawalNonce: startNonce,
	}
	// Zero hash at genesis.
	var zero types.Hash
	if initial.WithdrawalsCommitment != zero {
		t.Fatalf("genesis BridgeState.WithdrawalsCommitment = %x, want zero", initial.WithdrawalsCommitment)
	}

	genesisTxID := types.HexToHash("0xa1")
	stateCovenantTxID := types.HexToHash("0xa2")
	bm := NewBridgeManager(genesisTxID, 0, initialBalance, initial, stateCovenantTxID)

	addrs := [][]byte{
		make([]byte, 20),
		make([]byte, 20),
		make([]byte, 20),
	}
	addrs[0][0] = 0x11
	addrs[1][0] = 0x22
	addrs[2][0] = 0x33
	amounts := []uint64{1_000, 2_500, 7_777}

	root := types.HexToHash("0xbe")
	proof := [][]byte{make([]byte, 32)}

	type step = struct {
		addr   []byte
		amount uint64
		nonce  uint64
	}
	var history []step
	for i := 0; i < 3; i++ {
		nonce := startNonce + uint64(i)
		_, err := bm.BuildWithdrawalData(addrs[i], amounts[i], root, proof, 0)
		if err != nil {
			t.Fatalf("BuildWithdrawalData[%d]: %v", i, err)
		}
		var txid types.Hash
		txid[0] = 0xb0 + byte(i)
		bm.ApplyWithdrawal(txid, amounts[i])

		history = append(history, step{addr: addrs[i], amount: amounts[i], nonce: nonce})
		want := expectedCommitmentAfter(zero, history)
		got := bm.CurrentState().WithdrawalsCommitment
		if got != want {
			t.Fatalf("after withdrawal %d: commitment = %x, want %x", i, got, want)
		}
	}

	// Snapshot the commitment after the third withdrawal.
	commitAfter3 := bm.CurrentState().WithdrawalsCommitment
	if bytes.Equal(commitAfter3[:], zero[:]) {
		t.Fatalf("commitment still zero after 3 withdrawals")
	}

	// Roll back the most recent withdrawal. The commitment is a
	// tamper-evident log — once a withdrawal has been observed, the
	// commitment MUST NOT retreat. If it did, a BSV-reorg replay could
	// hide the earlier observation from auditors.
	bm.RollbackWithdrawal(types.HexToHash("0xc0"), amounts[2])
	got := bm.CurrentState().WithdrawalsCommitment
	if got != commitAfter3 {
		t.Errorf("commitment rolled back: got %x, want %x (commitment must not retreat)",
			got, commitAfter3)
	}
	// Nonce should have rolled back.
	if want := startNonce + 2; bm.CurrentState().WithdrawalNonce != want {
		t.Errorf("nonce not rolled back: got %d, want %d",
			bm.CurrentState().WithdrawalNonce, want)
	}
}

// TestBridgeState_EncodeDecode_CommitmentRoundTrip verifies the 32-byte
// WithdrawalsCommitment field survives the encode/decode round-trip
// with a distinctive non-zero value.
func TestBridgeState_EncodeDecode_CommitmentRoundTrip(t *testing.T) {
	var c types.Hash
	for i := range c {
		c[i] = byte(i) ^ 0x5a
	}
	s := BridgeState{
		Balance:               12345,
		WithdrawalNonce:       7,
		WithdrawalsCommitment: c,
	}
	encoded := s.Encode()
	if got := len(encoded); got != bridgeStateEncodedSize {
		t.Fatalf("encoded len = %d, want %d", got, bridgeStateEncodedSize)
	}
	decoded, err := DecodeBridgeState(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Balance != s.Balance {
		t.Errorf("balance: got %d, want %d", decoded.Balance, s.Balance)
	}
	if decoded.WithdrawalNonce != s.WithdrawalNonce {
		t.Errorf("nonce: got %d, want %d", decoded.WithdrawalNonce, s.WithdrawalNonce)
	}
	if decoded.WithdrawalsCommitment != s.WithdrawalsCommitment {
		t.Errorf("commitment: got %x, want %x",
			decoded.WithdrawalsCommitment, s.WithdrawalsCommitment)
	}
}
