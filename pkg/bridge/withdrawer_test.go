package bridge

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// TestCSVDelayForAmount
// ---------------------------------------------------------------------------

func TestCSVDelayForAmount(t *testing.T) {
	tests := []struct {
		name      string
		satoshis  uint64
		wantDelay uint32
	}{
		{"5 BSV (500M sats)", 500_000_000, 6},
		{"50 BSV (5B sats)", 5_000_000_000, 20},
		{"500 BSV (50B sats)", 50_000_000_000, 100},
		{"1 sat", 1, 6},
		{"1 BSV", 100_000_000, 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CSVDelayForAmount(tt.satoshis)
			if got != tt.wantDelay {
				t.Errorf("CSVDelayForAmount(%d) = %d, want %d", tt.satoshis, got, tt.wantDelay)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCSVDelayForAmount_Boundaries
// ---------------------------------------------------------------------------

func TestCSVDelayForAmount_Boundaries(t *testing.T) {
	tests := []struct {
		name      string
		satoshis  uint64
		wantDelay uint32
	}{
		{"exactly 10 BSV", 1_000_000_000, 6},
		{"10 BSV + 1 sat", 1_000_000_001, 20},
		{"exactly 100 BSV", 10_000_000_000, 20},
		{"100 BSV + 1 sat", 10_000_000_001, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CSVDelayForAmount(tt.satoshis)
			if got != tt.wantDelay {
				t.Errorf("CSVDelayForAmount(%d) = %d, want %d", tt.satoshis, got, tt.wantDelay)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_Valid
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_Valid(t *testing.T) {
	addr := make([]byte, 20)
	addr[0] = 0xde
	addr[1] = 0xad

	claim := &WithdrawalClaim{
		BridgeTxID:     types.BytesToHash([]byte{0xaa, 0xbb}),
		BridgeVout:     0,
		BridgeSats:     10_000_000_000, // 100 BSV
		BridgeScript:   []byte{0x76, 0xa9, 0x14},
		BSVAddress:     addr,
		SatoshiAmount:  1_000_000_000, // 10 BSV
		Nonce:          42,
		WithdrawalRoot: types.BytesToHash([]byte{0xcc}),
		MerkleProof:    []types.Hash{types.BytesToHash([]byte{0xdd})},
		LeafIndex:      0,
		CSVDelay:       6,
	}

	result, err := BuildWithdrawalClaimTx(claim)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaimTx failed: %v", err)
	}

	if result == nil {
		t.Fatal("result is nil")
	}
	if len(result.RawTx) == 0 {
		t.Error("raw transaction is empty")
	}
	if result.NewBalance != 9_000_000_000 {
		t.Errorf("new balance = %d, want 9000000000", result.NewBalance)
	}
	if result.CSVDelay != 6 {
		t.Errorf("CSV delay = %d, want 6", result.CSVDelay)
	}
	if result.TxID == (types.Hash{}) {
		t.Error("txid is zero hash")
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_ZeroAmount
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_ZeroAmount(t *testing.T) {
	addr := make([]byte, 20)
	claim := &WithdrawalClaim{
		BridgeTxID:    types.BytesToHash([]byte{0xaa}),
		BridgeSats:    1_000_000,
		BridgeScript:  []byte{0x76},
		BSVAddress:    addr,
		SatoshiAmount: 0,
	}

	_, err := BuildWithdrawalClaimTx(claim)
	if err == nil {
		t.Fatal("expected error for zero amount")
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_InsufficientBridge
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_InsufficientBridge(t *testing.T) {
	addr := make([]byte, 20)
	claim := &WithdrawalClaim{
		BridgeTxID:    types.BytesToHash([]byte{0xaa}),
		BridgeSats:    500,
		BridgeScript:  []byte{0x76},
		BSVAddress:    addr,
		SatoshiAmount: 1000,
	}

	_, err := BuildWithdrawalClaimTx(claim)
	if err == nil {
		t.Fatal("expected error for insufficient bridge balance")
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_InvalidAddress
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_InvalidAddress(t *testing.T) {
	tests := []struct {
		name string
		addr []byte
	}{
		{"too short", make([]byte, 10)},
		{"too long", make([]byte, 25)},
		{"empty", []byte{}},
		{"nil", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := &WithdrawalClaim{
				BridgeTxID:    types.BytesToHash([]byte{0xaa}),
				BridgeSats:    1_000_000,
				BridgeScript:  []byte{0x76},
				BSVAddress:    tt.addr,
				SatoshiAmount: 1000,
			}

			_, err := BuildWithdrawalClaimTx(claim)
			if err == nil {
				t.Fatal("expected error for invalid address length")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_NilClaim
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_NilClaim(t *testing.T) {
	_, err := BuildWithdrawalClaimTx(nil)
	if err == nil {
		t.Fatal("expected error for nil claim")
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_EmptyBridgeScript
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_EmptyBridgeScript(t *testing.T) {
	addr := make([]byte, 20)
	claim := &WithdrawalClaim{
		BridgeTxID:    types.BytesToHash([]byte{0xaa}),
		BridgeSats:    1_000_000,
		BridgeScript:  nil,
		BSVAddress:    addr,
		SatoshiAmount: 1000,
	}

	_, err := BuildWithdrawalClaimTx(claim)
	if err == nil {
		t.Fatal("expected error for empty bridge script")
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_DefaultCSVDelay
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_DefaultCSVDelay(t *testing.T) {
	addr := make([]byte, 20)
	addr[0] = 0x01

	// CSVDelay = 0 should trigger auto-calculation.
	claim := &WithdrawalClaim{
		BridgeTxID:    types.BytesToHash([]byte{0xaa}),
		BridgeSats:    5_000_000_000, // 50 BSV
		BridgeScript:  []byte{0x76, 0xa9},
		BSVAddress:    addr,
		SatoshiAmount: 5_000_000_000, // 50 BSV
		Nonce:         1,
		CSVDelay:      0, // auto
	}

	result, err := BuildWithdrawalClaimTx(claim)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaimTx failed: %v", err)
	}

	// 50 BSV > 10 BSV, <= 100 BSV => delay 20.
	if result.CSVDelay != 20 {
		t.Errorf("CSV delay = %d, want 20 (auto-calculated for 50 BSV)", result.CSVDelay)
	}
}

// ---------------------------------------------------------------------------
// TestBuildCSVLockedP2PKH
// ---------------------------------------------------------------------------

func TestBuildCSVLockedP2PKH(t *testing.T) {
	addr := make([]byte, 20)
	for i := range addr {
		addr[i] = byte(i + 1)
	}

	script := buildCSVLockedP2PKH(6, addr)

	// Check structure:
	// <push 6> OP_CSV OP_DROP OP_DUP OP_HASH160 PUSH20 <addr> OP_EQUALVERIFY OP_CHECKSIG

	// The number 6 is encoded as OP_6 (0x56).
	if script[0] != 0x56 {
		t.Errorf("first byte = 0x%02x, want 0x56 (OP_6)", script[0])
	}

	// OP_CHECKSEQUENCEVERIFY = 0xb2
	if script[1] != 0xb2 {
		t.Errorf("second byte = 0x%02x, want 0xb2 (OP_CSV)", script[1])
	}

	// OP_DROP = 0x75
	if script[2] != 0x75 {
		t.Errorf("third byte = 0x%02x, want 0x75 (OP_DROP)", script[2])
	}

	// OP_DUP = 0x76
	if script[3] != 0x76 {
		t.Errorf("byte 3 = 0x%02x, want 0x76 (OP_DUP)", script[3])
	}

	// OP_HASH160 = 0xa9
	if script[4] != 0xa9 {
		t.Errorf("byte 4 = 0x%02x, want 0xa9 (OP_HASH160)", script[4])
	}

	// PUSH20 = 0x14
	if script[5] != 0x14 {
		t.Errorf("byte 5 = 0x%02x, want 0x14 (PUSH20)", script[5])
	}

	// Address hash (20 bytes).
	if !bytes.Equal(script[6:26], addr) {
		t.Error("address hash mismatch")
	}

	// OP_EQUALVERIFY = 0x88
	if script[26] != 0x88 {
		t.Errorf("byte 26 = 0x%02x, want 0x88 (OP_EQUALVERIFY)", script[26])
	}

	// OP_CHECKSIG = 0xac
	if script[27] != 0xac {
		t.Errorf("byte 27 = 0x%02x, want 0xac (OP_CHECKSIG)", script[27])
	}
}

// ---------------------------------------------------------------------------
// TestBuildCSVLockedP2PKH_LargeDelay
// ---------------------------------------------------------------------------

func TestBuildCSVLockedP2PKH_LargeDelay(t *testing.T) {
	addr := make([]byte, 20)
	script := buildCSVLockedP2PKH(100, addr)

	// 100 is > 16 so it should be encoded as a minimal script number push.
	// 100 = 0x64, fits in 1 byte, push as: 0x01 0x64
	if script[0] != 0x01 {
		t.Errorf("first byte = 0x%02x, want 0x01 (push 1 byte)", script[0])
	}
	if script[1] != 0x64 {
		t.Errorf("second byte = 0x%02x, want 0x64 (100)", script[1])
	}

	// OP_CSV should follow.
	if script[2] != 0xb2 {
		t.Errorf("byte 2 = 0x%02x, want 0xb2 (OP_CSV)", script[2])
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalReceipt
// ---------------------------------------------------------------------------

func TestBuildWithdrawalReceipt(t *testing.T) {
	addr := make([]byte, 20)
	addr[0] = 0xab
	addr[19] = 0xcd

	receipt := buildWithdrawalReceipt(42, 1_000_000_000, addr)

	// Must start with OP_FALSE OP_RETURN.
	if receipt[0] != 0x00 {
		t.Errorf("first byte = 0x%02x, want 0x00 (OP_FALSE)", receipt[0])
	}
	if receipt[1] != 0x6a {
		t.Errorf("second byte = 0x%02x, want 0x6a (OP_RETURN)", receipt[1])
	}

	// Extract the data payload (skip OP_FALSE, OP_RETURN, and push length byte).
	// For 37-byte payload (4+1+8+8+20 = 41), it's <= 75 so single push byte.
	pushLen := receipt[2]
	if pushLen != 41 { // "BSVM" (4) + type (1) + nonce (8) + amount (8) + addr (20) = 41
		t.Errorf("push length = %d, want 41", pushLen)
	}

	data := receipt[3:]

	// Check magic.
	if string(data[0:4]) != "BSVM" {
		t.Errorf("magic = %q, want BSVM", string(data[0:4]))
	}

	// Check message type.
	if data[4] != 0x04 {
		t.Errorf("message type = 0x%02x, want 0x04", data[4])
	}

	// Check nonce (big-endian).
	nonce := binary.BigEndian.Uint64(data[5:13])
	if nonce != 42 {
		t.Errorf("nonce = %d, want 42", nonce)
	}

	// Check amount (big-endian).
	amount := binary.BigEndian.Uint64(data[13:21])
	if amount != 1_000_000_000 {
		t.Errorf("amount = %d, want 1000000000", amount)
	}

	// Check address.
	if !bytes.Equal(data[21:41], addr) {
		t.Error("address hash mismatch in receipt")
	}
}

// ---------------------------------------------------------------------------
// TestPushScriptNumber
// ---------------------------------------------------------------------------

func TestPushScriptNumber(t *testing.T) {
	tests := []struct {
		name string
		n    int64
		want []byte
	}{
		{"zero", 0, []byte{0x00}},
		{"one", 1, []byte{0x51}},              // OP_1
		{"six", 6, []byte{0x56}},              // OP_6
		{"sixteen", 16, []byte{0x60}},         // OP_16
		{"seventeen", 17, []byte{0x01, 0x11}}, // push 1 byte: 0x11
		{"twenty", 20, []byte{0x01, 0x14}},
		{"hundred", 100, []byte{0x01, 0x64}},
		{"negative one", -1, []byte{0x4f}},     // OP_1NEGATE
		{"128", 128, []byte{0x02, 0x80, 0x00}}, // needs sign byte
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pushScriptNumber(tt.n)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("pushScriptNumber(%d) = %x, want %x", tt.n, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildWithdrawalClaimTx_FullBalance
// ---------------------------------------------------------------------------

func TestBuildWithdrawalClaimTx_FullBalance(t *testing.T) {
	addr := make([]byte, 20)
	addr[0] = 0x01

	// Withdraw entire bridge balance.
	claim := &WithdrawalClaim{
		BridgeTxID:    types.BytesToHash([]byte{0xaa}),
		BridgeSats:    1_000_000,
		BridgeScript:  []byte{0x76, 0xa9},
		BSVAddress:    addr,
		SatoshiAmount: 1_000_000,
		Nonce:         0,
		CSVDelay:      6,
	}

	result, err := BuildWithdrawalClaimTx(claim)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaimTx failed: %v", err)
	}

	if result.NewBalance != 0 {
		t.Errorf("new balance = %d, want 0", result.NewBalance)
	}
}

// ---------------------------------------------------------------------------
// Signing-path tests
// ---------------------------------------------------------------------------

// stubSigner returns a fixed unlock script and records every call so
// tests can assert what was signed.
type stubSigner struct {
	unlockHex string
	calls     int
	wantErr   error
	lastIdx   int
	lastSats  uint64
	lastScrpt string
}

func (s *stubSigner) SignInput(_ string, idx int, prevScript string, prevSats uint64) (string, error) {
	s.calls++
	s.lastIdx = idx
	s.lastSats = prevSats
	s.lastScrpt = prevScript
	if s.wantErr != nil {
		return "", s.wantErr
	}
	return s.unlockHex, nil
}

func TestBuildWithdrawalClaimTx_Signed(t *testing.T) {
	addr := make([]byte, 20)
	addr[0] = 0xab
	signer := &stubSigner{unlockHex: "abcdef"}

	claim := &WithdrawalClaim{
		BridgeTxID:    types.BytesToHash([]byte{0xaa}),
		BridgeSats:    1_000_000,
		BridgeScript:  []byte{0x76, 0xa9, 0x14},
		BSVAddress:    addr,
		SatoshiAmount: 1000,
		Nonce:         1,
		CSVDelay:      6,
		Signer:        signer,
	}
	got, err := BuildWithdrawalClaimTx(claim)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaimTx: %v", err)
	}
	if signer.calls != 1 {
		t.Errorf("signer call count = %d, want 1", signer.calls)
	}
	if signer.lastIdx != 0 {
		t.Errorf("signer received input index %d, want 0", signer.lastIdx)
	}
	if signer.lastSats != claim.BridgeSats {
		t.Errorf("signer received satoshis %d, want %d", signer.lastSats, claim.BridgeSats)
	}
	if signer.lastScrpt != hex.EncodeToString(claim.BridgeScript) {
		t.Errorf("signer received script %s, want %s", signer.lastScrpt, hex.EncodeToString(claim.BridgeScript))
	}
	wantUnlock, _ := hex.DecodeString(signer.unlockHex)
	if !bytes.Contains(got.RawTx, wantUnlock) {
		t.Error("signed raw tx does not contain the unlock script returned by signer")
	}
}

func TestBuildWithdrawalClaimTx_SignerError(t *testing.T) {
	addr := make([]byte, 20)
	signer := &stubSigner{wantErr: errors.New("boom")}
	claim := &WithdrawalClaim{
		BridgeTxID:    types.BytesToHash([]byte{0xaa}),
		BridgeSats:    1_000_000,
		BridgeScript:  []byte{0x76},
		BSVAddress:    addr,
		SatoshiAmount: 1000,
		Signer:        signer,
	}
	_, err := BuildWithdrawalClaimTx(claim)
	if err == nil {
		t.Fatal("expected signer error to surface, got nil")
	}
}

// ---------------------------------------------------------------------------
// Withdrawer integration tests
// ---------------------------------------------------------------------------

// flakyBroadcaster fails the first `failures` calls then succeeds.
type flakyBroadcaster struct {
	failures int
	calls    int
	txid     types.Hash
}

func (f *flakyBroadcaster) Broadcast(_ []byte) (types.Hash, error) {
	f.calls++
	if f.calls <= f.failures {
		return types.Hash{}, errors.New("transient broadcast error")
	}
	return f.txid, nil
}

func TestWithdrawer_BuildsCompleteClaim(t *testing.T) {
	bsvAddr := make([]byte, 20)
	for i := range bsvAddr {
		bsvAddr[i] = byte(i + 1)
	}

	leaf := WithdrawalHash(bsvAddr, 100_000_000, 1)
	pending := []*PendingWithdrawal{{
		Nonce:          1,
		BSVAddress:     bsvAddr,
		AmountSatoshis: 100_000_000,
		L2BlockNum:     10,
		LeafIndex:      0,
		BatchHashes:    []types.Hash{leaf},
		WithdrawalHash: leaf,
	}}
	scanner := &mockWithdrawalScanner{withdrawals: pending}

	stateScript := []byte{0x76, 0xa9, 0x14, 0x00, 0x00}
	opReturn := buildOpReturnWithRoot(leaf)
	advanceTx := &BSVTransaction{
		TxID: types.HexToHash("0xbeef"),
		Outputs: []BSVOutput{
			{Script: stateScript, Value: 1000},
			{Script: opReturn, Value: 0},
		},
	}
	finder := &mockAdvanceFinder{tx: advanceTx}

	bridgeUTXO := &BridgeUTXO{
		TxID:             types.HexToHash("0xaaaa"),
		Vout:             0,
		Balance:          1_000_000_000,
		LastClaimedNonce: 0,
		Script:           []byte{0x76, 0xa9, 0x14},
	}

	bcaster := &flakyBroadcaster{txid: types.HexToHash("0xfeed")}
	signer := &stubSigner{unlockHex: "11"}

	w := NewWithdrawer(bcaster, bridgeUTXO, scanner, finder, DefaultWithdrawalConfig()).
		WithSigner(signer)

	if err := w.ProcessFinalizedWithdrawals(); err != nil {
		t.Fatalf("ProcessFinalizedWithdrawals: %v", err)
	}
	if signer.calls != 1 {
		t.Errorf("signer called %d times, want 1", signer.calls)
	}
	if bcaster.calls != 1 {
		t.Errorf("broadcaster called %d times, want 1", bcaster.calls)
	}
	if bridgeUTXO.LastClaimedNonce != 1 {
		t.Errorf("LastClaimedNonce = %d, want 1", bridgeUTXO.LastClaimedNonce)
	}
}

func TestWithdrawer_RetriesBroadcastFailure(t *testing.T) {
	bsvAddr := make([]byte, 20)
	leaf := WithdrawalHash(bsvAddr, 50_000_000, 1)
	pending := []*PendingWithdrawal{{
		Nonce:          1,
		BSVAddress:     bsvAddr,
		AmountSatoshis: 50_000_000,
		L2BlockNum:     10,
		BatchHashes:    []types.Hash{leaf},
		LeafIndex:      0,
	}}
	scanner := &mockWithdrawalScanner{withdrawals: pending}
	advanceTx := &BSVTransaction{Outputs: []BSVOutput{
		{Script: []byte{0x76}, Value: 1000},
		{Script: buildOpReturnWithRoot(leaf), Value: 0},
	}}

	bridgeUTXO := &BridgeUTXO{
		TxID:    types.HexToHash("0xaaaa"),
		Balance: 100_000_000_000,
		Script:  []byte{0x76, 0xa9},
	}
	bcaster := &flakyBroadcaster{failures: 2, txid: types.HexToHash("0xfeed")}

	w := NewWithdrawer(bcaster, bridgeUTXO, scanner,
		&mockAdvanceFinder{tx: advanceTx}, DefaultWithdrawalConfig())
	w.SetBroadcastRetryPolicy(3, []time.Duration{0, 0, 0})

	if err := w.ProcessFinalizedWithdrawals(); err != nil {
		t.Fatalf("ProcessFinalizedWithdrawals: %v", err)
	}
	if bcaster.calls != 3 {
		t.Errorf("broadcaster calls = %d, want 3", bcaster.calls)
	}
	if bridgeUTXO.LastClaimedNonce != 1 {
		t.Errorf("LastClaimedNonce = %d, want 1", bridgeUTXO.LastClaimedNonce)
	}
}

func TestWithdrawer_BroadcastExhausted(t *testing.T) {
	bsvAddr := make([]byte, 20)
	leaf := WithdrawalHash(bsvAddr, 50_000_000, 1)
	pending := []*PendingWithdrawal{{
		Nonce:          1,
		BSVAddress:     bsvAddr,
		AmountSatoshis: 50_000_000,
		L2BlockNum:     10,
		BatchHashes:    []types.Hash{leaf},
		LeafIndex:      0,
	}}
	scanner := &mockWithdrawalScanner{withdrawals: pending}
	advanceTx := &BSVTransaction{Outputs: []BSVOutput{
		{Script: []byte{0x76}, Value: 1000},
		{Script: buildOpReturnWithRoot(leaf), Value: 0},
	}}

	bridgeUTXO := &BridgeUTXO{
		TxID:    types.HexToHash("0xaaaa"),
		Balance: 100_000_000_000,
		Script:  []byte{0x76, 0xa9},
	}
	bcaster := &flakyBroadcaster{failures: 5}

	w := NewWithdrawer(bcaster, bridgeUTXO, scanner,
		&mockAdvanceFinder{tx: advanceTx}, DefaultWithdrawalConfig())
	w.SetBroadcastRetryPolicy(2, []time.Duration{0, 0})

	err := w.ProcessFinalizedWithdrawals()
	if err == nil {
		t.Fatal("expected broadcast exhaustion error")
	}
	if bridgeUTXO.LastClaimedNonce != 0 {
		t.Errorf("LastClaimedNonce = %d, want 0 (claim must not advance on broadcast failure)",
			bridgeUTXO.LastClaimedNonce)
	}
}

func TestWithdrawer_RootMismatchSkips(t *testing.T) {
	bsvAddr := make([]byte, 20)
	leaf := WithdrawalHash(bsvAddr, 50_000_000, 1)
	pending := []*PendingWithdrawal{{
		Nonce:          1,
		BSVAddress:     bsvAddr,
		AmountSatoshis: 50_000_000,
		L2BlockNum:     10,
		BatchHashes:    []types.Hash{leaf},
		LeafIndex:      0,
	}}
	scanner := &mockWithdrawalScanner{withdrawals: pending}

	wrongRoot := types.HexToHash("0xdeadbeef")
	advanceTx := &BSVTransaction{Outputs: []BSVOutput{
		{Script: []byte{0x76}, Value: 1000},
		{Script: buildOpReturnWithRoot(wrongRoot), Value: 0},
	}}

	bridgeUTXO := &BridgeUTXO{TxID: types.HexToHash("0xaa"), Balance: 1e9, Script: []byte{0x76}}
	bcaster := &flakyBroadcaster{}

	w := NewWithdrawer(bcaster, bridgeUTXO, scanner,
		&mockAdvanceFinder{tx: advanceTx}, DefaultWithdrawalConfig())

	if err := w.ProcessFinalizedWithdrawals(); err != nil {
		t.Fatalf("ProcessFinalizedWithdrawals: %v", err)
	}
	if bcaster.calls != 0 {
		t.Errorf("broadcaster called %d times, want 0 (root mismatch should skip)", bcaster.calls)
	}
	if bridgeUTXO.LastClaimedNonce != 0 {
		t.Error("LastClaimedNonce advanced despite root mismatch")
	}
}

// buildOpReturnWithRoot builds the advance OP_RETURN script the rollup
// contracts emit: "BSVM\x02" || withdrawalRoot(32) || zero-padded
// batch-data tail. Length stays >75 so the push uses OP_PUSHDATA2.
func buildOpReturnWithRoot(root types.Hash) []byte {
	payload := make([]byte, 5+32+128)
	copy(payload[:5], []byte("BSVM\x02"))
	copy(payload[5:5+32], root[:])

	script := []byte{0x6a, 0x4d}
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(payload)))
	script = append(script, lenBuf...)
	script = append(script, payload...)
	return script
}
