package bridge

import (
	"bytes"
	"encoding/binary"
	"testing"

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
