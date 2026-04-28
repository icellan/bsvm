package bridge

import (
	"bytes"
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// makeFeeUTXO returns a FeeUTXO with deterministic content for tests.
func makeFeeUTXO(sats uint64) *FeeUTXO {
	return &FeeUTXO{
		TxID:          types.HexToHash("0xfee1"),
		Vout:          0,
		Satoshis:      sats,
		LockingScript: []byte{0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac},
	}
}

// TestBuildWithdrawalClaimTx_WithFeeUTXO_ConservesBridgeBalance
// asserts spec 07's claim-tx shape: Output 0 = BridgeSats - SatoshiAmount
// exactly (no fee leakage from bridge). Output 2 = FeeUTXO.Satoshis - fee.
func TestBuildWithdrawalClaimTx_WithFeeUTXO_ConservesBridgeBalance(t *testing.T) {
	const (
		bridgeSats    = uint64(100_000_000_000) // 1 000 BSV
		withdrawSats  = uint64(50_000_000)      //   0.5 BSV
		feeUTXOSats   = uint64(10_000)
		feeSatPerByte = int64(1)
	)

	addr := bytes.Repeat([]byte{0xab}, 20)
	claim := &WithdrawalClaim{
		BridgeTxID:    types.HexToHash("0xb1"),
		BridgeVout:    0,
		BridgeSats:    bridgeSats,
		BridgeScript:  []byte{0x52, 0x53}, // dummy bridge locking script
		BSVAddress:    addr,
		SatoshiAmount: withdrawSats,
		Nonce:         0,
		FeeSatPerByte: feeSatPerByte,
		FeeUTXO:       makeFeeUTXO(feeUTXOSats),
	}

	out, err := BuildWithdrawalClaimTx(claim)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaimTx: %v", err)
	}
	if out.NewBalance != bridgeSats-withdrawSats {
		t.Errorf("NewBalance = %d, want %d (bridge conserved exactly)",
			out.NewBalance, bridgeSats-withdrawSats)
	}

	// Decode the raw tx and assert structure.
	dec, err := decodeRawTx(out.RawTx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := len(dec.inputs); got != 2 {
		t.Errorf("inputs = %d, want 2", got)
	}
	if got := len(dec.outputs); got != 4 {
		t.Errorf("outputs = %d, want 4", got)
	}
	if dec.outputs[0].value != bridgeSats-withdrawSats {
		t.Errorf("Output 0 (bridge change) = %d, want %d (no fee subtracted)",
			dec.outputs[0].value, bridgeSats-withdrawSats)
	}
	if dec.outputs[1].value != withdrawSats {
		t.Errorf("Output 1 (payee) = %d, want %d", dec.outputs[1].value, withdrawSats)
	}
	if dec.outputs[2].value == 0 {
		t.Errorf("Output 2 (claimer change) = 0, expected positive")
	}
	if dec.outputs[2].value >= feeUTXOSats {
		t.Errorf("Output 2 = %d, want < FeeUTXO.Satoshis %d (fee should be deducted)",
			dec.outputs[2].value, feeUTXOSats)
	}
	if dec.outputs[3].value != 0 {
		t.Errorf("Output 3 (OP_RETURN) value = %d, want 0", dec.outputs[3].value)
	}
	// Output 3 must be OP_RETURN (OP_FALSE OP_RETURN ...).
	if len(dec.outputs[3].script) < 2 ||
		dec.outputs[3].script[0] != 0x00 || dec.outputs[3].script[1] != 0x6a {
		t.Errorf("Output 3 not OP_RETURN: %x", dec.outputs[3].script)
	}

	// Conservation: in - out should equal fee.
	totalIn := bridgeSats + feeUTXOSats
	totalOut := dec.outputs[0].value + dec.outputs[1].value + dec.outputs[2].value + dec.outputs[3].value
	if totalIn-totalOut == 0 && feeSatPerByte > 0 {
		t.Errorf("expected non-zero fee, got in=%d out=%d", totalIn, totalOut)
	}
}

// TestBuildWithdrawalClaimTx_FeeUTXOInsufficient asserts that an
// undersized fee UTXO produces a clear error before broadcast.
func TestBuildWithdrawalClaimTx_FeeUTXOInsufficient(t *testing.T) {
	addr := bytes.Repeat([]byte{0xab}, 20)
	claim := &WithdrawalClaim{
		BridgeTxID:    types.HexToHash("0xb1"),
		BridgeVout:    0,
		BridgeSats:    100_000_000_000,
		BridgeScript:  []byte{0x52, 0x53},
		BSVAddress:    addr,
		SatoshiAmount: 50_000_000,
		Nonce:         0,
		FeeSatPerByte: 100,             // 100 sat/byte — wildly above realistic tx size
		FeeUTXO:       makeFeeUTXO(50), // 50 sats — far below required fee
	}

	_, err := BuildWithdrawalClaimTx(claim)
	if err == nil {
		t.Fatal("expected fee-UTXO-insufficient error")
	}
	if !strings.Contains(err.Error(), "fee") {
		t.Errorf("error %q does not mention fee", err.Error())
	}
}

// TestBuildWithdrawalClaimTx_LegacyPathUnchanged verifies the
// nil-FeeUTXO path produces the original 3-output, 1-input shape with
// fee absorbed from bridge change. This is the EE-shipped path that
// FF's withdrawal_claim_test asserts against.
func TestBuildWithdrawalClaimTx_LegacyPathUnchanged(t *testing.T) {
	const (
		bridgeSats   = uint64(100_000_000_000)
		withdrawSats = uint64(50_000_000)
	)
	addr := bytes.Repeat([]byte{0xab}, 20)
	claim := &WithdrawalClaim{
		BridgeTxID:    types.HexToHash("0xb1"),
		BridgeVout:    0,
		BridgeSats:    bridgeSats,
		BridgeScript:  []byte{0x52, 0x53},
		BSVAddress:    addr,
		SatoshiAmount: withdrawSats,
		Nonce:         0,
		FeeSatPerByte: 1,
		// FeeUTXO intentionally nil — legacy path.
	}
	out, err := BuildWithdrawalClaimTx(claim)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaimTx: %v", err)
	}
	dec, err := decodeRawTx(out.RawTx)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dec.inputs) != 1 {
		t.Errorf("legacy inputs = %d, want 1", len(dec.inputs))
	}
	if len(dec.outputs) != 3 {
		t.Errorf("legacy outputs = %d, want 3", len(dec.outputs))
	}
	// Bridge change reflects fee subtracted (legacy semantics).
	if dec.outputs[0].value >= bridgeSats-withdrawSats {
		t.Errorf("legacy bridge change = %d, expected < %d (fee absorbed)",
			dec.outputs[0].value, bridgeSats-withdrawSats)
	}
}

// ---------------------------------------------------------------------------
// minimal raw-tx decoder local to this test file (mirrors the e2e harness
// shape so we don't pull test/e2e into a unit test)
// ---------------------------------------------------------------------------

type decTx struct {
	version  uint32
	inputs   []decIn
	outputs  []decOut
	lockTime uint32
}
type decIn struct {
	prevTxID types.Hash
	prevVout uint32
	script   []byte
	sequence uint32
}
type decOut struct {
	value  uint64
	script []byte
}

func decodeRawTx(raw []byte) (*decTx, error) {
	if len(raw) < 4 {
		return nil, errShort
	}
	pos := 0
	d := &decTx{}
	d.version = leUint32(raw[pos:])
	pos += 4
	nIn, used, err := readVarInt(raw[pos:])
	if err != nil {
		return nil, err
	}
	pos += used
	for i := uint64(0); i < nIn; i++ {
		var in decIn
		if pos+32+4 > len(raw) {
			return nil, errShort
		}
		copy(in.prevTxID[:], raw[pos:pos+32])
		pos += 32
		in.prevVout = leUint32(raw[pos:])
		pos += 4
		sl, used2, err := readVarInt(raw[pos:])
		if err != nil {
			return nil, err
		}
		pos += used2
		if pos+int(sl)+4 > len(raw) {
			return nil, errShort
		}
		in.script = append([]byte(nil), raw[pos:pos+int(sl)]...)
		pos += int(sl)
		in.sequence = leUint32(raw[pos:])
		pos += 4
		d.inputs = append(d.inputs, in)
	}
	nOut, used3, err := readVarInt(raw[pos:])
	if err != nil {
		return nil, err
	}
	pos += used3
	for i := uint64(0); i < nOut; i++ {
		var out decOut
		if pos+8 > len(raw) {
			return nil, errShort
		}
		out.value = leUint64(raw[pos:])
		pos += 8
		sl, used4, err := readVarInt(raw[pos:])
		if err != nil {
			return nil, err
		}
		pos += used4
		if pos+int(sl) > len(raw) {
			return nil, errShort
		}
		out.script = append([]byte(nil), raw[pos:pos+int(sl)]...)
		pos += int(sl)
		d.outputs = append(d.outputs, out)
	}
	if pos+4 > len(raw) {
		return nil, errShort
	}
	d.lockTime = leUint32(raw[pos:])
	return d, nil
}

func leUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func leUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func readVarInt(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errShort
	}
	switch b[0] {
	case 0xff:
		if len(b) < 9 {
			return 0, 0, errShort
		}
		return leUint64(b[1:]), 9, nil
	case 0xfe:
		if len(b) < 5 {
			return 0, 0, errShort
		}
		return uint64(leUint32(b[1:])), 5, nil
	case 0xfd:
		if len(b) < 3 {
			return 0, 0, errShort
		}
		return uint64(b[1]) | uint64(b[2])<<8, 3, nil
	default:
		return uint64(b[0]), 1, nil
	}
}

var errShort = errStr("short raw tx")

type errStr string

func (e errStr) Error() string { return string(e) }
