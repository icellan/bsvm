package covenant

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// TestBSVTxSerialize
// ---------------------------------------------------------------------------

func TestBSVTxSerialize(t *testing.T) {
	tx := &BSVTx{
		Version: 1,
		Inputs: []BSVInput{
			{
				PrevTxID: types.BytesToHash([]byte{0xaa, 0xbb}),
				PrevVout: 0,
				Script:   []byte{0x01, 0x02, 0x03},
				Sequence: 0xffffffff,
			},
		},
		Outputs: []BSVOutput{
			{
				Value:  10000,
				Script: []byte{0x76, 0xa9, 0x14},
			},
		},
		LockTime: 0,
	}

	raw := tx.Serialize()
	if len(raw) == 0 {
		t.Fatal("serialized transaction is empty")
	}

	// Check version (first 4 bytes).
	version := binary.LittleEndian.Uint32(raw[0:4])
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}

	// Check input count varint (byte 4).
	if raw[4] != 1 {
		t.Errorf("input count = %d, want 1", raw[4])
	}

	// Check locktime (last 4 bytes).
	lt := binary.LittleEndian.Uint32(raw[len(raw)-4:])
	if lt != 0 {
		t.Errorf("locktime = %d, want 0", lt)
	}

	// Verify deterministic — serialize twice.
	raw2 := tx.Serialize()
	if !bytes.Equal(raw, raw2) {
		t.Error("serialization is not deterministic")
	}
}

// ---------------------------------------------------------------------------
// TestBSVTxTxID
// ---------------------------------------------------------------------------

func TestBSVTxTxID(t *testing.T) {
	tx := &BSVTx{
		Version: 1,
		Inputs: []BSVInput{
			{
				PrevTxID: types.Hash{},
				PrevVout: 0xffffffff,
				Script:   []byte{0x04, 0xff, 0xff, 0x00, 0x1d},
				Sequence: 0xffffffff,
			},
		},
		Outputs: []BSVOutput{
			{
				Value:  5000000000,
				Script: []byte{0x41, 0x04},
			},
		},
		LockTime: 0,
	}

	raw := tx.Serialize()
	txid := tx.TxID()

	// Manually compute expected double-SHA256 (reversed).
	first := sha256.Sum256(raw)
	second := sha256.Sum256(first[:])
	var expected types.Hash
	for i := 0; i < 32; i++ {
		expected[i] = second[31-i]
	}

	if txid != expected {
		t.Errorf("TxID mismatch:\n  got  %x\n  want %x", txid, expected)
	}

	// TxID should be deterministic.
	txid2 := tx.TxID()
	if txid != txid2 {
		t.Error("TxID is not deterministic")
	}
}

// ---------------------------------------------------------------------------
// TestWriteVarInt
// ---------------------------------------------------------------------------

func TestWriteVarInt(t *testing.T) {
	tests := []struct {
		name   string
		value  uint64
		wantLen int
		wantPrefix byte
	}{
		{"zero", 0, 1, 0x00},
		{"one", 1, 1, 0x01},
		{"max single byte", 252, 1, 252},
		{"253 uses fd prefix", 253, 3, 0xfd},
		{"65535 uses fd prefix", 65535, 3, 0xfd},
		{"65536 uses fe prefix", 65536, 5, 0xfe},
		{"large uint32 uses fe prefix", 0xffffffff, 5, 0xfe},
		{"large uint64 uses ff prefix", 0x100000000, 9, 0xff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := writeVarInt(tt.value)
			if len(result) != tt.wantLen {
				t.Errorf("length = %d, want %d", len(result), tt.wantLen)
			}
			if result[0] != tt.wantPrefix {
				t.Errorf("prefix = 0x%02x, want 0x%02x", result[0], tt.wantPrefix)
			}

			// Verify the value is correctly encoded.
			switch {
			case tt.wantLen == 1:
				if uint64(result[0]) != tt.value {
					t.Errorf("decoded value = %d, want %d", result[0], tt.value)
				}
			case tt.wantLen == 3:
				v := binary.LittleEndian.Uint16(result[1:3])
				if uint64(v) != tt.value {
					t.Errorf("decoded value = %d, want %d", v, tt.value)
				}
			case tt.wantLen == 5:
				v := binary.LittleEndian.Uint32(result[1:5])
				if uint64(v) != tt.value {
					t.Errorf("decoded value = %d, want %d", v, tt.value)
				}
			case tt.wantLen == 9:
				v := binary.LittleEndian.Uint64(result[1:9])
				if v != tt.value {
					t.Errorf("decoded value = %d, want %d", v, tt.value)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildOpReturnScript
// ---------------------------------------------------------------------------

func TestBuildOpReturnScript(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantMin  int
	}{
		{"small data", []byte("hello"), 2 + 1 + 5},
		{"76 bytes uses pushdata1", make([]byte, 76), 2 + 2 + 76},
		{"256 bytes uses pushdata2", make([]byte, 256), 2 + 3 + 256},
		{"single byte", []byte{0x42}, 2 + 1 + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := buildOpReturnScript(tt.data)

			// Must start with OP_FALSE OP_RETURN.
			if script[0] != 0x00 {
				t.Errorf("first byte = 0x%02x, want 0x00 (OP_FALSE)", script[0])
			}
			if script[1] != 0x6a {
				t.Errorf("second byte = 0x%02x, want 0x6a (OP_RETURN)", script[1])
			}

			if len(script) < tt.wantMin {
				t.Errorf("script length = %d, want at least %d", len(script), tt.wantMin)
			}

			// The data should be embedded in the script.
			if !bytes.Contains(script, tt.data) {
				t.Error("script does not contain the original data")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestPushData
// ---------------------------------------------------------------------------

func TestPushData(t *testing.T) {
	tests := []struct {
		name       string
		dataLen    int
		wantPrefix byte
		wantTotal  int
	}{
		{"1 byte", 1, 0x01, 2},
		{"75 bytes", 75, 75, 76},
		{"76 bytes OP_PUSHDATA1", 76, 0x4c, 78},
		{"255 bytes OP_PUSHDATA1", 255, 0x4c, 257},
		{"256 bytes OP_PUSHDATA2", 256, 0x4d, 259},
		{"65535 bytes OP_PUSHDATA2", 65535, 0x4d, 65538},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataLen)
			for i := range data {
				data[i] = byte(i % 256)
			}

			result := pushData(data)
			if len(result) != tt.wantTotal {
				t.Errorf("total length = %d, want %d", len(result), tt.wantTotal)
			}
			if result[0] != tt.wantPrefix {
				t.Errorf("prefix = 0x%02x, want 0x%02x", result[0], tt.wantPrefix)
			}

			// Data should appear at the end.
			if !bytes.Equal(result[len(result)-tt.dataLen:], data) {
				t.Error("data content mismatch in pushData result")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceState_ValidInputs
// ---------------------------------------------------------------------------

func TestAdvanceState_ValidInputs(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x51, 0x52, 0x93, 0x87}, // OP_1 OP_2 OP_ADD OP_EQUAL
		StateSize:     3,
		ScriptHash:    sha256.Sum256([]byte{0x51, 0x52, 0x93, 0x87}),
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}

	genesisTxID := types.BytesToHash([]byte{0xaa, 0xbb, 0xcc})
	cm := NewCovenantManager(cov, genesisTxID, 0, DefaultCovenantSats, initialState, 8453111, VerifyGroth16)

	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}
	batchData := []byte("batch-data-for-block-1")
	proof := []byte("stark-proof-data-here")
	publicValues := []byte("public-values-data")

	feeUTXOs := []FeeInput{
		{
			TxID:     types.BytesToHash([]byte{0x11, 0x22}),
			Vout:     0,
			Satoshis: 50000,
			Script:   []byte{0x76, 0xa9},
		},
	}
	changeAddr := make([]byte, 20)
	changeAddr[0] = 0xde
	changeAddr[1] = 0xad

	result, err := cm.AdvanceState(newState, batchData, proof, publicValues, feeUTXOs, changeAddr)
	if err != nil {
		t.Fatalf("AdvanceState failed: %v", err)
	}

	if result == nil {
		t.Fatal("result is nil")
	}
	if len(result.RawTx) == 0 {
		t.Error("raw transaction is empty")
	}
	if result.CovenantInputIndex != 0 {
		t.Errorf("covenant input index = %d, want 0", result.CovenantInputIndex)
	}
	if len(result.FeeInputIndices) != 1 {
		t.Fatalf("fee input indices length = %d, want 1", len(result.FeeInputIndices))
	}
	if result.FeeInputIndices[0] != 1 {
		t.Errorf("fee input index = %d, want 1", result.FeeInputIndices[0])
	}
	if result.NewCovenantVout != 0 {
		t.Errorf("new covenant vout = %d, want 0", result.NewCovenantVout)
	}
	if result.TotalFee == 0 {
		t.Error("total fee is zero")
	}
	if result.TotalFee > 50000 {
		t.Errorf("total fee %d exceeds fee input amount 50000", result.TotalFee)
	}

	// TxID should be non-zero.
	if result.TxID == (types.Hash{}) {
		t.Error("txid is zero hash")
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceState_EmptyProof
// ---------------------------------------------------------------------------

func TestAdvanceState_EmptyProof(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	newState := CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1}
	_, err := cm.AdvanceState(newState, []byte("batch"), []byte{}, []byte("pv"),
		[]FeeInput{{Satoshis: 10000}}, make([]byte, 20))
	if err == nil {
		t.Fatal("expected error for empty proof")
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceState_EmptyBatchData
// ---------------------------------------------------------------------------

func TestAdvanceState_EmptyBatchData(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	newState := CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1}
	_, err := cm.AdvanceState(newState, []byte{}, []byte("proof"), []byte("pv"),
		[]FeeInput{{Satoshis: 10000}}, make([]byte, 20))
	if err == nil {
		t.Fatal("expected error for empty batch data")
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceState_InsufficientFees
// ---------------------------------------------------------------------------

func TestAdvanceState_InsufficientFees(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x51, 0x52},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	newState := CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1}

	// Provide a fee UTXO with only 1 satoshi — way too little for any tx.
	_, err := cm.AdvanceState(newState, []byte("batch"), []byte("proof"), []byte("pv"),
		[]FeeInput{{Satoshis: 1}}, make([]byte, 20))
	if err == nil {
		t.Fatal("expected error for insufficient fees")
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceState_NoFeeUTXOs
// ---------------------------------------------------------------------------

func TestAdvanceState_NoFeeUTXOs(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	newState := CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1}
	_, err := cm.AdvanceState(newState, []byte("batch"), []byte("proof"), []byte("pv"),
		nil, make([]byte, 20))
	if err == nil {
		t.Fatal("expected error for no fee UTXOs")
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceState_EmptyChangeAddress
// ---------------------------------------------------------------------------

func TestAdvanceState_EmptyChangeAddress(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	newState := CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1}
	_, err := cm.AdvanceState(newState, []byte("batch"), []byte("proof"), []byte("pv"),
		[]FeeInput{{Satoshis: 50000}}, nil)
	if err == nil {
		t.Fatal("expected error for empty change address")
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceState_MultipleFeeUTXOs
// ---------------------------------------------------------------------------

func TestAdvanceState_MultipleFeeUTXOs(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x51},
		StateSize:     3,
		ScriptHash:    sha256.Sum256([]byte{0x51}),
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	newState := CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1}
	feeUTXOs := []FeeInput{
		{TxID: types.BytesToHash([]byte{0x11}), Vout: 0, Satoshis: 5000},
		{TxID: types.BytesToHash([]byte{0x22}), Vout: 1, Satoshis: 5000},
		{TxID: types.BytesToHash([]byte{0x33}), Vout: 2, Satoshis: 5000},
	}

	result, err := cm.AdvanceState(newState, []byte("batch"), []byte("proof"), []byte("pv"),
		feeUTXOs, make([]byte, 20))
	if err != nil {
		t.Fatalf("AdvanceState failed: %v", err)
	}

	if len(result.FeeInputIndices) != 3 {
		t.Fatalf("fee input indices length = %d, want 3", len(result.FeeInputIndices))
	}
	for i, idx := range result.FeeInputIndices {
		if idx != i+1 {
			t.Errorf("fee input index[%d] = %d, want %d", i, idx, i+1)
		}
	}
}

// ---------------------------------------------------------------------------
// TestBSVTxSerialize_MultipleInputsOutputs
// ---------------------------------------------------------------------------

func TestBSVTxSerialize_MultipleInputsOutputs(t *testing.T) {
	tx := &BSVTx{
		Version: 2,
		Inputs: []BSVInput{
			{PrevTxID: types.Hash{}, PrevVout: 0, Script: []byte{0x01}, Sequence: 0xffffffff},
			{PrevTxID: types.Hash{}, PrevVout: 1, Script: []byte{0x02, 0x03}, Sequence: 0xfffffffe},
		},
		Outputs: []BSVOutput{
			{Value: 100, Script: []byte{0x76, 0xa9}},
			{Value: 0, Script: []byte{0x6a, 0x04}},
			{Value: 50, Script: []byte{0x76, 0xa9, 0x14}},
		},
		LockTime: 500000,
	}

	raw := tx.Serialize()
	if len(raw) == 0 {
		t.Fatal("empty serialization")
	}

	// Verify version.
	version := binary.LittleEndian.Uint32(raw[0:4])
	if version != 2 {
		t.Errorf("version = %d, want 2", version)
	}

	// Verify input count.
	if raw[4] != 2 {
		t.Errorf("input count = %d, want 2", raw[4])
	}

	// Verify locktime.
	lt := binary.LittleEndian.Uint32(raw[len(raw)-4:])
	if lt != 500000 {
		t.Errorf("locktime = %d, want 500000", lt)
	}
}
