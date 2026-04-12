package covenant

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// makeGenesisResult creates a GenesisResult for testing without going through
// the Runar compiler (which requires the runar-go dependency).
func makeGenesisResult() *GenesisResult {
	lockingScript := []byte{0x51, 0x52, 0x93, 0x87} // OP_1 OP_2 OP_ADD OP_EQUAL
	anfData := []byte(`{"contractName":"rollup","version":"1.0"}`)

	return &GenesisResult{
		Covenant: &CompiledCovenant{
			LockingScript:       lockingScript,
			ANF:                 anfData,
			StateSize:           3,
			ScriptHash:          sha256.Sum256(lockingScript),
			SP1VerifyingKeyHash: sha256.Sum256([]byte("test-vk")),
		},
		InitialState: CovenantState{
			StateRoot:   testStateRoot(0),
			BlockNumber: 0,
			Frozen:      0,
		},
		LockingScript: lockingScript,
		ANF:           anfData,
	}
}

func makeFundingInput(sats uint64) FeeInput {
	return FeeInput{
		TxID:     types.BytesToHash([]byte{0x11, 0x22, 0x33}),
		Vout:     0,
		Satoshis: sats,
		Script:   []byte{0x76, 0xa9},
	}
}

func makeChangeAddress() []byte {
	addr := make([]byte, 20)
	addr[0] = 0xde
	addr[1] = 0xad
	return addr
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_Structure
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_Structure verifies that the genesis transaction
// has 1 input and 3 outputs.
func TestBuildGenesisTransaction_Structure(t *testing.T) {
	gr := makeGenesisResult()
	funding := makeFundingInput(100000)
	changeAddr := makeChangeAddress()

	tx, err := gr.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err != nil {
		t.Fatalf("BuildGenesisTransaction failed: %v", err)
	}

	if len(tx.Inputs) != 1 {
		t.Errorf("input count = %d, want 1", len(tx.Inputs))
	}
	if len(tx.Outputs) != 3 {
		t.Errorf("output count = %d, want 3", len(tx.Outputs))
	}
	if tx.Version != 1 {
		t.Errorf("version = %d, want 1", tx.Version)
	}
	if tx.LockTime != 0 {
		t.Errorf("locktime = %d, want 0", tx.LockTime)
	}

	// Input should reference the funding UTXO.
	if tx.Inputs[0].PrevTxID != funding.TxID {
		t.Error("input does not reference funding UTXO")
	}
	if tx.Inputs[0].PrevVout != funding.Vout {
		t.Errorf("input vout = %d, want %d", tx.Inputs[0].PrevVout, funding.Vout)
	}
	if tx.Inputs[0].Script != nil {
		t.Error("input script should be nil (unsigned)")
	}
	if tx.Inputs[0].Sequence != 0xffffffff {
		t.Errorf("input sequence = %d, want 0xffffffff", tx.Inputs[0].Sequence)
	}
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_OpReturn
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_OpReturn verifies that output 1 is an OP_RETURN
// that starts with the BSVM\x01 prefix.
func TestBuildGenesisTransaction_OpReturn(t *testing.T) {
	gr := makeGenesisResult()
	funding := makeFundingInput(100000)
	changeAddr := makeChangeAddress()

	tx, err := gr.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err != nil {
		t.Fatalf("BuildGenesisTransaction failed: %v", err)
	}

	opReturnOutput := tx.Outputs[1]

	// Value should be 0.
	if opReturnOutput.Value != 0 {
		t.Errorf("OP_RETURN output value = %d, want 0", opReturnOutput.Value)
	}

	// Script should start with OP_FALSE OP_RETURN.
	if len(opReturnOutput.Script) < 2 {
		t.Fatal("OP_RETURN script too short")
	}
	if opReturnOutput.Script[0] != 0x00 {
		t.Errorf("first byte = 0x%02x, want 0x00 (OP_FALSE)", opReturnOutput.Script[0])
	}
	if opReturnOutput.Script[1] != 0x6a {
		t.Errorf("second byte = 0x%02x, want 0x6a (OP_RETURN)", opReturnOutput.Script[1])
	}

	// The payload (after OP_FALSE OP_RETURN + push length) should contain BSVM\x01.
	bsvmPrefix := []byte{0x42, 0x53, 0x56, 0x4d, 0x01}
	if !bytes.Contains(opReturnOutput.Script, bsvmPrefix) {
		t.Error("OP_RETURN script does not contain BSVM\\x01 prefix")
	}

	// The payload should also contain the initial state (49 bytes).
	initialStateBytes := gr.InitialState.Encode()
	if !bytes.Contains(opReturnOutput.Script, initialStateBytes) {
		t.Error("OP_RETURN script does not contain initial state")
	}
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_CovenantOutput
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_CovenantOutput verifies that output 0 has the
// correct satoshi amount and locking script.
func TestBuildGenesisTransaction_CovenantOutput(t *testing.T) {
	gr := makeGenesisResult()
	funding := makeFundingInput(100000)
	changeAddr := makeChangeAddress()

	tx, err := gr.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err != nil {
		t.Fatalf("BuildGenesisTransaction failed: %v", err)
	}

	covenantOutput := tx.Outputs[0]

	// Value should be DefaultCovenantSats.
	if covenantOutput.Value != DefaultCovenantSats {
		t.Errorf("covenant output value = %d, want %d", covenantOutput.Value, DefaultCovenantSats)
	}

	// Script should be the locking script.
	if !bytes.Equal(covenantOutput.Script, gr.LockingScript) {
		t.Error("covenant output script does not match locking script")
	}
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_ChangeOutput
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_ChangeOutput verifies that output 2 sends to
// the change address with a P2PKH script.
func TestBuildGenesisTransaction_ChangeOutput(t *testing.T) {
	gr := makeGenesisResult()
	funding := makeFundingInput(100000)
	changeAddr := makeChangeAddress()

	tx, err := gr.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err != nil {
		t.Fatalf("BuildGenesisTransaction failed: %v", err)
	}

	changeOutput := tx.Outputs[2]

	// The change output script should be a P2PKH script containing the address.
	expectedScript := buildP2PKHScript(changeAddr)
	if !bytes.Equal(changeOutput.Script, expectedScript) {
		t.Error("change output script does not match expected P2PKH script")
	}

	// The change output should contain the address hash.
	if !bytes.Contains(changeOutput.Script, changeAddr) {
		t.Error("change output script does not contain change address")
	}

	// The change output value should be positive (funding - covenant - fee).
	if changeOutput.Value == 0 {
		t.Error("change output value should be positive")
	}
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_Fee
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_Fee verifies that the mining fee is deducted
// from the change output.
func TestBuildGenesisTransaction_Fee(t *testing.T) {
	gr := makeGenesisResult()
	fundingSats := uint64(100000)
	funding := makeFundingInput(fundingSats)
	changeAddr := makeChangeAddress()

	tx, err := gr.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err != nil {
		t.Fatalf("BuildGenesisTransaction failed: %v", err)
	}

	// Sum all output values.
	var totalOutputs uint64
	for _, out := range tx.Outputs {
		totalOutputs += out.Value
	}

	// The difference between funding and outputs is the fee.
	fee := fundingSats - totalOutputs
	if fee == 0 {
		t.Error("fee should be non-zero")
	}

	// Fee should be reasonable (not excessive). At 50 sat/KB for a small tx,
	// fee should be well under 1000 satoshis.
	if fee > 1000 {
		t.Errorf("fee = %d, seems excessive for a small genesis transaction", fee)
	}

	// Verify the accounting: covenant sats + change + fee = funding.
	covenantValue := tx.Outputs[0].Value
	changeValue := tx.Outputs[2].Value
	opReturnValue := tx.Outputs[1].Value

	if covenantValue+opReturnValue+changeValue+fee != fundingSats {
		t.Errorf("accounting mismatch: %d + %d + %d + %d != %d",
			covenantValue, opReturnValue, changeValue, fee, fundingSats)
	}

	// Fee should be based on serialized size at 50 sat/KB.
	rawSize := uint64(len(tx.Serialize()))
	expectedFee := (rawSize * defaultFeeRate) / 1000
	if expectedFee == 0 {
		expectedFee = 1
	}
	// The fee might differ slightly from expectedFee because the change amount
	// was updated after initial fee estimation, but it should be close.
	// We allow a delta of +/- 1 sat for rounding.
	if fee > expectedFee+1 || fee+1 < expectedFee {
		t.Errorf("fee = %d, expected approximately %d (from size %d bytes at %d sat/KB)",
			fee, expectedFee, rawSize, defaultFeeRate)
	}
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_InsufficientFunding
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_InsufficientFunding verifies that building a
// genesis transaction fails when funding is insufficient.
func TestBuildGenesisTransaction_InsufficientFunding(t *testing.T) {
	gr := makeGenesisResult()
	changeAddr := makeChangeAddress()

	// Funding less than covenant sats.
	funding := makeFundingInput(5000) // less than DefaultCovenantSats (10000)
	_, err := gr.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err == nil {
		t.Fatal("expected error for insufficient funding")
	}
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_Validation
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_Validation verifies input validation.
func TestBuildGenesisTransaction_Validation(t *testing.T) {
	gr := makeGenesisResult()
	funding := makeFundingInput(100000)
	changeAddr := makeChangeAddress()

	// Zero satoshis in funding.
	zeroFunding := FeeInput{TxID: types.Hash{}, Satoshis: 0}
	_, err := gr.BuildGenesisTransaction(zeroFunding, DefaultCovenantSats, changeAddr)
	if err == nil {
		t.Error("expected error for zero funding satoshis")
	}

	// Zero covenant sats.
	_, err = gr.BuildGenesisTransaction(funding, 0, changeAddr)
	if err == nil {
		t.Error("expected error for zero covenant sats")
	}

	// Empty change address.
	_, err = gr.BuildGenesisTransaction(funding, DefaultCovenantSats, nil)
	if err == nil {
		t.Error("expected error for empty change address")
	}

	// Empty locking script.
	emptyScriptResult := &GenesisResult{
		Covenant:      gr.Covenant,
		InitialState:  gr.InitialState,
		LockingScript: nil,
		ANF:           gr.ANF,
	}
	_, err = emptyScriptResult.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err == nil {
		t.Error("expected error for empty locking script")
	}
}

// ---------------------------------------------------------------------------
// TestBuildGenesisTransaction_Serializable
// ---------------------------------------------------------------------------

// TestBuildGenesisTransaction_Serializable verifies the genesis tx can be
// serialized and has the expected wire format structure.
func TestBuildGenesisTransaction_Serializable(t *testing.T) {
	gr := makeGenesisResult()
	funding := makeFundingInput(100000)
	changeAddr := makeChangeAddress()

	tx, err := gr.BuildGenesisTransaction(funding, DefaultCovenantSats, changeAddr)
	if err != nil {
		t.Fatalf("BuildGenesisTransaction failed: %v", err)
	}

	raw := tx.Serialize()
	if len(raw) == 0 {
		t.Fatal("serialized transaction is empty")
	}

	// Check version.
	version := binary.LittleEndian.Uint32(raw[0:4])
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}

	// Check input count (byte 4).
	if raw[4] != 1 {
		t.Errorf("input count = %d, want 1", raw[4])
	}

	// Check locktime (last 4 bytes).
	lt := binary.LittleEndian.Uint32(raw[len(raw)-4:])
	if lt != 0 {
		t.Errorf("locktime = %d, want 0", lt)
	}

	// TxID should be non-zero.
	txID := tx.TxID()
	if txID == (types.Hash{}) {
		t.Error("txid is zero hash")
	}

	// Serialization should be deterministic.
	raw2 := tx.Serialize()
	if !bytes.Equal(raw, raw2) {
		t.Error("serialization is not deterministic")
	}
}
