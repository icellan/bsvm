package prover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// TestPublicValuesParsing verifies that encoding and decoding 272-byte
// public values is a perfect roundtrip.
func TestPublicValuesParsing(t *testing.T) {
	original := &PublicValues{
		PreStateRoot:      types.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		PostStateRoot:     types.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		ReceiptsHash:      types.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		GasUsed:           21000,
		BatchDataHash:     types.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444"),
		ChainID:           1337,
		WithdrawalRoot:    types.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
		InboxRootBefore:   types.HexToHash("0x6666666666666666666666666666666666666666666666666666666666666666"),
		InboxRootAfter:    types.HexToHash("0x7777777777777777777777777777777777777777777777777777777777777777"),
		MigrateScriptHash: types.HexToHash("0x8888888888888888888888888888888888888888888888888888888888888888"),
	}

	// Encode.
	encoded := original.Encode()
	if len(encoded) != PublicValuesSize {
		t.Fatalf("encoded size = %d, want %d", len(encoded), PublicValuesSize)
	}

	// Decode.
	decoded, err := ParsePublicValues(encoded)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}

	// Verify all fields match.
	if decoded.PreStateRoot != original.PreStateRoot {
		t.Errorf("PreStateRoot mismatch: got %s, want %s", decoded.PreStateRoot.Hex(), original.PreStateRoot.Hex())
	}
	if decoded.PostStateRoot != original.PostStateRoot {
		t.Errorf("PostStateRoot mismatch: got %s, want %s", decoded.PostStateRoot.Hex(), original.PostStateRoot.Hex())
	}
	if decoded.ReceiptsHash != original.ReceiptsHash {
		t.Errorf("ReceiptsHash mismatch: got %s, want %s", decoded.ReceiptsHash.Hex(), original.ReceiptsHash.Hex())
	}
	if decoded.GasUsed != original.GasUsed {
		t.Errorf("GasUsed mismatch: got %d, want %d", decoded.GasUsed, original.GasUsed)
	}
	if decoded.BatchDataHash != original.BatchDataHash {
		t.Errorf("BatchDataHash mismatch: got %s, want %s", decoded.BatchDataHash.Hex(), original.BatchDataHash.Hex())
	}
	if decoded.ChainID != original.ChainID {
		t.Errorf("ChainID mismatch: got %d, want %d", decoded.ChainID, original.ChainID)
	}
	if decoded.WithdrawalRoot != original.WithdrawalRoot {
		t.Errorf("WithdrawalRoot mismatch: got %s, want %s", decoded.WithdrawalRoot.Hex(), original.WithdrawalRoot.Hex())
	}
	if decoded.InboxRootBefore != original.InboxRootBefore {
		t.Errorf("InboxRootBefore mismatch: got %s, want %s", decoded.InboxRootBefore.Hex(), original.InboxRootBefore.Hex())
	}
	if decoded.InboxRootAfter != original.InboxRootAfter {
		t.Errorf("InboxRootAfter mismatch: got %s, want %s", decoded.InboxRootAfter.Hex(), original.InboxRootAfter.Hex())
	}
	if decoded.MigrateScriptHash != original.MigrateScriptHash {
		t.Errorf("MigrateScriptHash mismatch: got %s, want %s", decoded.MigrateScriptHash.Hex(), original.MigrateScriptHash.Hex())
	}

	// Re-encode and compare bytes.
	reEncoded := decoded.Encode()
	if !bytes.Equal(encoded, reEncoded) {
		t.Error("re-encoded bytes differ from original encoding")
	}
}

// TestPublicValuesParsingErrors verifies that ParsePublicValues rejects
// invalid input sizes.
func TestPublicValuesParsingErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 271)},
		{"too long", make([]byte, 273)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicValues(tt.data)
			if err == nil {
				t.Error("expected error for invalid input size")
			}
		})
	}
}

// TestStateExportSerialization verifies JSON roundtrip of StateExport.
func TestStateExportSerialization(t *testing.T) {
	balance := uint256.NewInt(1000000)
	original := &StateExport{
		PreStateRoot: types.HexToHash("0xabcdef0000000000000000000000000000000000000000000000000000000001"),
		Accounts: []AccountExport{
			{
				Address:      types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
				Nonce:        42,
				Balance:      balance,
				CodeHash:     types.EmptyCodeHash,
				StorageRoot:  types.EmptyRootHash,
				Code:         []byte{0x60, 0x00, 0x60, 0x00, 0xf3}, // PUSH1 0 PUSH1 0 RETURN
				AccountProof: [][]byte{{0x01, 0x02}, {0x03, 0x04}},
				StorageSlots: []StorageSlotExport{
					{
						Key:   types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
						Value: types.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000ff"),
						Proof: [][]byte{{0x05, 0x06}},
					},
				},
			},
			{
				Address:      types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
				Nonce:        0,
				Balance:      uint256.NewInt(0),
				CodeHash:     types.EmptyCodeHash,
				StorageRoot:  types.EmptyRootHash,
				AccountProof: [][]byte{},
			},
		},
	}

	// Serialize.
	data, err := SerializeExport(original)
	if err != nil {
		t.Fatalf("SerializeExport: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized export is empty")
	}

	// Deserialize.
	decoded, err := DeserializeExport(data)
	if err != nil {
		t.Fatalf("DeserializeExport: %v", err)
	}

	// Verify structure.
	if decoded.PreStateRoot != original.PreStateRoot {
		t.Errorf("PreStateRoot mismatch")
	}
	if len(decoded.Accounts) != len(original.Accounts) {
		t.Fatalf("account count mismatch: got %d, want %d", len(decoded.Accounts), len(original.Accounts))
	}

	acct := decoded.Accounts[0]
	if acct.Address != original.Accounts[0].Address {
		t.Errorf("account address mismatch")
	}
	if acct.Nonce != original.Accounts[0].Nonce {
		t.Errorf("account nonce mismatch: got %d, want %d", acct.Nonce, original.Accounts[0].Nonce)
	}
	if acct.Balance.Cmp(original.Accounts[0].Balance) != 0 {
		t.Errorf("account balance mismatch")
	}
	if !bytes.Equal(acct.Code, original.Accounts[0].Code) {
		t.Errorf("account code mismatch")
	}
	if len(acct.StorageSlots) != 1 {
		t.Fatalf("storage slot count mismatch: got %d, want 1", len(acct.StorageSlots))
	}
	if acct.StorageSlots[0].Key != original.Accounts[0].StorageSlots[0].Key {
		t.Errorf("storage slot key mismatch")
	}
	if acct.StorageSlots[0].Value != original.Accounts[0].StorageSlots[0].Value {
		t.Errorf("storage slot value mismatch")
	}
}

// TestStateExportSerializationEdgeCases tests nil and empty export handling.
func TestStateExportSerializationEdgeCases(t *testing.T) {
	// Nil export.
	data, err := SerializeExport(nil)
	if err != nil {
		t.Fatalf("SerializeExport(nil): %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data for nil export")
	}

	// Empty data.
	result, err := DeserializeExport(nil)
	if err != nil {
		t.Fatalf("DeserializeExport(nil): %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for nil data")
	}

	result, err = DeserializeExport([]byte{})
	if err != nil {
		t.Fatalf("DeserializeExport(empty): %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty data")
	}
}

// TestMockProver verifies that the mock prover returns a valid structure
// without requiring the SP1 prover binary.
func TestMockProver(t *testing.T) {
	prover := NewSP1Prover(Config{
		Mode:      ProverMock,
		ProofMode: "compressed",
	})

	preStateRoot := types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	input := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  []byte(`{"pre_state_root":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","accounts":[]}`),
		Transactions: [][]byte{
			{0xf8, 0x65}, // dummy tx bytes
		},
		BlockContext: BlockContext{
			Number:    1,
			Timestamp: 1700000000,
			Coinbase:  types.HexToAddress("0x0000000000000000000000000000000000000001"),
			GasLimit:  30000000,
			BaseFee:   1000000000,
		},
	}

	output, err := prover.Prove(context.Background(), input)
	if err != nil {
		t.Fatalf("Prove (mock): %v", err)
	}

	// Verify output structure.
	if output == nil {
		t.Fatal("output is nil")
	}
	if len(output.Proof) == 0 {
		t.Error("proof data is empty")
	}
	if len(output.PublicValues) != PublicValuesSize {
		t.Errorf("public values size = %d, want %d", len(output.PublicValues), PublicValuesSize)
	}

	// Parse and verify public values.
	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}
	if pv.PreStateRoot != preStateRoot {
		t.Errorf("PreStateRoot mismatch: got %s, want %s", pv.PreStateRoot.Hex(), preStateRoot.Hex())
	}
	// In mock mode, PostStateRoot equals PreStateRoot.
	if pv.PostStateRoot != preStateRoot {
		t.Errorf("PostStateRoot should equal PreStateRoot in mock mode")
	}

	// Verify the VK hash is non-zero.
	if output.VKHash == (types.Hash{}) {
		t.Error("VKHash is zero in mock output")
	}
}

// TestMockProverNilInput verifies that the mock prover rejects nil input.
func TestMockProverNilInput(t *testing.T) {
	prover := NewSP1Prover(DefaultConfig())

	_, err := prover.Prove(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil input")
	}
}

// TestMockProverEmptyTransactions verifies mock proving with no transactions.
func TestMockProverEmptyTransactions(t *testing.T) {
	prover := NewSP1Prover(Config{Mode: ProverMock})

	input := &ProveInput{
		PreStateRoot: types.Hash{},
		Transactions: nil,
		BlockContext: BlockContext{Number: 1},
	}

	output, err := prover.Prove(context.Background(), input)
	if err != nil {
		t.Fatalf("Prove (mock, empty txs): %v", err)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}
	// With no transactions, the batch data hash should be zero.
	if pv.BatchDataHash != (types.Hash{}) {
		t.Errorf("BatchDataHash should be zero for empty transactions, got %s", pv.BatchDataHash.Hex())
	}
}

// TestBatchDataHashUsesHash256 verifies that the mock prover computes
// batchDataHash as hash256 (double-SHA256), not keccak256.
func TestBatchDataHashUsesHash256(t *testing.T) {
	prover := NewSP1Prover(Config{Mode: ProverMock})

	txData := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05},
	}
	input := &ProveInput{
		PreStateRoot: types.Hash{},
		Transactions: txData,
		BlockContext: BlockContext{Number: 1},
	}

	output, err := prover.Prove(context.Background(), input)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}

	// Compute expected hash256 (double-SHA256) manually.
	concat := append(txData[0], txData[1]...)
	first := sha256.Sum256(concat)
	second := sha256.Sum256(first[:])
	expected := types.BytesToHash(second[:])

	if pv.BatchDataHash != expected {
		t.Errorf("BatchDataHash mismatch:\n  got  %s\n  want %s (hash256)",
			pv.BatchDataHash.Hex(), expected.Hex())
	}

	// Verify it is NOT keccak256 (the old incorrect behavior).
	keccakHash := types.BytesToHash(crypto.Keccak256(concat))
	if pv.BatchDataHash == keccakHash {
		t.Error("BatchDataHash matches keccak256 -- should be hash256 (double-SHA256)")
	}
}

// TestProveInputSerialization verifies that ProveInput serializes to JSON
// correctly for the host bridge protocol.
func TestProveInputSerialization(t *testing.T) {
	input := &ProveInput{
		PreStateRoot: types.HexToHash("0xdeadbeef00000000000000000000000000000000000000000000000000000001"),
		StateExport:  []byte(`{"pre_state_root":"0x00","accounts":[]}`),
		Transactions: [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		},
		BlockContext: BlockContext{
			Number:    100,
			Timestamp: 1700000000,
			Coinbase:  types.HexToAddress("0xcafe"),
			GasLimit:  30000000,
			BaseFee:   1000000000,
			Random:    types.HexToHash("0xbeef"),
		},
	}

	// Serialize to JSON.
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Deserialize back.
	var decoded ProveInput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Verify fields.
	if decoded.PreStateRoot != input.PreStateRoot {
		t.Errorf("PreStateRoot mismatch")
	}
	if len(decoded.Transactions) != len(input.Transactions) {
		t.Fatalf("transaction count mismatch: got %d, want %d", len(decoded.Transactions), len(input.Transactions))
	}
	for i, tx := range decoded.Transactions {
		if !bytes.Equal(tx, input.Transactions[i]) {
			t.Errorf("transaction[%d] mismatch", i)
		}
	}
	if decoded.BlockContext.Number != input.BlockContext.Number {
		t.Errorf("BlockContext.Number mismatch")
	}
	if decoded.BlockContext.Timestamp != input.BlockContext.Timestamp {
		t.Errorf("BlockContext.Timestamp mismatch")
	}
	if decoded.BlockContext.Coinbase != input.BlockContext.Coinbase {
		t.Errorf("BlockContext.Coinbase mismatch")
	}
	if decoded.BlockContext.GasLimit != input.BlockContext.GasLimit {
		t.Errorf("BlockContext.GasLimit mismatch")
	}
	if decoded.BlockContext.BaseFee != input.BlockContext.BaseFee {
		t.Errorf("BlockContext.BaseFee mismatch")
	}
	if decoded.BlockContext.Random != input.BlockContext.Random {
		t.Errorf("BlockContext.Random mismatch")
	}
}

// TestProofSerialization verifies JSON roundtrip of the Proof type.
func TestProofSerialization(t *testing.T) {
	original := &Proof{
		Data: []byte("some-proof-data"),
		PublicValues: PublicValues{
			PreStateRoot: types.HexToHash("0x01"),
			PostStateRoot: types.HexToHash("0x02"),
			GasUsed: 21000,
			ChainID: 1337,
		},
		VKHash: types.HexToHash("0xab"),
		Mode:   "compressed",
	}

	data, err := SerializeProof(original)
	if err != nil {
		t.Fatalf("SerializeProof: %v", err)
	}

	decoded, err := DeserializeProof(data)
	if err != nil {
		t.Fatalf("DeserializeProof: %v", err)
	}

	if !bytes.Equal(decoded.Data, original.Data) {
		t.Errorf("proof data mismatch")
	}
	if decoded.PublicValues.PreStateRoot != original.PublicValues.PreStateRoot {
		t.Errorf("public values PreStateRoot mismatch")
	}
	if decoded.PublicValues.GasUsed != original.PublicValues.GasUsed {
		t.Errorf("public values GasUsed mismatch")
	}
	if decoded.VKHash != original.VKHash {
		t.Errorf("VKHash mismatch")
	}
	if decoded.Mode != original.Mode {
		t.Errorf("Mode mismatch: got %s, want %s", decoded.Mode, original.Mode)
	}
}

// TestProofSerializationErrors verifies error cases in proof serialization.
func TestProofSerializationErrors(t *testing.T) {
	_, err := SerializeProof(nil)
	if err == nil {
		t.Error("expected error for nil proof")
	}

	_, err = DeserializeProof(nil)
	if err == nil {
		t.Error("expected error for nil data")
	}

	_, err = DeserializeProof([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}

	_, err = DeserializeProof([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid json")
	}
}

// TestMockProofVerification verifies that mock proofs pass verification.
func TestMockProofVerification(t *testing.T) {
	proof := &Proof{
		Data: []byte("MOCK_SP1_PROOF"),
		PublicValues: PublicValues{
			PreStateRoot: types.HexToHash("0x01"),
		},
		VKHash: types.HexToHash("0xab"),
		Mode:   "compressed",
	}

	// Mock proofs always verify.
	err := VerifyProof(proof, types.HexToHash("0xab"), nil)
	if err != nil {
		t.Errorf("VerifyProof (mock): %v", err)
	}
}

// TestVerifyProofErrors verifies error conditions in proof verification.
func TestVerifyProofErrors(t *testing.T) {
	err := VerifyProof(nil, types.Hash{}, nil)
	if err == nil {
		t.Error("expected error for nil proof")
	}
}

// TestProverModeString verifies the String() method of ProverMode.
func TestProverModeString(t *testing.T) {
	tests := []struct {
		mode ProverMode
		want string
	}{
		{ProverLocal, "local"},
		{ProverNetwork, "network"},
		{ProverMock, "mock"},
		{ProverMode(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("ProverMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

// TestNetworkProverReturnsError verifies that network mode returns
// a not-implemented error.
func TestNetworkProverReturnsError(t *testing.T) {
	prover := NewSP1Prover(Config{Mode: ProverNetwork})

	input := &ProveInput{
		PreStateRoot: types.Hash{},
		BlockContext: BlockContext{Number: 1},
	}

	_, err := prover.Prove(context.Background(), input)
	if err == nil {
		t.Error("expected error for network mode")
	}
}

// TestProveInput_InboxRoots verifies that inbox root fields are included
// in the ProveInput JSON serialization.
func TestProveInput_InboxRoots(t *testing.T) {
	inboxBefore := types.HexToHash("0xaaaa000000000000000000000000000000000000000000000000000000000001")
	inboxAfter := types.HexToHash("0xbbbb000000000000000000000000000000000000000000000000000000000002")

	input := &ProveInput{
		PreStateRoot:    types.HexToHash("0x01"),
		InboxRootBefore: inboxBefore,
		InboxRootAfter:  inboxAfter,
		BlockContext:    BlockContext{Number: 1},
	}

	// Serialize to JSON.
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Deserialize back.
	var decoded ProveInput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.InboxRootBefore != inboxBefore {
		t.Errorf("InboxRootBefore mismatch: got %s, want %s",
			decoded.InboxRootBefore.Hex(), inboxBefore.Hex())
	}
	if decoded.InboxRootAfter != inboxAfter {
		t.Errorf("InboxRootAfter mismatch: got %s, want %s",
			decoded.InboxRootAfter.Hex(), inboxAfter.Hex())
	}
}

// TestPublicValues_InboxRoots verifies that inbox roots from ProveInput
// flow through the mock prover into the PublicValues output.
func TestPublicValues_InboxRoots(t *testing.T) {
	inboxBefore := types.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	inboxAfter := types.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")

	prover := NewSP1Prover(Config{Mode: ProverMock})

	input := &ProveInput{
		PreStateRoot:    types.HexToHash("0x01"),
		InboxRootBefore: inboxBefore,
		InboxRootAfter:  inboxAfter,
		BlockContext:    BlockContext{Number: 1},
		ExpectedResults: &ExpectedResults{
			PostStateRoot: types.HexToHash("0x02"),
			ReceiptsHash:  types.HexToHash("0x03"),
			GasUsed:       21000,
			ChainID:       1337,
		},
	}

	output, err := prover.Prove(context.Background(), input)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}

	if pv.InboxRootBefore != inboxBefore {
		t.Errorf("InboxRootBefore mismatch: got %s, want %s",
			pv.InboxRootBefore.Hex(), inboxBefore.Hex())
	}
	if pv.InboxRootAfter != inboxAfter {
		t.Errorf("InboxRootAfter mismatch: got %s, want %s",
			pv.InboxRootAfter.Hex(), inboxAfter.Hex())
	}
}
