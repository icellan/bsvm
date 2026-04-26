package covenant

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testKey returns a fake 33-byte compressed public key with the given seed.
func testKey(seed byte) []byte {
	key := make([]byte, 33)
	key[0] = 0x02 // valid compressed key prefix
	key[1] = seed
	// Fill remaining bytes deterministically
	h := sha256.Sum256([]byte{seed})
	copy(key[2:], h[:31])
	return key
}

// testStateRoot returns a deterministic state root for a given block number.
func testStateRoot(block uint64) types.Hash {
	h := sha256.Sum256([]byte{byte(block), byte(block >> 8)})
	return types.BytesToHash(h[:])
}

// ---------------------------------------------------------------------------
// TestCovenantStateSerialization
// ---------------------------------------------------------------------------

func TestCovenantStateSerialization(t *testing.T) {
	tests := []struct {
		name  string
		state CovenantState
	}{
		{
			name: "zero state",
			state: CovenantState{
				StateRoot:   types.Hash{},
				BlockNumber: 0,
				Frozen:      0,
			},
		},
		{
			name: "active state at block 42",
			state: CovenantState{
				StateRoot:   testStateRoot(42),
				BlockNumber: 42,
				Frozen:      0,
			},
		},
		{
			name: "frozen state at block 100",
			state: CovenantState{
				StateRoot:   testStateRoot(100),
				BlockNumber: 100,
				Frozen:      1,
			},
		},
		{
			name: "max block number",
			state: CovenantState{
				StateRoot:   testStateRoot(255),
				BlockNumber: ^uint64(0),
				Frozen:      0,
			},
		},
		{
			name: "advances since inbox at threshold",
			state: CovenantState{
				StateRoot:          testStateRoot(7),
				BlockNumber:        7,
				Frozen:             0,
				AdvancesSinceInbox: 9,
			},
		},
		{
			name: "advances since inbox max",
			state: CovenantState{
				StateRoot:          testStateRoot(8),
				BlockNumber:        8,
				Frozen:             0,
				AdvancesSinceInbox: 255,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.state.Encode()
			if len(encoded) != covenantStateEncodedSize {
				t.Fatalf("expected %d bytes, got %d", covenantStateEncodedSize, len(encoded))
			}

			decoded, err := DecodeCovenantState(encoded)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			if decoded.StateRoot != tt.state.StateRoot {
				t.Errorf("state root mismatch: got %x, want %x", decoded.StateRoot, tt.state.StateRoot)
			}
			if decoded.BlockNumber != tt.state.BlockNumber {
				t.Errorf("block number mismatch: got %d, want %d", decoded.BlockNumber, tt.state.BlockNumber)
			}
			if decoded.Frozen != tt.state.Frozen {
				t.Errorf("frozen mismatch: got %d, want %d", decoded.Frozen, tt.state.Frozen)
			}
			if decoded.AdvancesSinceInbox != tt.state.AdvancesSinceInbox {
				t.Errorf("advances since inbox mismatch: got %d, want %d",
					decoded.AdvancesSinceInbox, tt.state.AdvancesSinceInbox)
			}
		})
	}
}

func TestCovenantStateDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: make([]byte, 10),
		},
		{
			name: "too long",
			data: make([]byte, 60),
		},
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "invalid frozen value",
			data: func() []byte {
				s := CovenantState{Frozen: 0}
				b := s.Encode()
				b[40] = 2 // invalid frozen value
				return b
			}(),
		},
		{
			name: "old v1 size (41 bytes)",
			data: make([]byte, 41), // pre-AdvancesSinceInbox layout — must be rejected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeCovenantState(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestGovernanceConfigValidation
// ---------------------------------------------------------------------------

func TestGovernanceConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  GovernanceConfig
		wantErr bool
	}{
		{
			name:    "none mode valid",
			config:  GovernanceConfig{Mode: GovernanceNone},
			wantErr: false,
		},
		{
			name: "none mode with keys",
			config: GovernanceConfig{
				Mode: GovernanceNone,
				Keys: [][]byte{testKey(1)},
			},
			wantErr: true,
		},
		{
			name: "none mode with threshold",
			config: GovernanceConfig{
				Mode:      GovernanceNone,
				Threshold: 1,
			},
			wantErr: true,
		},
		{
			name: "single key valid",
			config: GovernanceConfig{
				Mode: GovernanceSingleKey,
				Keys: [][]byte{testKey(1)},
			},
			wantErr: false,
		},
		{
			name: "single key no keys",
			config: GovernanceConfig{
				Mode: GovernanceSingleKey,
			},
			wantErr: true,
		},
		{
			name: "single key too many keys",
			config: GovernanceConfig{
				Mode: GovernanceSingleKey,
				Keys: [][]byte{testKey(1), testKey(2)},
			},
			wantErr: true,
		},
		{
			name: "single key with threshold",
			config: GovernanceConfig{
				Mode:      GovernanceSingleKey,
				Keys:      [][]byte{testKey(1)},
				Threshold: 1,
			},
			wantErr: true,
		},
		{
			name: "single key invalid key length",
			config: GovernanceConfig{
				Mode: GovernanceSingleKey,
				Keys: [][]byte{make([]byte, 20)},
			},
			wantErr: true,
		},
		{
			name: "single key invalid key prefix",
			config: GovernanceConfig{
				Mode: GovernanceSingleKey,
				Keys: [][]byte{func() []byte {
					k := testKey(1)
					k[0] = 0x04 // uncompressed prefix
					return k
				}()},
			},
			wantErr: true,
		},
		{
			name: "multisig valid 2-of-3",
			config: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
				Threshold: 2,
			},
			wantErr: false,
		},
		{
			name: "multisig valid 1-of-2",
			config: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), testKey(2)},
				Threshold: 1,
			},
			wantErr: false,
		},
		{
			name: "multisig valid n-of-n",
			config: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
				Threshold: 3,
			},
			wantErr: false,
		},
		{
			name: "multisig too few keys",
			config: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1)},
				Threshold: 1,
			},
			wantErr: true,
		},
		{
			name: "multisig threshold zero",
			config: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), testKey(2)},
				Threshold: 0,
			},
			wantErr: true,
		},
		{
			name: "multisig threshold exceeds keys",
			config: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), testKey(2)},
				Threshold: 3,
			},
			wantErr: true,
		},
		{
			name: "multisig invalid key in set",
			config: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), make([]byte, 10)},
				Threshold: 1,
			},
			wantErr: true,
		},
		{
			name:    "unknown mode",
			config:  GovernanceConfig{Mode: GovernanceMode(99)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGovernanceModeString(t *testing.T) {
	tests := []struct {
		mode GovernanceMode
		want string
	}{
		{GovernanceNone, "none"},
		{GovernanceSingleKey, "single_key"},
		{GovernanceMultiSig, "multisig"},
		{GovernanceMode(42), "unknown(42)"},
	}

	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("GovernanceMode(%d).String() = %q, want %q", int(tt.mode), got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCovenantManagerState
// ---------------------------------------------------------------------------

func TestCovenantManagerState(t *testing.T) {
	covenant := &CompiledCovenant{
		LockingScript: []byte{0x01, 0x02, 0x03},
		StateSize:     3,
		ScriptHash:    sha256.Sum256([]byte{0x01, 0x02, 0x03}),
	}
	genesisTxID := types.BytesToHash([]byte{0xaa, 0xbb})
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}

	cm := NewCovenantManager(covenant, genesisTxID, 0, DefaultCovenantSats, initialState, 8453111, VerifyGroth16)

	// Check initial state
	if cm.CurrentState().BlockNumber != 0 {
		t.Errorf("expected block 0, got %d", cm.CurrentState().BlockNumber)
	}
	if cm.CurrentTxID() != genesisTxID {
		t.Errorf("expected genesis txid %x, got %x", genesisTxID, cm.CurrentTxID())
	}
	if cm.CurrentVout() != 0 {
		t.Errorf("expected vout 0, got %d", cm.CurrentVout())
	}
	if cm.Covenant() != covenant {
		t.Error("expected same covenant pointer")
	}

	// Build advance data
	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}
	batchData := []byte("batch-data-block-1")
	proof := []byte("stark-proof-data")
	publicValues := []byte("public-values-data")

	if err := cm.ValidateAdvanceData(newState, batchData, proof, publicValues); err != nil {
		t.Fatalf("ValidateAdvanceData failed: %v", err)
	}

	// Apply advance
	newTxID := types.BytesToHash([]byte{0xcc, 0xdd})
	if err := cm.ApplyAdvance(newTxID, newState); err != nil {
		t.Fatalf("ApplyAdvance failed: %v", err)
	}

	if cm.CurrentState().BlockNumber != 1 {
		t.Errorf("expected block 1, got %d", cm.CurrentState().BlockNumber)
	}
	if cm.CurrentTxID() != newTxID {
		t.Errorf("expected new txid %x, got %x", newTxID, cm.CurrentTxID())
	}
	if cm.CurrentState().StateRoot != testStateRoot(1) {
		t.Errorf("state root not updated")
	}
}

// ---------------------------------------------------------------------------
// TestCovenantManagerBlockNumberIncrement
// ---------------------------------------------------------------------------

func TestCovenantManagerBlockNumberIncrement(t *testing.T) {
	covenant := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
		ScriptHash:    sha256.Sum256([]byte{0x01}),
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}

	cm := NewCovenantManager(covenant, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	batchData := []byte("batch")
	proof := []byte("proof")
	publicValues := []byte("pv")

	// Block number must be exactly current + 1
	tests := []struct {
		name        string
		newBlockNum uint64
		wantErr     bool
	}{
		{"correct increment to 1", 1, false},
		{"skip to 2 from 0", 2, true},
		{"same block 0", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newState := CovenantState{
				StateRoot:   testStateRoot(tt.newBlockNum),
				BlockNumber: tt.newBlockNum,
			}
			err := cm.ValidateAdvanceData(newState, batchData, proof, publicValues)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAdvanceData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// Advance to block 1
	newState1 := CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1}
	err := cm.ValidateAdvanceData(newState1, batchData, proof, publicValues)
	if err != nil {
		t.Fatalf("advance to block 1 failed: %v", err)
	}
	if err := cm.ApplyAdvance(types.BytesToHash([]byte{0x01}), newState1); err != nil {
		t.Fatalf("ApplyAdvance failed: %v", err)
	}

	// Now block 2 should work, block 3 should not
	newState2 := CovenantState{StateRoot: testStateRoot(2), BlockNumber: 2}
	err = cm.ValidateAdvanceData(newState2, batchData, proof, publicValues)
	if err != nil {
		t.Errorf("advance to block 2 should succeed: %v", err)
	}

	newState3 := CovenantState{StateRoot: testStateRoot(3), BlockNumber: 3}
	err = cm.ValidateAdvanceData(newState3, batchData, proof, publicValues)
	if err == nil {
		t.Error("advance to block 3 from block 1 should fail")
	}
}

func TestCovenantManagerRejectFrozen(t *testing.T) {
	covenant := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	frozenState := CovenantState{
		StateRoot:   testStateRoot(5),
		BlockNumber: 5,
		Frozen:      1,
	}

	cm := NewCovenantManager(covenant, types.Hash{}, 0, DefaultCovenantSats, frozenState, 1, VerifyGroth16)

	newState := CovenantState{StateRoot: testStateRoot(6), BlockNumber: 6}
	err := cm.ValidateAdvanceData(newState, []byte("b"), []byte("p"), []byte("pv"))
	if err == nil {
		t.Fatal("expected error when covenant is frozen")
	}
}

// ---------------------------------------------------------------------------
// TestPrepareGenesis
// ---------------------------------------------------------------------------

func TestPrepareGenesis(t *testing.T) {
	tests := []struct {
		name string
		gov  GovernanceConfig
	}{
		{
			name: "governance none",
			gov:  GovernanceConfig{Mode: GovernanceNone},
		},
		{
			name: "governance single key",
			gov: GovernanceConfig{
				Mode: GovernanceSingleKey,
				Keys: [][]byte{testKey(1)},
			},
		},
		{
			name: "governance multisig 2-of-3",
			gov: GovernanceConfig{
				Mode:      GovernanceMultiSig,
				Keys:      [][]byte{testKey(1), testKey(2), testKey(3)},
				Threshold: 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &GenesisConfig{
				ChainID:          8453111,
				SP1VerifyingKey:  []byte("test-sp1-vk-data"),
				InitialStateRoot: testStateRoot(0),
				Governance:       tt.gov,
				Verification:     VerifyFRI, // Basefold path compiles; Groth16 requires BN254 pairing support not yet in Rúnar
				CovenantSats:     DefaultCovenantSats,
			}

			result, err := PrepareGenesis(config)
			if err != nil {
				t.Fatalf("PrepareGenesis failed: %v", err)
			}

			if result.Covenant == nil {
				t.Fatal("compiled covenant is nil")
			}
			if result.InitialState.BlockNumber != 0 {
				t.Errorf("genesis block number should be 0, got %d", result.InitialState.BlockNumber)
			}
			if result.InitialState.Frozen != 0 {
				t.Errorf("genesis should not be frozen")
			}
			if result.InitialState.StateRoot != config.InitialStateRoot {
				t.Errorf("genesis state root mismatch")
			}
			if len(result.LockingScript) == 0 {
				t.Error("locking script is empty")
			}
		})
	}
}

func TestPrepareGenesisErrors(t *testing.T) {
	tests := []struct {
		name   string
		config *GenesisConfig
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name: "zero chain id",
			config: &GenesisConfig{
				ChainID:         0,
				SP1VerifyingKey: []byte("vk"),
			},
		},
		{
			name: "empty verifying key",
			config: &GenesisConfig{
				ChainID: 1,
			},
		},
		{
			name: "invalid governance",
			config: &GenesisConfig{
				ChainID:         1,
				SP1VerifyingKey: []byte("vk"),
				Governance:      GovernanceConfig{Mode: GovernanceMode(99)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrepareGenesis(tt.config)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestPrepareGenesisDefaultSats(t *testing.T) {
	config := &GenesisConfig{
		ChainID:          1,
		SP1VerifyingKey:  []byte("vk"),
		InitialStateRoot: testStateRoot(0),
		Governance:       GovernanceConfig{Mode: GovernanceNone},
		Verification:     VerifyFRI, // Basefold compiles; Groth16 needs BN254 not yet in Rúnar
		CovenantSats:     0,         // Should default to DefaultCovenantSats
	}

	result, err := PrepareGenesis(config)
	if err != nil {
		t.Fatalf("PrepareGenesis failed: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

// ---------------------------------------------------------------------------
// TestAdvanceDataValidation
// ---------------------------------------------------------------------------

func TestAdvanceDataValidation(t *testing.T) {
	covenant := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(covenant, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	tests := []struct {
		name         string
		newState     CovenantState
		batchData    []byte
		proof        []byte
		publicValues []byte
		wantErr      bool
	}{
		{
			name:         "valid advance",
			newState:     CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1},
			batchData:    []byte("batch"),
			proof:        []byte("proof"),
			publicValues: []byte("pv"),
			wantErr:      false,
		},
		{
			name:         "empty proof",
			newState:     CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1},
			batchData:    []byte("batch"),
			proof:        []byte{},
			publicValues: []byte("pv"),
			wantErr:      true,
		},
		{
			name:         "empty public values",
			newState:     CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1},
			batchData:    []byte("batch"),
			proof:        []byte("proof"),
			publicValues: []byte{},
			wantErr:      true,
		},
		{
			name:         "empty batch data",
			newState:     CovenantState{StateRoot: testStateRoot(1), BlockNumber: 1},
			batchData:    []byte{},
			proof:        []byte("proof"),
			publicValues: []byte("pv"),
			wantErr:      true,
		},
		{
			name:         "wrong block number (skip)",
			newState:     CovenantState{StateRoot: testStateRoot(5), BlockNumber: 5},
			batchData:    []byte("batch"),
			proof:        []byte("proof"),
			publicValues: []byte("pv"),
			wantErr:      true,
		},
		{
			name:         "wrong block number (same)",
			newState:     CovenantState{StateRoot: testStateRoot(0), BlockNumber: 0},
			batchData:    []byte("batch"),
			proof:        []byte("proof"),
			publicValues: []byte("pv"),
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cm.ValidateAdvanceData(tt.newState, tt.batchData, tt.proof, tt.publicValues)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAdvanceData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestDefaultCovenantSats
// ---------------------------------------------------------------------------

func TestDefaultCovenantSats(t *testing.T) {
	if DefaultCovenantSats != 10000 {
		t.Errorf("DefaultCovenantSats = %d, want 10000", DefaultCovenantSats)
	}
}

// ---------------------------------------------------------------------------
// TestCovenantManagerChainedAdvances
// ---------------------------------------------------------------------------

func TestCovenantManagerChainedAdvances(t *testing.T) {
	covenant := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(covenant, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	// Chain 5 advances
	for block := uint64(1); block <= 5; block++ {
		newState := CovenantState{
			StateRoot:   testStateRoot(block),
			BlockNumber: block,
			Frozen:      0,
		}
		err := cm.ValidateAdvanceData(newState, []byte("batch"), []byte("proof"), []byte("pv"))
		if err != nil {
			t.Fatalf("advance to block %d failed: %v", block, err)
		}
		newTxID := types.BytesToHash([]byte{byte(block)})
		if err := cm.ApplyAdvance(newTxID, newState); err != nil {
			t.Fatalf("ApplyAdvance block %d failed: %v", block, err)
		}

		if cm.CurrentState().BlockNumber != block {
			t.Errorf("after advance, expected block %d, got %d", block, cm.CurrentState().BlockNumber)
		}
	}
}

// ---------------------------------------------------------------------------
// TestHexToBytes
// ---------------------------------------------------------------------------

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{"empty", "", []byte{}, false},
		{"simple", "0102", []byte{1, 2}, false},
		{"with 0x prefix", "0x0102", []byte{1, 2}, false},
		{"uppercase", "AABB", []byte{0xaa, 0xbb}, false},
		{"mixed case", "aAbB", []byte{0xaa, 0xbb}, false},
		{"odd length", "abc", []byte{0x0a, 0xbc}, false},
		{"invalid char", "0xGG", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexToBytes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("hexToBytes(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("hexToBytes(%q) = %x, want %x", tt.input, got, tt.want)
			}
		})
	}
}

func TestVerificationModeString(t *testing.T) {
	tests := []struct {
		mode VerificationMode
		want string
	}{
		{VerifyGroth16, "groth16"},
		{VerifyFRI, "fri"},
		{VerificationMode(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("VerificationMode(%d).String() = %q, want %q", int(tt.mode), got, tt.want)
		}
	}
}

func TestCovenantManagerVerificationMode(t *testing.T) {
	covenant := &CompiledCovenant{
		LockingScript: []byte{0x01},
		ScriptHash:    sha256.Sum256([]byte{0x01}),
	}
	state := CovenantState{StateRoot: testStateRoot(0), BlockNumber: 0, Frozen: 0}

	// Groth16 mode (default, recommended)
	cm1 := NewCovenantManager(covenant, types.Hash{}, 0, DefaultCovenantSats, state, 1, VerifyGroth16)
	if cm1.VerificationMode() != VerifyGroth16 {
		t.Errorf("expected VerifyGroth16, got %s", cm1.VerificationMode())
	}

	// Basefold mode
	cm2 := NewCovenantManager(covenant, types.Hash{}, 0, DefaultCovenantSats, state, 1, VerifyFRI)
	if cm2.VerificationMode() != VerifyFRI {
		t.Errorf("expected VerifyFRI, got %s", cm2.VerificationMode())
	}
}

func TestGenesisConfigVerificationMode(t *testing.T) {
	// Default (zero value) should be VerifyGroth16
	config := &GenesisConfig{
		ChainID:          8453111,
		SP1VerifyingKey:  []byte{0x01, 0x02, 0x03},
		InitialStateRoot: testStateRoot(0),
		Governance:       GovernanceConfig{Mode: GovernanceNone},
	}
	if config.Verification != VerifyGroth16 {
		t.Errorf("default verification mode should be VerifyGroth16 (0), got %d", config.Verification)
	}

	// Explicit Basefold
	config.Verification = VerifyFRI
	if config.Verification != VerifyFRI {
		t.Errorf("expected VerifyFRI, got %s", config.Verification)
	}
}
