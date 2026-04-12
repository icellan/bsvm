package main

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// TestDisassemble verifies that known bytecode disassembles to the expected
// mnemonic output.
func TestDisassemble(t *testing.T) {
	// PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	code, err := hex.DecodeString("604260005260206000f3")
	if err != nil {
		t.Fatal(err)
	}
	got := disasmToString(code)

	expected := []string{
		"0000: PUSH1 0x42",
		"0002: PUSH1 0x00",
		"0004: MSTORE",
		"0005: PUSH1 0x20",
		"0007: PUSH1 0x00",
		"0009: RETURN",
	}
	for _, exp := range expected {
		if !strings.Contains(got, exp) {
			t.Errorf("disassembly missing expected line %q\ngot:\n%s", exp, got)
		}
	}
}

// TestHash verifies keccak256 against a known test vector.
func TestHash(t *testing.T) {
	// keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
	hash := crypto.Keccak256([]byte{})
	got := hex.EncodeToString(hash)
	want := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got != want {
		t.Errorf("keccak256('') = %s, want %s", got, want)
	}

	// keccak256(0x00) = bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a
	hash2 := crypto.Keccak256([]byte{0x00})
	got2 := hex.EncodeToString(hash2)
	want2 := "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"
	if got2 != want2 {
		t.Errorf("keccak256(0x00) = %s, want %s", got2, want2)
	}
}

// TestRunSimple executes bytecode that stores 0x42 in memory and returns 32
// bytes, then verifies the return data and gas consumption.
func TestRunSimple(t *testing.T) {
	// PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	codeHex := "604260005260206000f3"
	code, err := hex.DecodeString(codeHex)
	if err != nil {
		t.Fatal(err)
	}

	statedb := state.NewMemoryStateDB()
	sender := types.HexToAddress("0x1000000000000000000000000000000000000001")
	contractAddr := types.HexToAddress("0x2000000000000000000000000000000000000002")

	senderBalance := new(uint256.Int).Mul(
		uint256.NewInt(1_000_000_000),
		uint256.NewInt(1_000_000_000),
	)
	statedb.AddBalance(sender, senderBalance, 0)

	statedb.CreateAccount(contractAddr)
	statedb.SetCode(contractAddr, code, 0)

	chainCfg := vm.DefaultL2Config(1)
	blockCtx := vm.BlockContext{
		CanTransfer: vm.CanTransfer,
		Transfer:    vm.Transfer,
		GetHash: func(n uint64) types.Hash {
			return types.Hash{}
		},
		Coinbase:    types.Address{},
		GasLimit:    30_000_000,
		BlockNumber: big.NewInt(1),
		Time:        1,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(0),
	}

	txCtx := vm.TxContext{
		Origin:   sender,
		GasPrice: big.NewInt(0),
	}

	evm := vm.NewEVM(blockCtx, statedb, chainCfg, vm.Config{})
	evm.TxContext = txCtx

	rules := chainCfg.Rules(blockCtx.BlockNumber, false, blockCtx.Time)
	statedb.Prepare(rules, sender, types.Address{}, &contractAddr, nil, nil)

	gas := uint64(10_000_000)
	ret, leftOverGas, err := evm.Call(sender, contractAddr, nil, gas, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("EVM call failed: %v", err)
	}

	gasUsed := gas - leftOverGas
	if gasUsed == 0 {
		t.Error("expected nonzero gas used")
	}

	// The return value should be 32 bytes with 0x42 at the last byte.
	if len(ret) != 32 {
		t.Fatalf("expected 32 bytes return data, got %d", len(ret))
	}
	if ret[31] != 0x42 {
		t.Errorf("expected return[31] = 0x42, got 0x%02x", ret[31])
	}

	// Verify all other bytes are zero (EVM pads left).
	for i := 0; i < 31; i++ {
		if ret[i] != 0 {
			t.Errorf("expected return[%d] = 0x00, got 0x%02x", i, ret[i])
		}
	}
}

// TestDisassemblePUSH0 verifies PUSH0 (0x5f) disassembly.
func TestDisassemblePUSH0(t *testing.T) {
	// PUSH0 STOP
	code := []byte{0x5f, 0x00}
	got := disasmToString(code)
	if !strings.Contains(got, "PUSH0") {
		t.Errorf("expected PUSH0 in disassembly, got:\n%s", got)
	}
	if !strings.Contains(got, "STOP") {
		t.Errorf("expected STOP in disassembly, got:\n%s", got)
	}
}
