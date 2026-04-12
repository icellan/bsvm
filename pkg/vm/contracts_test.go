package vm

import (
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// TestBSVStubPrecompilesRegistered verifies that BSV precompile addresses
// 0x80-0x82 are present in the precompile map for all fork levels.
func TestBSVStubPrecompilesRegistered(t *testing.T) {
	addrs := []types.Address{
		types.BytesToAddress([]byte{0x80}),
		types.BytesToAddress([]byte{0x81}),
		types.BytesToAddress([]byte{0x82}),
	}

	// Test across multiple fork levels.
	rules := []struct {
		name  string
		rules Rules
	}{
		{"frontier", Rules{IsBSVM: true}},
		{"byzantium", Rules{IsByzantium: true, IsBSVM: true}},
		{"istanbul", Rules{IsByzantium: true, IsIstanbul: true, IsBSVM: true}},
		{"berlin", Rules{IsByzantium: true, IsIstanbul: true, IsBerlin: true, IsBSVM: true}},
		{"cancun", Rules{IsByzantium: true, IsIstanbul: true, IsBerlin: true, IsCancun: true, IsBSVM: true}},
	}

	for _, tc := range rules {
		t.Run(tc.name, func(t *testing.T) {
			m := precompileMap(tc.rules)
			for _, addr := range addrs {
				if _, ok := m[addr]; !ok {
					t.Errorf("BSV precompile %s not registered in %s fork", addr.Hex(), tc.name)
				}
			}
		})
	}
}

// TestBSVStubPrecompilesRevert verifies that calling a BSV stub precompile
// returns ErrBSVPrecompileNotActive and that gas is consumed proportionally.
func TestBSVStubPrecompilesRevert(t *testing.T) {
	stub := &stubBSVPrecompile{}

	tests := []struct {
		name        string
		input       []byte
		expectedGas uint64
	}{
		{"empty_input", nil, 0},
		{"one_byte", []byte{0x01}, 1},
		{"32_bytes", make([]byte, 32), 32},
		{"256_bytes", make([]byte, 256), 256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gas := stub.RequiredGas(tc.input)
			if gas != tc.expectedGas {
				t.Errorf("RequiredGas(%d bytes) = %d, want %d", len(tc.input), gas, tc.expectedGas)
			}

			result, err := stub.Run(tc.input)
			if err != ErrBSVPrecompileNotActive {
				t.Errorf("Run() error = %v, want ErrBSVPrecompileNotActive", err)
			}
			if result != nil {
				t.Errorf("Run() returned non-nil result: %x", result)
			}
		})
	}
}

// TestBSVStubPrecompilesRunPrecompiled verifies the full RunPrecompiledContract
// path for BSV stubs: gas is consumed, error is returned.
func TestBSVStubPrecompilesRunPrecompiled(t *testing.T) {
	stub := &stubBSVPrecompile{}
	input := make([]byte, 100)

	// Case 1: enough gas — gas consumed, error returned.
	ret, remainGas, err := RunPrecompiledContract(stub, input, 200, nil)
	if err != ErrBSVPrecompileNotActive {
		t.Fatalf("expected ErrBSVPrecompileNotActive, got %v", err)
	}
	if ret != nil {
		t.Fatalf("expected nil return, got %x", ret)
	}
	if remainGas != 100 {
		t.Fatalf("expected 100 remaining gas, got %d", remainGas)
	}

	// Case 2: not enough gas — ErrOutOfGas.
	_, _, err = RunPrecompiledContract(stub, input, 50, nil)
	if err != ErrOutOfGas {
		t.Fatalf("expected ErrOutOfGas, got %v", err)
	}
}

// TestBSVPrecompilesExcludedFromActiveList verifies that BSV precompiles
// are NOT returned by ActivePrecompiles, preserving EIP-2929 warm/cold
// gas semantics for ethereum/tests compatibility.
func TestBSVPrecompilesExcludedFromActiveList(t *testing.T) {
	bsvAddrs := map[types.Address]bool{
		types.BytesToAddress([]byte{0x80}): true,
		types.BytesToAddress([]byte{0x81}): true,
		types.BytesToAddress([]byte{0x82}): true,
	}

	rules := Rules{IsByzantium: true, IsIstanbul: true, IsBerlin: true, IsCancun: true, IsBSVM: true}
	active := ActivePrecompiles(rules)

	for _, addr := range active {
		if bsvAddrs[addr] {
			t.Errorf("BSV precompile %s should not be in ActivePrecompiles list", addr.Hex())
		}
	}

	// Verify standard precompiles ARE present.
	standardCount := 0
	for _, addr := range active {
		if !bsvAddrs[addr] {
			standardCount++
		}
	}
	if standardCount != 10 { // 0x01-0x0a
		t.Errorf("expected 10 standard precompiles, got %d", standardCount)
	}
}

// TestIsBSVPrecompile verifies the isBSVPrecompile helper.
func TestIsBSVPrecompile(t *testing.T) {
	tests := []struct {
		addr   byte
		expect bool
	}{
		{0x01, false},
		{0x0a, false},
		{0x7f, false},
		{0x80, true},
		{0x81, true},
		{0x82, true},
		{0x83, false},
		{0xff, false},
	}

	for _, tc := range tests {
		addr := types.BytesToAddress([]byte{tc.addr})
		got := isBSVPrecompile(addr)
		if got != tc.expect {
			t.Errorf("isBSVPrecompile(0x%02x) = %v, want %v", tc.addr, got, tc.expect)
		}
	}
}

// TestBSVPrecompilesNotRegisteredWithoutFlag verifies that BSV precompiles
// are NOT in the precompile map when IsBSVM is false (ethereum/tests mode).
func TestBSVPrecompilesNotRegisteredWithoutFlag(t *testing.T) {
	bsvAddrs := []types.Address{
		types.BytesToAddress([]byte{0x80}),
		types.BytesToAddress([]byte{0x81}),
		types.BytesToAddress([]byte{0x82}),
	}

	// Without IsBSVM, these should not be registered.
	rules := Rules{IsByzantium: true, IsIstanbul: true, IsBerlin: true, IsCancun: true}
	m := precompileMap(rules)
	for _, addr := range bsvAddrs {
		if _, ok := m[addr]; ok {
			t.Errorf("BSV precompile %s should NOT be registered without IsBSVM flag", addr.Hex())
		}
	}
}
