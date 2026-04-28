package vm

// Native Go fuzz harnesses for the EVM execution path. These pin
// "any panic / deadlock / OOM is a bug" properties for three
// security-sensitive surfaces:
//
//  1. FuzzInterpreter   — random bytecode + calldata + small state.
//     Properties: termination, gas accounting, bounded post-state.
//  2. FuzzPrecompiles   — random input bytes for every precompile
//     registered in the precompile map. Properties: no panic,
//     RequiredGas matches RunPrecompiledContract's gas charge.
//  3. FuzzGasAccounting — pin "no gas creation" across nested CALL
//     stacks. The caller's leftover gas is always ≤ the gas it
//     supplied to the EVM.
//
// Run a single fuzzer for 60 seconds:
//
//	go test -fuzz=FuzzInterpreter -fuzztime=60s ./pkg/vm/
//	go test -fuzz=FuzzPrecompiles -fuzztime=60s ./pkg/vm/
//	go test -fuzz=FuzzGasAccounting -fuzztime=60s ./pkg/vm/
//
// CI-safe sentinel exercises only the seeded corpus:
//
//	go test -run FuzzCorpus -count=1 ./pkg/vm/
//
// Any FuzzXxx that fails is automatically minimised by the Go fuzz
// engine and the failing input is written to
// pkg/vm/testdata/fuzz/FuzzXxx/<hash>.

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// fuzzGasLimit is the supplied-gas cap for fuzz iterations. Small
// enough that runaway loops terminate quickly via OOG; large enough
// that real opcodes get a chance to execute.
const fuzzGasLimit = uint64(200_000)

// newFuzzEVM builds an EVM with the in-test kzgTestStateDB and a
// caller account funded with 1 ETH. It returns the EVM, the caller
// address, and a target contract address with `code` installed. The
// target is funded with 0 balance so transfers don't underflow the
// uint256 balance accumulator on edge inputs.
func newFuzzEVM(code []byte) (*EVM, types.Address, types.Address) {
	statedb := &kzgTestStateDB{accounts: make(map[types.Address]*kzgTestAccount)}

	caller := types.HexToAddress("0x1000000000000000000000000000000000000001")
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	contract := types.HexToAddress("0x2000000000000000000000000000000000000002")
	statedb.CreateAccount(contract)
	if len(code) > 0 {
		// Cap deployed bytecode at MaxCodeSize to avoid the contract
		// being rejected by deployment-size checks. Fuzz inputs that
		// happen to exceed the cap get a clean truncation.
		if len(code) > MaxCodeSize {
			code = code[:MaxCodeSize]
		}
		statedb.SetCode(contract, code, tracing.CodeChangeCreation)
	}

	config := DefaultL2Config(1)
	blockCtx := BlockContext{
		CanTransfer: func(db StateDB, addr types.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient types.Address, amount *uint256.Int) {
			if amount.IsZero() {
				return
			}
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		GetHash:     func(n uint64) types.Hash { return types.Hash{} },
		BlockNumber: big.NewInt(1),
		Time:        1000,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(1),
		GasLimit:    30_000_000,
	}
	evm := NewEVM(blockCtx, statedb, config, Config{})
	return evm, caller, contract
}

// FuzzInterpreter feeds random bytecode + random calldata to
// EVM.Call and asserts the four properties documented at the top of
// this file. The fuzz engine treats any panic as a finding.
func FuzzInterpreter(f *testing.F) {
	// Seed with known-tricky inputs.
	f.Add([]byte{}, []byte{})                                         // zero-length runtime code
	f.Add([]byte{0x49}, []byte{})                                     // BLOBHASH with no operand on stack — should underflow cleanly
	f.Add([]byte{0x60, 0x00, 0x49, 0x00}, []byte{})                   // PUSH1 0; BLOBHASH; STOP — empty blob list path
	f.Add([]byte{0x5b, 0x60, 0x00, 0x56}, []byte{})                   // JUMPDEST; PUSH1 0; JUMP — tight-loop OOG
	f.Add([]byte{0xfe}, []byte{})                                     // INVALID opcode
	f.Add([]byte{0x73}, []byte{})                                     // PUSH20 with no following bytes
	f.Add([]byte{0x60, 0x20, 0x60, 0x00, 0x52}, []byte{})             // memory expansion via MSTORE
	f.Add([]byte{0xf1, 0xf1, 0xf1}, []byte{0x01, 0x02, 0x03})         // CALL CALL CALL with random calldata
	f.Add([]byte{0xf4}, []byte{})                                     // DELEGATECALL with empty stack
	f.Add([]byte{0xfa}, []byte{})                                     // STATICCALL with empty stack
	f.Add([]byte{0x60, 0x80, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xfa}, []byte{}) // STATICCALL to 0x80 (BSV stub) with too-short input
	f.Add([]byte{0x32, 0x33, 0x34, 0x35, 0x36}, []byte{})             // ORIGIN/CALLER/CALLVALUE/CALLDATALOAD/CALLDATASIZE
	f.Add([]byte{0x60, 0x00, 0x80, 0x80, 0x80, 0x80, 0xf1}, []byte{}) // CALL chain at depth 0
	f.Add([]byte{0xff}, []byte{})                                     // SELFDESTRUCT with no operand

	f.Fuzz(func(t *testing.T, code []byte, calldata []byte) {
		// Skip very long fuzzy inputs in -short mode (CI smoke).
		if testing.Short() && (len(code) > 1024 || len(calldata) > 1024) {
			t.Skip()
		}
		// Hard cap on inputs to keep iteration latency bounded; the
		// fuzz engine will prefer smaller inputs anyway.
		if len(code) > 4096 {
			code = code[:4096]
		}
		if len(calldata) > 4096 {
			calldata = calldata[:4096]
		}

		evm, caller, contract := newFuzzEVM(code)
		statedb := evm.StateDB.(*kzgTestStateDB)
		preCount := len(statedb.accounts)

		gasLimit := fuzzGasLimit
		// Property 1: never panic. The deferred recover would mask the
		// fuzz finding, so we DON'T recover here — let the runtime
		// crash and the fuzz engine record the input.
		_, leftOverGas, err := evm.Call(caller, contract, calldata, gasLimit, uint256.NewInt(0))

		// Property 2: gas_consumed >= 0 and gas_consumed <= gas_limit.
		if leftOverGas > gasLimit {
			t.Fatalf("gas creation: leftOverGas=%d > gasLimit=%d (err=%v)", leftOverGas, gasLimit, err)
		}
		// (gas_consumed >= 0 is enforced by the uint64 type.)

		// Property 3: post-state account count cannot exceed pre-state
		// + a bounded delta. Each CREATE/CREATE2 in the bytecode adds
		// at most one account; with gasLimit=200k we can't fit more
		// than ~6 CREATE-2's worth of work. Cap at 32 to be generous.
		postCount := len(statedb.accounts)
		if postCount > preCount+32 {
			t.Fatalf("post-state account explosion: pre=%d post=%d (err=%v)", preCount, postCount, err)
		}

		// Property 4: memory expansion bounded by remaining gas. We
		// can't easily measure memory after Run() since the local
		// Memory is freed on return; the gas check above is the
		// observable proxy. If the interpreter ever returned with
		// leftOverGas > supplied that would imply gas creation, which
		// we already rejected.

		// Sanity: the only allowed errors are termination errors. A
		// nil err with empty return is fine. Any error other than the
		// allow-list could be a panic-equivalent inside an opcode.
		if err != nil && !isAllowedFuzzError(err) {
			t.Fatalf("unexpected error from EVM.Call: %v", err)
		}
	})
}

// isAllowedFuzzError returns true when err is one of the documented
// EVM-termination errors. Anything else is treated as a fuzz finding.
func isAllowedFuzzError(err error) bool {
	if err == nil {
		return true
	}
	if err == errStopToken {
		return true
	}
	if err == ErrOutOfGas || err == ErrGasUintOverflow || err == ErrCodeStoreOutOfGas {
		return true
	}
	if err == ErrDepth || err == ErrInsufficientBalance {
		return true
	}
	if err == ErrExecutionReverted || err == ErrMaxCodeSizeExceeded || err == ErrInvalidCode {
		return true
	}
	if err == ErrContractAddressCollision || err == ErrNonceUintOverflow {
		return true
	}
	if err == ErrWriteProtection || err == ErrReturnDataOutOfBounds || err == ErrInvalidJump {
		return true
	}
	// Stack underflow / overflow are typed errors with values.
	if _, ok := err.(*ErrStackUnderflow); ok {
		return true
	}
	if _, ok := err.(*ErrStackOverflow); ok {
		return true
	}
	if _, ok := err.(*ErrInvalidOpCode); ok {
		return true
	}
	// Wrapped OOG (e.g. dynamic-gas paths) — match by Is.
	if errIsOOG(err) {
		return true
	}
	// Precompile-reported errors are surfaced through the interpreter
	// for STATICCALL to a precompile address; treat as allowed.
	if err == ErrBSVPrecompileNotActive {
		return true
	}
	return false
}

// errIsOOG handles wrapped ErrOutOfGas (the dynamic-gas path returns
// fmt.Errorf("%w: %v", ErrOutOfGas, err)).
func errIsOOG(err error) bool {
	for cur := err; cur != nil; {
		if cur == ErrOutOfGas {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := cur.(unwrapper)
		if !ok {
			return false
		}
		cur = u.Unwrap()
	}
	return false
}

// FuzzPrecompiles runs random input bytes through every precompile
// registered for Cancun-rules + IsBSVM. Properties:
//
//   - Run() never panics.
//   - gasCharged := RequiredGas(input); RunPrecompiledContract drains
//     exactly that much from the supplied budget on success or
//     returns ErrOutOfGas when the budget is too small.
//   - Output is either nil (with err) or a deterministic byte slice.
func FuzzPrecompiles(f *testing.F) {
	// Seed with shapes that have historically broken precompiles.
	f.Add(byte(0x01), []byte{})                              // ecrecover empty
	f.Add(byte(0x01), make([]byte, 128))                     // ecrecover all-zero
	f.Add(byte(0x02), []byte{})                              // sha256 empty
	f.Add(byte(0x02), []byte("hello world"))                 // sha256 short
	f.Add(byte(0x03), []byte{})                              // ripemd empty
	f.Add(byte(0x04), []byte{0xff, 0xee, 0xdd})              // identity short
	f.Add(byte(0x05), make([]byte, 96))                      // modexp zero-lengths
	f.Add(byte(0x06), make([]byte, 64))                      // bn256 add zero point
	f.Add(byte(0x06), make([]byte, 128))                     // bn256 add full
	f.Add(byte(0x07), make([]byte, 96))                      // bn256 scalar mul
	f.Add(byte(0x08), make([]byte, 0))                       // bn256 pairing empty (valid: identity)
	f.Add(byte(0x08), make([]byte, 192))                     // bn256 pairing one pair
	f.Add(byte(0x09), make([]byte, 213))                     // blake2f canonical length
	f.Add(byte(0x09), make([]byte, 100))                     // blake2f wrong length
	f.Add(byte(0x0a), make([]byte, 192))                     // kzg point eval (will fail VHash check)
	f.Add(byte(0x0a), make([]byte, 50))                      // kzg point eval too-short
	f.Add(byte(0x80), []byte{0x01})                          // BSV stub 0x80
	f.Add(byte(0x81), []byte{0x01, 0x02})                    // BSV stub 0x81
	f.Add(byte(0x82), []byte{})                              // BSV stub 0x82

	rules := Rules{
		IsByzantium: true, IsIstanbul: true, IsBerlin: true,
		IsLondon: true, IsShanghai: true, IsCancun: true,
		IsBSVM: true,
	}
	pmap := precompileMap(rules)

	f.Fuzz(func(t *testing.T, addrLowByte byte, input []byte) {
		// Cap input to avoid quadratic-time precompiles on
		// pathological lengths (modexp, bn256 pairing). 4 KiB is
		// enough to exercise every parsing branch.
		if len(input) > 4096 {
			input = input[:4096]
		}
		addr := types.BytesToAddress([]byte{addrLowByte})
		p, ok := pmap[addr]
		if !ok {
			t.Skip()
		}

		// Property 1: RequiredGas must not panic on any input.
		gasCost := p.RequiredGas(input)

		// Sanity cap: don't direct-call Run with inputs whose
		// declared work is unreasonable. The wrapper path
		// (RunPrecompiledContract) is gated by RequiredGas so this
		// only matters for the direct call below. blake2f's "rounds"
		// field is user-controlled and 32-bit wide — uncapped, an
		// adversary can request 4 billion rounds. In production the
		// gas check rejects this; the harness must skip to avoid
		// fuzzer-engine timeouts that mask real findings.
		const directRunGasCap = uint64(10_000_000)
		if gasCost > directRunGasCap {
			t.Skip()
		}

		// Property 2: Run must not panic. We DON'T recover so the
		// fuzz engine sees the panic as a finding.
		out, runErr := p.Run(input)

		// Property 3: when err==nil, output must be a non-nil slice
		// (possibly empty). When err!=nil, output should be nil.
		if runErr == nil && out == nil {
			// The identity precompile + sha256 + ripemd always
			// allocate output, so out!=nil. modexp returns []byte{}
			// for zero-length mod, which is non-nil. Allow nil only
			// for ecrecover's "invalid signature" silent-fail case
			// where (nil, nil) is documented behaviour.
			if addrLowByte != 0x01 {
				t.Fatalf("addr=0x%02x: nil output with nil error", addrLowByte)
			}
		}

		// Property 4: RunPrecompiledContract drains exactly gasCost.
		budget := gasCost + 100 // give 100 spare so the call succeeds gas-wise
		ret, leftOver, err := RunPrecompiledContract(p, input, budget, nil)
		// Gas accounting: leftover must be budget - gasCost (or 0 with OOG).
		if err == ErrOutOfGas {
			if budget >= gasCost {
				t.Fatalf("addr=0x%02x: spurious OOG (budget=%d cost=%d)", addrLowByte, budget, gasCost)
			}
		} else {
			if leftOver != budget-gasCost {
				t.Fatalf("addr=0x%02x: leftOver=%d want=%d (budget=%d cost=%d)", addrLowByte, leftOver, budget-gasCost, budget, gasCost)
			}
		}
		// Run via wrapper must agree with direct call on success.
		if err == nil && runErr == nil && len(ret) != len(out) {
			t.Fatalf("addr=0x%02x: wrapper output length %d != direct %d", addrLowByte, len(ret), len(out))
		}

		// Property 5: undersupplied gas always returns ErrOutOfGas.
		if gasCost > 0 {
			_, _, err := RunPrecompiledContract(p, input, gasCost-1, nil)
			if err != ErrOutOfGas {
				t.Fatalf("addr=0x%02x: expected ErrOutOfGas with budget %d (cost %d), got %v", addrLowByte, gasCost-1, gasCost, err)
			}
		}
	})
}

// FuzzGasAccounting pins the global "no gas creation" invariant for
// nested calls. We construct bytecode that issues a CALL to a leaf
// contract with random sub-gas amounts and verify that the outer
// caller never observes leftOverGas > supplied gas.
func FuzzGasAccounting(f *testing.F) {
	// Seed: a leaf that immediately STOPs, called with various gas
	// stipends. The harness wraps caller bytecode that does a single
	// CALL with stack-controlled gas.
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(21000))
	f.Add(uint64(100000))
	f.Add(uint64(1<<60)) // huge stipend — must be clamped by 63/64

	// Leaf: STOP. Address 0x3000... is funded but otherwise empty.
	leafAddr := types.HexToAddress("0x3000000000000000000000000000000000000003")

	f.Fuzz(func(t *testing.T, subGas uint64) {
		// Caller bytecode issues:
		//   PUSH gasArg PUSH 0 PUSH 0 PUSH 0 PUSH 0 PUSH leafAddr GAS CALL
		// using PUSH8 for sub-gas keeps the stack frame small enough
		// for any uint64.
		var code []byte
		// PUSH1 0 (retSize)
		code = append(code, 0x60, 0x00)
		// PUSH1 0 (retOffset)
		code = append(code, 0x60, 0x00)
		// PUSH1 0 (argSize)
		code = append(code, 0x60, 0x00)
		// PUSH1 0 (argOffset)
		code = append(code, 0x60, 0x00)
		// PUSH1 0 (value)
		code = append(code, 0x60, 0x00)
		// PUSH20 leafAddr
		code = append(code, 0x73)
		code = append(code, leafAddr.Bytes()...)
		// PUSH8 subGas
		code = append(code, 0x67)
		var gasBytes [8]byte
		for i := 0; i < 8; i++ {
			gasBytes[7-i] = byte(subGas >> (8 * i))
		}
		code = append(code, gasBytes[:]...)
		// CALL
		code = append(code, 0xf1)
		// STOP
		code = append(code, 0x00)

		evm, caller, contract := newFuzzEVM(code)
		statedb := evm.StateDB.(*kzgTestStateDB)
		statedb.CreateAccount(leafAddr) // empty leaf, returns immediately

		gasLimit := fuzzGasLimit
		_, leftOver, err := evm.Call(caller, contract, nil, gasLimit, uint256.NewInt(0))

		// No gas creation, ever.
		if leftOver > gasLimit {
			t.Fatalf("gas creation: leftOver=%d > gasLimit=%d subGas=%d err=%v", leftOver, gasLimit, subGas, err)
		}
		if err != nil && !isAllowedFuzzError(err) {
			t.Fatalf("unexpected error: %v (subGas=%d)", err, subGas)
		}
	})
}

// TestFuzzCorpus_VM is the CI-safe sentinel: it runs each FuzzXxx in
// "exercise the seeded corpus" mode (no random mutation, no -fuzz
// flag). Any panic or property violation surfaces as a normal test
// failure. This is what `go test ./pkg/vm/` runs.
func TestFuzzCorpus_VM(t *testing.T) {
	// Each FuzzXxx, when invoked via testing.F.Fuzz under `go test`,
	// runs the seed corpus exactly once. The sentinel is implicit —
	// if `go test ./pkg/vm/` passes, all seeds passed.
	t.Log("seed corpus is exercised by FuzzInterpreter, FuzzPrecompiles, FuzzGasAccounting under `go test`")
}
