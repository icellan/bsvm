package fuzz

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// FuzzEVMExecution runs random bytecode with random calldata through the
// EVM and verifies that execution always completes (success or error)
// without panicking.
func FuzzEVMExecution(f *testing.F) {
	// Seed with known bytecodes.
	// STOP
	f.Add([]byte{0x00}, []byte{})
	// PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	f.Add([]byte{0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}, []byte{})
	// PUSH1 0x01 PUSH1 0x01 ADD POP STOP
	f.Add([]byte{0x60, 0x01, 0x60, 0x01, 0x01, 0x50, 0x00}, []byte{})
	// CALLDATALOAD STOP
	f.Add([]byte{0x60, 0x00, 0x35, 0x00}, []byte{0x01, 0x02, 0x03, 0x04})
	// PUSH1 0x00 SLOAD STOP (storage load)
	f.Add([]byte{0x60, 0x00, 0x54, 0x00}, []byte{})
	// PUSH1 0x42 PUSH1 0x00 SSTORE STOP (storage store)
	f.Add([]byte{0x60, 0x42, 0x60, 0x00, 0x55, 0x00}, []byte{})
	// INVALID opcode
	f.Add([]byte{0xfe}, []byte{})
	// REVERT
	f.Add([]byte{0x60, 0x00, 0x60, 0x00, 0xfd}, []byte{})
	// Random-looking bytecode
	f.Add([]byte{0x60, 0xff, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0x20}, []byte{})
	// Empty bytecode (immediate stop)
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, code []byte, calldata []byte) {
		// Limit code and calldata size to keep execution bounded.
		if len(code) > 1024 {
			code = code[:1024]
		}
		if len(calldata) > 256 {
			calldata = calldata[:256]
		}

		// Create a fresh in-memory StateDB.
		sdb := state.NewMemoryStateDB()

		// Set up the contract account with the fuzzed code.
		contractAddr := types.HexToAddress("0xc0de000000000000000000000000000000000001")
		callerAddr := types.HexToAddress("0xca11e70000000000000000000000000000000001")

		sdb.CreateAccount(contractAddr)
		sdb.SetCode(contractAddr, code, tracing.CodeChangeUnspecified)
		sdb.CreateAccount(callerAddr)
		sdb.AddBalance(callerAddr, uint256.NewInt(1_000_000_000_000_000_000), tracing.BalanceChangeUnspecified)

		// Create the EVM with a standard L2 config.
		chainConfig := vm.DefaultL2Config(1337)
		blockNum := big.NewInt(1)
		blockCtx := vm.BlockContext{
			CanTransfer: canTransfer,
			Transfer:    transfer,
			GetHash:     getHash,
			Coinbase:    types.Address{},
			GasLimit:    30_000_000,
			BlockNumber: blockNum,
			Time:        1000,
			Difficulty:  big.NewInt(0),
			BaseFee:     big.NewInt(0),
		}
		evmInstance := vm.NewEVM(blockCtx, sdb, chainConfig, vm.Config{})
		evmInstance.SetTxContext(vm.TxContext{
			Origin:   callerAddr,
			GasPrice: big.NewInt(1),
		})

		// Prepare the access list.
		rules := chainConfig.Rules(blockNum, true, 1000)
		sdb.Prepare(rules, callerAddr, types.Address{}, &contractAddr, activePrecompileAddrs(rules), nil)

		// Execute with limited gas. Must not panic.
		_, _, err := evmInstance.Call(callerAddr, contractAddr, calldata, 100_000, uint256.NewInt(0))

		// Any result (success or error) is acceptable -- we only
		// care that execution completes without panicking.
		_ = err
	})
}

// canTransfer checks if the sender has enough balance.
func canTransfer(db vm.StateDB, addr types.Address, amount *uint256.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// transfer moves value between two accounts.
func transfer(db vm.StateDB, sender, recipient types.Address, amount *uint256.Int) {
	db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
	db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
}

// getHash returns a dummy block hash.
func getHash(n uint64) types.Hash {
	return types.BytesToHash([]byte{byte(n)})
}

// activePrecompileAddrs returns the precompile addresses active for the
// given chain rules. This matches the addresses the EVM will check.
func activePrecompileAddrs(rules vm.Rules) []types.Address {
	// Standard Ethereum precompiles at addresses 0x01-0x09.
	addrs := make([]types.Address, 0, 9)
	for i := 1; i <= 9; i++ {
		addrs = append(addrs, types.BytesToAddress([]byte{byte(i)}))
	}
	if rules.IsCancun {
		// EIP-4844 point evaluation precompile at 0x0a.
		addrs = append(addrs, types.BytesToAddress([]byte{0x0a}))
	}
	return addrs
}
