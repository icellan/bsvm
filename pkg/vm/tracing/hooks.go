package tracing

import (
	"math/big"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/holiman/uint256"
)

// Hooks is the collection of tracing hooks that can be used to observe EVM execution.
// All fields are optional -- nil hooks are not called.
type Hooks struct {
	// OnTxStart is called before a transaction starts executing.
	OnTxStart func(gasLimit uint64)
	// OnTxEnd is called after a transaction finishes executing.
	OnTxEnd func(gasUsed uint64, err error)
	// OnEnter is called when the EVM enters a new scope (call, create, etc).
	OnEnter func(depth int, typ byte, from types.Address, to types.Address, input []byte, gas uint64, value *big.Int)
	// OnExit is called when the EVM exits a scope.
	OnExit func(depth int, output []byte, gasUsed uint64, err error, reverted bool)
	// OnOpcode is called for each opcode executed.
	OnOpcode func(pc uint64, op byte, gas, cost uint64, scope OpContext, rData []byte, depth int, err error)
	// OnFault is called when an error occurs during execution.
	OnFault func(pc uint64, op byte, gas, cost uint64, scope OpContext, depth int, err error)
	// OnGasChange is called when gas is consumed or refunded.
	OnGasChange func(old, new uint64, reason GasChangeReason)
	// OnBalanceChange is called when an account balance changes.
	OnBalanceChange func(addr types.Address, prev, new *big.Int, reason BalanceChangeReason)
	// OnNonceChange is called when an account nonce changes.
	OnNonceChange func(addr types.Address, prev, new uint64)
	// OnCodeChange is called when contract code is set.
	OnCodeChange func(addr types.Address, prevCodeHash types.Hash, prevCode []byte, codeHash types.Hash, code []byte)
	// OnStorageChange is called when a storage slot is modified.
	OnStorageChange func(addr types.Address, slot types.Hash, prev, new types.Hash)
	// OnLog is called when a LOG opcode is executed.
	OnLog func(log *LogRecord)
	// OnBlockHashRead is called when BLOCKHASH reads a block hash.
	OnBlockHashRead func(blockNum uint64, hash types.Hash)
}

// OpContext provides context about the current operation for tracers.
type OpContext interface {
	// MemoryData returns the memory contents of the current scope.
	MemoryData() []byte
	// StackData returns the stack data of the current scope.
	StackData() []uint256.Int
	// Caller returns the caller address of the current scope.
	Caller() types.Address
	// Address returns the address of the contract being executed.
	Address() types.Address
	// CallValue returns the value sent with the current call.
	CallValue() *uint256.Int
	// CallInput returns the input data of the current call.
	CallInput() []byte
	// ContractCode returns the code of the contract being executed.
	ContractCode() []byte
}

// VMContext provides context about the block being executed.
type VMContext struct {
	Coinbase    types.Address
	BlockNumber *big.Int
	Time        uint64
	Random      *types.Hash
	BaseFee     *big.Int
	StateDB     interface{} // opaque to avoid circular dependency
}

// LogRecord is a simplified log record for tracing.
type LogRecord struct {
	// Address is the contract address that generated the log.
	Address [20]byte
	// Topics are the indexed log topics.
	Topics [][32]byte
	// Data is the non-indexed log data.
	Data []byte
}
