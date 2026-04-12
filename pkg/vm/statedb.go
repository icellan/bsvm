package vm

import (
	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// StateDB is the interface that the EVM uses to read and write world state.
// This is the single most important seam in the architecture: the EVM
// interpreter only depends on this interface, never on a concrete state
// implementation.
type StateDB interface {
	// CreateAccount creates a new account.
	CreateAccount(types.Address)
	// CreateContract marks an address as a contract being created.
	CreateContract(types.Address)
	// Exist reports whether the given account exists in the state.
	Exist(types.Address) bool
	// Empty returns whether the given account is considered empty (no code, zero nonce, zero balance).
	Empty(types.Address) bool

	// GetBalance returns the balance of the given account.
	GetBalance(types.Address) *uint256.Int
	// AddBalance adds amount to the account balance. Returns the previous balance.
	AddBalance(types.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int
	// SubBalance subtracts amount from the account balance. Returns the previous balance.
	SubBalance(types.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int

	// GetNonce returns the nonce of the account.
	GetNonce(types.Address) uint64
	// SetNonce sets the nonce of the account.
	SetNonce(types.Address, uint64, tracing.NonceChangeReason)

	// GetCode returns the code associated with the account.
	GetCode(types.Address) []byte
	// SetCode sets the code for the account. Returns the previous code.
	SetCode(types.Address, []byte, tracing.CodeChangeReason) []byte
	// GetCodeHash returns the code hash of the account.
	GetCodeHash(types.Address) types.Hash
	// GetCodeSize returns the size of the code associated with the account.
	GetCodeSize(types.Address) int

	// GetState returns the value of a storage slot.
	GetState(types.Address, types.Hash) types.Hash
	// GetCommittedState returns the value of a storage slot from the committed state.
	GetCommittedState(types.Address, types.Hash) types.Hash
	// SetState sets the value of a storage slot. Returns the previous value.
	SetState(types.Address, types.Hash, types.Hash) types.Hash
	// GetStorageRoot returns the storage root of the account.
	GetStorageRoot(types.Address) types.Hash

	// GetTransientState returns a value from transient storage (EIP-1153).
	GetTransientState(types.Address, types.Hash) types.Hash
	// SetTransientState sets a value in transient storage (EIP-1153).
	SetTransientState(types.Address, types.Hash, types.Hash)

	// SelfDestruct marks the account for self-destruction.
	SelfDestruct(types.Address)
	// HasSelfDestructed returns whether the account has been self-destructed.
	HasSelfDestructed(types.Address) bool
	// Selfdestruct6780 implements EIP-6780: only self-destructs if created in same tx.
	Selfdestruct6780(types.Address)

	// AddLog adds a log entry.
	AddLog(*types.Log)
	// AddRefund adds gas to the refund counter.
	AddRefund(uint64)
	// SubRefund subtracts gas from the refund counter.
	SubRefund(uint64)
	// GetRefund returns the current refund counter.
	GetRefund() uint64

	// AddPreimage records a SHA3 preimage.
	AddPreimage(types.Hash, []byte)

	// AddressInAccessList returns whether the address is in the access list.
	AddressInAccessList(types.Address) bool
	// SlotInAccessList returns whether the address and slot are in the access list.
	SlotInAccessList(types.Address, types.Hash) (bool, bool)
	// AddAddressToAccessList adds an address to the access list.
	AddAddressToAccessList(types.Address)
	// AddSlotToAccessList adds an address+slot pair to the access list.
	AddSlotToAccessList(types.Address, types.Hash)

	// Snapshot creates a snapshot of the current state and returns a revision id.
	Snapshot() int
	// RevertToSnapshot reverts state to the given snapshot.
	RevertToSnapshot(int)

	// Prepare sets up the access list for an upcoming transaction.
	Prepare(rules Rules, sender, coinbase types.Address, dest *types.Address, precompiles []types.Address, txAccess types.AccessList)
}
