package vm

import (
	"math/big"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// BlockContext provides the EVM with auxiliary information about the current block.
// Once created it should not be modified.
type BlockContext struct {
	// CanTransfer returns whether the account has enough balance for a transfer.
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to another.
	Transfer TransferFunc
	// GetHash returns the hash of the block with the given number.
	GetHash GetHashFunc
	// Coinbase is the beneficiary address for block rewards.
	Coinbase types.Address
	// GasLimit is the maximum gas available for this block.
	GasLimit uint64
	// BlockNumber is the current block number.
	BlockNumber *big.Int
	// Time is the block timestamp.
	Time uint64
	// Difficulty is the current block difficulty (pre-merge).
	Difficulty *big.Int
	// BaseFee is the EIP-1559 base fee.
	BaseFee *big.Int
	// BlobBaseFee is the EIP-4844 blob base fee.
	BlobBaseFee *big.Int
	// Random is the post-merge PREVRANDAO value.
	Random *types.Hash
}

// TxContext provides the EVM with information about the current transaction.
type TxContext struct {
	// Origin is the sender of the transaction.
	Origin types.Address
	// GasPrice is the gas price for the transaction.
	GasPrice *big.Int
	// BlobHashes contains the versioned hashes from EIP-4844 blob transactions.
	BlobHashes []types.Hash
	// BlobFeeCap is the max blob fee the sender is willing to pay.
	BlobFeeCap *big.Int
}

// CanTransferFunc is the function type for checking transfer feasibility.
type CanTransferFunc func(StateDB, types.Address, *uint256.Int) bool

// TransferFunc is the function type for transferring value between accounts.
type TransferFunc func(StateDB, types.Address, types.Address, *uint256.Int)

// GetHashFunc is the function type for retrieving a block hash by number.
type GetHashFunc func(uint64) types.Hash

// CanTransfer checks whether the account has sufficient balance for a transfer.
func CanTransfer(db StateDB, addr types.Address, amount *uint256.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer moves value from sender to recipient.
func Transfer(db StateDB, sender, recipient types.Address, amount *uint256.Int) {
	db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
	db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
}
