// Copyright 2014 The go-ethereum Authors
// Adapted from go-ethereum core/state_processor.go for the BSVM project.

package block

import (
	"encoding/binary"
	"math/big"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// ChainContext provides block hash lookups needed by the EVM.
type ChainContext interface {
	// GetHeader returns the header for the given hash and number.
	GetHeader(types.Hash, uint64) *L2Header
}

// ApplyTransaction applies a single transaction to the state and returns
// a receipt. It creates an EVM, converts the transaction to a message,
// executes it, and builds the receipt with status, gas, logs, and bloom.
// bsvBlockHash is used for PREVRANDAO derivation; pass nil to fall back
// to the L2 parent hash.
func ApplyTransaction(
	config *vm.ChainConfig,
	bc ChainContext,
	coinbase *types.Address,
	gp *GasPool,
	statedb *state.StateDB,
	header *L2Header,
	tx *types.Transaction,
	usedGas *uint64,
	vmConfig vm.Config,
	bsvBlockHash *types.Hash,
) (*types.Receipt, error) {
	signer := types.LatestSignerForChainID(config.ChainID)
	msg, err := TransactionToMessage(tx, signer, header.BaseFee)
	if err != nil {
		return nil, err
	}

	// Create the EVM block context.
	blockCtx := newBlockContext(header, bc, coinbase, bsvBlockHash)

	// Create the EVM instance. ApplyMessage will set the TxContext.
	evmInst := vm.NewEVM(blockCtx, statedb, config, vmConfig)

	// Set the transaction context in the state for log attribution.
	statedb.SetTxContext(tx.Hash(), 0)

	// Apply the message.
	result, err := ApplyMessage(evmInst, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update cumulative gas used.
	*usedGas += result.UsedGas

	// Create the receipt.
	receipt := &types.Receipt{
		Type:              tx.Type(),
		CumulativeGasUsed: *usedGas,
		GasUsed:           result.UsedGas,
		TxHash:            tx.Hash(),
	}

	// Set status.
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}

	// Set contract address for contract creation transactions.
	if msg.To == nil {
		receipt.ContractAddress = types.Address(crypto.CreateAddress(msg.From, msg.Nonce))
	}

	// Set logs and bloom.
	receipt.Logs = statedb.GetLogs(tx.Hash(), header.Number.Uint64(), header.Hash())
	receipt.Bloom = types.CreateBloom([]*types.Receipt{receipt})
	receipt.BlockNumber = header.Number
	receipt.BlockHash = header.Hash()

	return receipt, nil
}

// newBlockContext creates a block context from an L2Header. If bsvBlockHash
// is non-nil it is used for PREVRANDAO derivation; otherwise the L2 parent
// hash is used as a fallback (useful in tests before BSV integration).
func newBlockContext(header *L2Header, chain ChainContext, coinbase *types.Address, bsvBlockHash *types.Hash) vm.BlockContext {
	beneficiary := header.Coinbase
	if coinbase != nil {
		beneficiary = *coinbase
	}

	baseFee := header.BaseFee
	if baseFee == nil {
		baseFee = new(big.Int)
	}

	// Derive a deterministic PREVRANDAO. Use the BSV block hash when
	// available; fall back to the L2 parent hash for test contexts.
	randomInput := header.ParentHash
	if bsvBlockHash != nil {
		randomInput = *bsvBlockHash
	}
	random := DeriveRandom(randomInput, header.Number.Uint64())

	return vm.BlockContext{
		CanTransfer: vm.CanTransfer,
		Transfer:    vm.Transfer,
		GetHash: func(n uint64) types.Hash {
			if chain == nil {
				return types.Hash{}
			}
			// BLOCKHASH only works for the 256 most recent blocks (EIP-2).
			currentBlockNum := header.Number.Uint64()
			if n >= currentBlockNum || currentBlockNum-n > 256 {
				return types.Hash{}
			}
			h := chain.GetHeader(types.Hash{}, n)
			if h != nil {
				return h.Hash()
			}
			return types.Hash{}
		},
		Coinbase:    beneficiary,
		GasLimit:    header.GasLimit,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        header.Timestamp,
		Difficulty:  big.NewInt(0),
		BaseFee:     new(big.Int).Set(baseFee),
		BlobBaseFee: big.NewInt(1),
		Random:      &random,
	}
}

// DeriveRandom computes a deterministic PREVRANDAO value from a BSV
// block hash and L2 block number: keccak256(bsvBlockHash || l2BlockNum).
// This is predictable by BSV observers and is NOT a secure source of
// randomness. Contracts requiring randomness should use an oracle.
func DeriveRandom(bsvBlockHash types.Hash, l2BlockNum uint64) types.Hash {
	data := make([]byte, 40) // 32 bytes hash + 8 bytes block number
	copy(data[:32], bsvBlockHash[:])
	binary.BigEndian.PutUint64(data[32:], l2BlockNum)
	return types.Hash(crypto.Keccak256Hash(data))
}

// stateDBFor type-asserts a vm.StateDB to the concrete *state.StateDB
// used by production code paths. The bridge withdrawal fast-path needs
// the concrete type because its rate-limit / storage-slot helpers
// (CheckWithdrawalRateLimit, RecordWithdrawal) operate on it directly
// rather than through the vm.StateDB interface. Returns (nil, false)
// for any other implementation (e.g. tracing wrappers used by external
// tooling) so the dispatch can revert cleanly instead of panicking.
func stateDBFor(s vm.StateDB) (*state.StateDB, bool) {
	concrete, ok := s.(*state.StateDB)
	return concrete, ok
}
