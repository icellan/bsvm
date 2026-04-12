package bridge

import (
	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/types"
)

// Deposit represents a BSV deposit detected on L1 that should be
// credited on L2.
type Deposit struct {
	// BSVTxID is the BSV transaction ID of the deposit.
	BSVTxID types.Hash

	// Vout is the output index within the BSV transaction.
	Vout uint32

	// TxIndex is the index of the deposit transaction within its BSV
	// block. Used for deterministic sorting of deposits.
	TxIndex uint

	// BSVBlockHeight is the BSV block height at which the deposit
	// transaction was mined.
	BSVBlockHeight uint64

	// L2Address is the recipient address on L2, extracted from the
	// OP_RETURN output of the BSV transaction.
	L2Address types.Address

	// SatoshiAmount is the deposit amount in satoshis.
	SatoshiAmount uint64

	// L2WeiAmount is the deposit amount in L2 wei (satoshis * 10^10).
	L2WeiAmount *uint256.Int

	// Confirmed indicates whether the deposit has sufficient BSV
	// confirmations.
	Confirmed bool
}

// NewDeposit creates a new Deposit with the L2 wei amount computed
// from the satoshi amount.
func NewDeposit(bsvTxID types.Hash, blockHeight uint64, l2Addr types.Address, satoshis uint64) *Deposit {
	return &Deposit{
		BSVTxID:        bsvTxID,
		BSVBlockHeight: blockHeight,
		L2Address:      l2Addr,
		SatoshiAmount:  satoshis,
		L2WeiAmount:    types.SatoshisToWei(satoshis),
	}
}

// NewDepositWithVout creates a new Deposit with a specific output index
// and the L2 wei amount computed from the satoshi amount.
func NewDepositWithVout(bsvTxID types.Hash, vout uint32, blockHeight uint64, l2Addr types.Address, satoshis uint64) *Deposit {
	return &Deposit{
		BSVTxID:        bsvTxID,
		Vout:           vout,
		BSVBlockHeight: blockHeight,
		L2Address:      l2Addr,
		SatoshiAmount:  satoshis,
		L2WeiAmount:    types.SatoshisToWei(satoshis),
	}
}

// ToDepositTx converts a Deposit to a system DepositTransaction
// for inclusion in an L2 block.
func (d *Deposit) ToDepositTx() *types.DepositTransaction {
	return &types.DepositTransaction{
		SourceHash: types.DepositTxID(d.BSVTxID),
		From:       types.BridgeSystemAddress,
		To:         d.L2Address,
		Value:      new(uint256.Int).Set(d.L2WeiAmount),
		Gas:        0,
		IsSystemTx: true,
		Data:       nil,
	}
}

// BSVTransaction represents a BSV transaction as seen by the bridge monitor.
type BSVTransaction struct {
	// TxID is the BSV transaction hash.
	TxID types.Hash

	// Outputs are the transaction outputs.
	Outputs []BSVOutput

	// BlockHeight is the block height where this transaction was mined.
	BlockHeight uint64

	// TxIndex is the index of this transaction within its block.
	TxIndex uint
}

// BSVOutput represents a single output of a BSV transaction.
type BSVOutput struct {
	// Script is the output's locking script (scriptPubKey).
	Script []byte

	// Value is the output amount in satoshis.
	Value uint64
}
