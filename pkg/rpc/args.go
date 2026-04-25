package rpc

import (
	"math/big"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/types"
)

// TransactionArgs represents arguments to construct a transaction.
// It is used for eth_call and eth_estimateGas requests.
type TransactionArgs struct {
	From                 *types.Address    `json:"from"`
	To                   *types.Address    `json:"to"`
	Gas                  *uint64           `json:"gas"`
	GasPrice             *big.Int          `json:"gasPrice"`
	MaxFeePerGas         *big.Int          `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *big.Int          `json:"maxPriorityFeePerGas"`
	Value                *big.Int          `json:"value"`
	Data                 *[]byte           `json:"data"`
	Input                *[]byte           `json:"input"`
	Nonce                *uint64           `json:"nonce"`
	AccessList           *types.AccessList `json:"accessList"`
	ChainID              *big.Int          `json:"chainId"`
}

// data returns the input data for the transaction. The "input" field takes
// precedence over "data" for backwards compatibility.
func (args *TransactionArgs) data() []byte {
	if args.Input != nil {
		return *args.Input
	}
	if args.Data != nil {
		return *args.Data
	}
	return nil
}

// toMessage converts TransactionArgs into a block.Message suitable for EVM
// execution. Fields that are nil are set to sensible defaults.
func (args *TransactionArgs) toMessage(globalGasCap uint64, baseFee *big.Int) *block.Message {
	msg := &block.Message{
		SkipNonceChecks:  true,
		SkipFromEOACheck: true,
		Data:             args.data(),
	}

	// From.
	if args.From != nil {
		msg.From = *args.From
	}

	// To.
	msg.To = args.To

	// Gas.
	gas := globalGasCap
	if args.Gas != nil {
		gas = *args.Gas
	}
	if gas == 0 || gas > globalGasCap {
		gas = globalGasCap
	}
	msg.GasLimit = gas

	// Value.
	if args.Value != nil {
		val, _ := uint256.FromBig(args.Value)
		msg.Value = val
	} else {
		msg.Value = new(uint256.Int)
	}

	// Gas price fields.
	if args.GasPrice != nil {
		msg.GasPrice = new(big.Int).Set(args.GasPrice)
		msg.GasFeeCap = new(big.Int).Set(args.GasPrice)
		msg.GasTipCap = new(big.Int).Set(args.GasPrice)
	} else {
		msg.GasPrice = new(big.Int)
		msg.GasFeeCap = new(big.Int)
		msg.GasTipCap = new(big.Int)
	}

	if args.MaxFeePerGas != nil {
		msg.GasFeeCap = new(big.Int).Set(args.MaxFeePerGas)
	}
	if args.MaxPriorityFeePerGas != nil {
		msg.GasTipCap = new(big.Int).Set(args.MaxPriorityFeePerGas)
	}

	// Access list.
	if args.AccessList != nil {
		msg.AccessList = *args.AccessList
	}

	// Nonce is not set for eth_call (SkipNonceChecks is true).

	return msg
}

// setDefaults fills in default values for fields that were not provided.
func (args *TransactionArgs) setDefaults(gasLimit uint64) {
	if args.Gas == nil {
		g := gasLimit
		args.Gas = &g
	}
	if args.Value == nil {
		args.Value = new(big.Int)
	}
	if args.GasPrice == nil && args.MaxFeePerGas == nil {
		args.GasPrice = new(big.Int)
	}
}

// toTransaction converts TransactionArgs to a types.Transaction for
// gas estimation purposes. This creates an unsigned legacy transaction.
func (args *TransactionArgs) toTransaction() *types.Transaction {
	var to *types.Address
	if args.To != nil {
		addr := *args.To
		to = &addr
	}

	gas := uint64(0)
	if args.Gas != nil {
		gas = *args.Gas
	}

	gasPrice := new(big.Int)
	if args.GasPrice != nil {
		gasPrice = args.GasPrice
	}

	value := uint256.NewInt(0)
	if args.Value != nil {
		v, _ := uint256.FromBig(args.Value)
		if v != nil {
			value = v
		}
	}

	nonce := uint64(0)
	if args.Nonce != nil {
		nonce = *args.Nonce
	}

	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		To:       to,
		Value:    value,
		Data:     args.data(),
	})
}
