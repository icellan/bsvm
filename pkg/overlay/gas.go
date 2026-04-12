package overlay

import (
	"fmt"
	"math/big"

	"github.com/icellan/bsvm/pkg/types"
)

// GasPriceOracle provides gas price suggestions and validates transaction
// gas prices against the configured minimum.
type GasPriceOracle struct {
	minGasPrice *big.Int
}

// NewGasPriceOracle creates a new gas price oracle with the given minimum
// gas price. If minGasPrice is nil, it defaults to 1 gwei.
func NewGasPriceOracle(minGasPrice *big.Int) *GasPriceOracle {
	if minGasPrice == nil {
		minGasPrice = big.NewInt(1_000_000_000) // 1 gwei
	}
	return &GasPriceOracle{
		minGasPrice: new(big.Int).Set(minGasPrice),
	}
}

// SuggestGasPrice returns the suggested gas price for new transactions.
// Currently returns the minimum gas price; a future implementation may
// consider recent block utilisation.
func (o *GasPriceOracle) SuggestGasPrice() *big.Int {
	return new(big.Int).Set(o.minGasPrice)
}

// ValidateGasPrice checks whether a transaction's effective gas price
// meets the node's minimum gas price requirement. Returns an error if
// the gas price is below the minimum.
func (o *GasPriceOracle) ValidateGasPrice(tx *types.Transaction) error {
	txGasPrice := tx.GasPrice()
	if txGasPrice == nil {
		return fmt.Errorf("transaction gas price is nil")
	}
	if txGasPrice.Cmp(o.minGasPrice) < 0 {
		return fmt.Errorf("transaction gas price %s below minimum %s", txGasPrice, o.minGasPrice)
	}
	return nil
}

// MinGasPrice returns the configured minimum gas price.
func (o *GasPriceOracle) MinGasPrice() *big.Int {
	return new(big.Int).Set(o.minGasPrice)
}
