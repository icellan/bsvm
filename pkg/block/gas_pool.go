package block

import "fmt"

// GasPool tracks the amount of gas available during execution of transactions
// in a block. It prevents the total gas consumption from exceeding the block
// gas limit.
type GasPool uint64

// AddGas adds the given amount of gas to the pool.
func (gp *GasPool) AddGas(amount uint64) *GasPool {
	*(*uint64)(gp) += amount
	return gp
}

// SubGas subtracts the given amount of gas from the pool. Returns an error
// if the pool does not have enough gas.
func (gp *GasPool) SubGas(amount uint64) error {
	if uint64(*gp) < amount {
		return fmt.Errorf("gas pool exhausted: have %d, want %d", uint64(*gp), amount)
	}
	*(*uint64)(gp) -= amount
	return nil
}

// Gas returns the current amount of gas in the pool.
func (gp *GasPool) Gas() uint64 {
	return uint64(*gp)
}

// String returns a human-readable representation of the gas pool.
func (gp *GasPool) String() string {
	return fmt.Sprintf("%d", uint64(*gp))
}

// SetGas sets the gas pool to the specified value.
func (gp *GasPool) SetGas(gas uint64) {
	*(*uint64)(gp) = gas
}
