package bridge

import (
	"math"

	"github.com/icellan/bsvm/pkg/types"
)

// Config holds the configuration for the bridge between BSV L1 and the L2 EVM.
type Config struct {
	// MinDepositSatoshis is the minimum deposit amount in satoshis.
	// Deposits below this threshold are ignored.
	MinDepositSatoshis uint64

	// MinWithdrawalSatoshis is the minimum withdrawal amount in satoshis.
	MinWithdrawalSatoshis uint64

	// BSVConfirmations is the number of BSV block confirmations required
	// before a deposit is eligible for inclusion in an L2 block.
	BSVConfirmations int

	// BridgeContractAddress is the L2 bridge predeploy address.
	BridgeContractAddress types.Address
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		MinDepositSatoshis:    10000, // 0.0001 BSV
		MinWithdrawalSatoshis: 10000, // 0.0001 BSV
		BSVConfirmations:      6,
		BridgeContractAddress: types.BridgeContractAddress,
	}
}

// WithdrawalConfig holds the configuration for withdrawal processing.
type WithdrawalConfig struct {
	// MinWithdrawal is the minimum withdrawal amount in satoshis.
	MinWithdrawal uint64

	// Tiers defines confirmation requirements by withdrawal amount.
	Tiers []WithdrawalTier
}

// WithdrawalTier defines the BSV confirmation requirement for
// withdrawals up to a given amount.
type WithdrawalTier struct {
	// MaxAmount is the maximum withdrawal amount in satoshis for
	// this tier. Use math.MaxUint64 for the final tier.
	MaxAmount uint64

	// Confirmations is the number of BSV block confirmations
	// required before the withdrawal can be spent.
	Confirmations int
}

// DefaultWithdrawalConfig returns a WithdrawalConfig with the default
// tiered confirmation requirements from spec 07.
func DefaultWithdrawalConfig() WithdrawalConfig {
	return WithdrawalConfig{
		MinWithdrawal: 10000, // 0.0001 BSV
		Tiers: []WithdrawalTier{
			{MaxAmount: 1_000_000_000, Confirmations: 6},    // <= 10 BSV
			{MaxAmount: 10_000_000_000, Confirmations: 20},  // <= 100 BSV
			{MaxAmount: math.MaxUint64, Confirmations: 100}, // > 100 BSV
		},
	}
}
