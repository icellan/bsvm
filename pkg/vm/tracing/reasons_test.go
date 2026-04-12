package tracing

import "testing"

func TestBalanceChangeReasonValues(t *testing.T) {
	tests := []struct {
		name     string
		reason   BalanceChangeReason
		expected byte
	}{
		{"Unspecified", BalanceChangeUnspecified, 0},
		{"RewardMineUncle", BalanceIncreaseRewardMineUncle, 1},
		{"RewardMineBlock", BalanceIncreaseRewardMineBlock, 2},
		{"Withdrawal", BalanceIncreaseWithdrawal, 3},
		{"GenesisBalance", BalanceIncreaseGenesisBalance, 4},
		{"RewardTransactionFee", BalanceIncreaseRewardTransactionFee, 5},
		{"GasBuy", BalanceDecreaseGasBuy, 6},
		{"GasReturn", BalanceIncreaseGasReturn, 7},
		{"DaoContract", BalanceIncreaseDaoContract, 8},
		{"DaoAccount", BalanceDecreaseDaoAccount, 9},
		{"Transfer", BalanceChangeTransfer, 10},
		{"TouchAccount", BalanceChangeTouchAccount, 11},
		{"Selfdestruct", BalanceIncreaseSelfdestruct, 12},
		{"DecreaseSelfdestruct", BalanceDecreaseSelfdestruct, 13},
		{"SelfdestructBurn", BalanceDecreaseSelfdestructBurn, 14},
		{"Revert", BalanceChangeRevert, 15},
		{"DecreaseTxFee", BalanceDecreaseTxFee, 16},
		{"IncreaseTxFee", BalanceIncreaseTxFee, 17},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if byte(tt.reason) != tt.expected {
				t.Errorf("BalanceChangeReason %s: got %d, want %d",
					tt.name, byte(tt.reason), tt.expected)
			}
		})
	}
}

func TestBalanceChangeReasonAliases(t *testing.T) {
	// BalanceIncreaseDeposit is an alias for BalanceIncreaseWithdrawal.
	if BalanceIncreaseDeposit != BalanceIncreaseWithdrawal {
		t.Errorf("BalanceIncreaseDeposit should equal BalanceIncreaseWithdrawal")
	}

	// BalanceDecreaseWithdrawal is an alias for BalanceDecreaseSelfdestruct.
	if BalanceDecreaseWithdrawal != BalanceDecreaseSelfdestruct {
		t.Errorf("BalanceDecreaseWithdrawal should equal BalanceDecreaseSelfdestruct")
	}
}

func TestGasChangeReasonValues(t *testing.T) {
	tests := []struct {
		name     string
		reason   GasChangeReason
		expected byte
	}{
		{"Unspecified", GasChangeUnspecified, 0},
		{"TxInitialBalance", GasChangeTxInitialBalance, 1},
		{"TxIntrinsicGas", GasChangeTxIntrinsicGas, 2},
		{"TxRefunds", GasChangeTxRefunds, 3},
		{"TxLeftOverReturned", GasChangeTxLeftOverReturned, 4},
		{"CallInitialBalance", GasChangeCallInitialBalance, 5},
		{"CallLeftOverReturned", GasChangeCallLeftOverReturned, 6},
		{"CallLeftOverRefunded", GasChangeCallLeftOverRefunded, 7},
		{"CallContractCreation", GasChangeCallContractCreation, 8},
		{"CallContractCreation2", GasChangeCallContractCreation2, 9},
		{"CallCodeStorage", GasChangeCallCodeStorage, 10},
		{"CallOpCode", GasChangeCallOpCode, 11},
		{"CallPrecompiledContract", GasChangeCallPrecompiledContract, 12},
		{"CallStorageColdAccess", GasChangeCallStorageColdAccess, 13},
		{"CallFailedExecution", GasChangeCallFailedExecution, 14},
		{"WitnessContractInit", GasChangeWitnessContractInit, 15},
		{"WitnessContractCreation", GasChangeWitnessContractCreation, 16},
		{"WitnessCodeChunk", GasChangeWitnessCodeChunk, 17},
		{"WitnessContractCollisionCheck", GasChangeWitnessContractCollisionCheck, 18},
		{"TxDataFloor", GasChangeTxDataFloor, 19},
		{"Ignored", GasChangeIgnored, 0xFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if byte(tt.reason) != tt.expected {
				t.Errorf("GasChangeReason %s: got %d, want %d",
					tt.name, byte(tt.reason), tt.expected)
			}
		})
	}
}

func TestNonceChangeReasonValues(t *testing.T) {
	tests := []struct {
		name     string
		reason   NonceChangeReason
		expected byte
	}{
		{"Unspecified", NonceChangeUnspecified, 0},
		{"Genesis", NonceChangeGenesis, 1},
		{"EoACall", NonceChangeEoACall, 2},
		{"ContractCreator", NonceChangeContractCreator, 3},
		{"NewContract", NonceChangeNewContract, 4},
		{"Authorization", NonceChangeAuthorization, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if byte(tt.reason) != tt.expected {
				t.Errorf("NonceChangeReason %s: got %d, want %d",
					tt.name, byte(tt.reason), tt.expected)
			}
		})
	}

	// NonceChangeTransaction is an alias for NonceChangeEoACall.
	if NonceChangeTransaction != NonceChangeEoACall {
		t.Errorf("NonceChangeTransaction should equal NonceChangeEoACall")
	}
}

func TestCodeChangeReasonValues(t *testing.T) {
	tests := []struct {
		name     string
		reason   CodeChangeReason
		expected byte
	}{
		{"Unspecified", CodeChangeUnspecified, 0},
		{"Creation", CodeChangeCreation, 1},
		{"Selfdestruct", CodeChangeSelfdestruct, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if byte(tt.reason) != tt.expected {
				t.Errorf("CodeChangeReason %s: got %d, want %d",
					tt.name, byte(tt.reason), tt.expected)
			}
		})
	}
}
