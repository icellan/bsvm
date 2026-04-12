package tracing

// BalanceChangeReason is the reason for a balance change in the StateDB.
type BalanceChangeReason byte

const (
	BalanceChangeUnspecified        BalanceChangeReason = 0
	BalanceIncreaseRewardMineUncle  BalanceChangeReason = 1
	BalanceIncreaseRewardMineBlock  BalanceChangeReason = 2
	BalanceIncreaseWithdrawal       BalanceChangeReason = 3
	BalanceIncreaseGenesisBalance   BalanceChangeReason = 4
	BalanceIncreaseRewardTransactionFee BalanceChangeReason = 5
	BalanceDecreaseGasBuy           BalanceChangeReason = 6
	BalanceIncreaseGasReturn        BalanceChangeReason = 7
	BalanceIncreaseDaoContract      BalanceChangeReason = 8
	BalanceDecreaseDaoAccount       BalanceChangeReason = 9
	BalanceChangeTransfer           BalanceChangeReason = 10
	BalanceChangeTouchAccount       BalanceChangeReason = 11
	BalanceIncreaseSelfdestruct     BalanceChangeReason = 12
	BalanceDecreaseSelfdestruct     BalanceChangeReason = 13
	BalanceDecreaseSelfdestructBurn BalanceChangeReason = 14
	BalanceChangeRevert             BalanceChangeReason = 15

	// Legacy aliases from old code
	BalanceIncreaseDeposit    = BalanceIncreaseWithdrawal // L2 deposits
	BalanceDecreaseWithdrawal = BalanceDecreaseSelfdestruct // alias
	BalanceDecreaseTxFee      BalanceChangeReason = 16
	BalanceIncreaseTxFee      BalanceChangeReason = 17
)

// GasChangeReason describes the reason for a gas change.
type GasChangeReason byte

const (
	GasChangeUnspecified              GasChangeReason = 0
	GasChangeTxInitialBalance         GasChangeReason = 1
	GasChangeTxIntrinsicGas           GasChangeReason = 2
	GasChangeTxRefunds                GasChangeReason = 3
	GasChangeTxLeftOverReturned       GasChangeReason = 4
	GasChangeCallInitialBalance       GasChangeReason = 5
	GasChangeCallLeftOverReturned     GasChangeReason = 6
	GasChangeCallLeftOverRefunded     GasChangeReason = 7
	GasChangeCallContractCreation     GasChangeReason = 8
	GasChangeCallContractCreation2    GasChangeReason = 9
	GasChangeCallCodeStorage          GasChangeReason = 10
	GasChangeCallOpCode               GasChangeReason = 11
	GasChangeCallPrecompiledContract  GasChangeReason = 12
	GasChangeCallStorageColdAccess    GasChangeReason = 13
	GasChangeCallFailedExecution      GasChangeReason = 14
	GasChangeWitnessContractInit      GasChangeReason = 15
	GasChangeWitnessContractCreation  GasChangeReason = 16
	GasChangeWitnessCodeChunk         GasChangeReason = 17
	GasChangeWitnessContractCollisionCheck GasChangeReason = 18
	GasChangeTxDataFloor              GasChangeReason = 19
	GasChangeIgnored                  GasChangeReason = 0xFF
)

// NonceChangeReason is the reason for a nonce change.
type NonceChangeReason byte

const (
	NonceChangeUnspecified    NonceChangeReason = 0
	NonceChangeGenesis        NonceChangeReason = 1
	NonceChangeEoACall        NonceChangeReason = 2
	NonceChangeContractCreator NonceChangeReason = 3
	NonceChangeNewContract    NonceChangeReason = 4
	NonceChangeAuthorization  NonceChangeReason = 5
	// Legacy aliases
	NonceChangeTransaction = NonceChangeEoACall
)

// CodeChangeReason is the reason for a code change.
type CodeChangeReason byte

const (
	CodeChangeUnspecified  CodeChangeReason = 0
	CodeChangeCreation     CodeChangeReason = 1
	CodeChangeSelfdestruct CodeChangeReason = 2
)
