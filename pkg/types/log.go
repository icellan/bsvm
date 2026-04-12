package types

// Log represents an EVM event log entry emitted during contract execution.
type Log struct {
	// Address is the contract address that generated the log.
	Address Address

	// Topics are the indexed log topics (up to 4).
	Topics []Hash

	// Data contains the non-indexed log data.
	Data []byte

	// BlockNumber is the block in which the transaction was included.
	BlockNumber uint64

	// TxHash is the hash of the transaction that produced this log.
	TxHash Hash

	// TxIndex is the index of the transaction in the block.
	TxIndex uint

	// BlockHash is the hash of the block containing this log.
	BlockHash Hash

	// Index is the position of this log in the block's log list.
	Index uint

	// Removed is true if this log was reverted due to a chain reorganisation.
	Removed bool
}
