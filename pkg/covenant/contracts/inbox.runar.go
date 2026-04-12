package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// InboxContract is a stateful UTXO chain covenant that allows anyone to submit
// EVM transactions for forced inclusion. The prover reads from the inbox queue
// and is required to include pending inbox transactions within a bounded number
// of covenant advances (default: 10).
//
// State fields:
//   - TxQueueHash: hash chain root of pending transactions
//   - TxCount:     number of pending transactions in the queue
//
// The inbox uses a hash chain (not a Merkle tree) for simplicity:
//
//	newRoot = hash256(oldRoot || txHash)
type InboxContract struct {
	runar.StatefulSmartContract
	TxQueueHash runar.ByteString // mutable: hash chain root
	TxCount     runar.Bigint     // mutable: number of queued txs
}

// Submit appends a transaction to the inbox queue. Anyone can call this.
// The txRLP is the RLP-encoded EVM transaction.
func (c *InboxContract) Submit(txRLP runar.ByteString) {
	// Compute hash of the submitted transaction.
	txHash := runar.Hash256(txRLP)

	// Extend the hash chain: newRoot = hash256(oldRoot || txHash).
	c.TxQueueHash = runar.Hash256(runar.Cat(c.TxQueueHash, txHash))
	c.TxCount = c.TxCount + 1
}

// NOTE: There is no Drain method on InboxContract. Per spec 10, inbox
// drain is handled through the state covenant's STARK public values
// (inboxRootBefore / inboxRootAfter), not as a separate inbox covenant
// method. The SP1 guest verifies the inbox hash chain and commits the
// before/after roots as public outputs. The state covenant reads these
// values and enforces forced inclusion rules.
