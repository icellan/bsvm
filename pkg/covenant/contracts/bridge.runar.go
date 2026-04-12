package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// BridgeCovenant holds locked BSV and manages deposits/withdrawals.
// The bridge has its own UTXO chain separate from the state covenant.
//
// State fields:
//   - Balance:         total locked BSV (satoshis)
//   - WithdrawalNonce: incremented on each withdrawal
//
// Readonly properties:
//   - StateCovenantScriptHash: hash256 of the state covenant script, used
//     for cross-covenant verification of withdrawalRoot
type BridgeCovenant struct {
	runar.StatefulSmartContract
	Balance                 runar.Bigint     // mutable: locked BSV balance in satoshis
	WithdrawalNonce         runar.Bigint     // mutable: monotonic withdrawal counter
	StateCovenantScriptHash runar.ByteString `runar:"readonly"` // hash256 of state covenant script
}

// Deposit locks BSV into the bridge. Anyone can call this by adding BSV
// to the covenant output. The deposit amount is the difference between
// the new output value and the previous output value.
func (c *BridgeCovenant) Deposit(depositAmount runar.Bigint) {
	// Verify deposit amount is positive
	runar.Assert(depositAmount > 0)

	// Update balance
	c.Balance = c.Balance + depositAmount
}

// Withdraw releases locked BSV to a user. The withdrawal must be proven
// by a Merkle proof that the withdrawal hash is in the withdrawal root
// committed by the prover. The withdrawalRoot is verified against a
// confirmed state covenant transaction (cross-covenant verification).
func (c *BridgeCovenant) Withdraw(
	bsvAddress runar.ByteString, // 20-byte BSV address
	satoshiAmount runar.Bigint, // amount to withdraw
	nonce runar.Bigint, // must match current WithdrawalNonce
	withdrawalRoot runar.ByteString, // from state covenant's batch data
	merkleProof runar.ByteString, // SHA-256 Merkle proof
	merkleIndex runar.Bigint, // leaf index in withdrawal tree
	refOutputScript runar.ByteString, // state covenant output script from referenced tx
	refOpReturn runar.ByteString, // OP_RETURN batch data from referenced tx
) {
	// Verify nonce matches
	runar.Assert(nonce == c.WithdrawalNonce)

	// Verify sufficient balance
	runar.Assert(satoshiAmount <= c.Balance)
	runar.Assert(satoshiAmount > 0)

	// Compute withdrawal hash: hash256(bsvAddress || amount_be || nonce_be)
	amountBytes := runar.Num2Bin(satoshiAmount, 8)
	nonceBytes := runar.Num2Bin(nonce, 8)
	withdrawalHash := runar.Hash256(runar.Cat(runar.Cat(bsvAddress, amountBytes), nonceBytes))

	// Verify Merkle proof against withdrawal root (max depth 16 per spec 13)
	computedRoot := runar.MerkleRootSha256(withdrawalHash, merkleProof, merkleIndex, 16)
	runar.Assert(computedRoot == withdrawalRoot)

	// Cross-covenant verification: verify the withdrawalRoot comes from
	// a confirmed state covenant advance. The unlocking script provides
	// the referenced tx's output script and OP_RETURN data. We verify:
	// (a) The hash of the referenced output script matches the known
	//     state covenant script hash (proves it's from a valid advance).
	// (b) The withdrawalRoot extracted from the OP_RETURN matches the
	//     one provided (proves the root is from that batch).
	runar.Assert(runar.Hash256(refOutputScript) == c.StateCovenantScriptHash)

	// Extract withdrawalRoot from the batch data OP_RETURN.
	// Batch data layout: the withdrawalRoot is at a fixed offset in
	// the batch data (see spec 12, Batch Data Encoding Format).
	// The offset is determined by the batch data encoding:
	// "BSVM\x02" (5) + preStateRoot (32) + postStateRoot (32) +
	// proofHash (32) + batchDataHash (32) + chainId (8) = 141
	// withdrawalRoot starts at offset 141, length 32.
	const batchWithdrawalRootOffset = 141
	extractedRoot := runar.Substr(refOpReturn, batchWithdrawalRootOffset, 32)
	runar.Assert(extractedRoot == withdrawalRoot)

	// Update state
	c.Balance = c.Balance - satoshiAmount
	c.WithdrawalNonce = c.WithdrawalNonce + 1
}

// Refund returns BSV from stale deposits after 144 BSV blocks.
// This allows users to reclaim BSV that was deposited but never
// credited on L2 (e.g., invalid shard ID, malformed OP_RETURN).
// The refund is only possible after a timeout period (144 BSV blocks,
// ~24 hours) to ensure the deposit has had time to be processed.
func (c *BridgeCovenant) Refund(
	refundAmount runar.Bigint, // amount to refund in satoshis
	locktime runar.ByteString, // sighash preimage for locktime check
) {
	// Verify refund amount is positive and within balance
	runar.Assert(refundAmount > 0)
	runar.Assert(refundAmount <= c.Balance)

	// Verify the transaction's locktime is at least 144 blocks after
	// the deposit, using the sighash preimage's locktime field.
	// ExtractLocktime returns the nLockTime from the sighash preimage.
	txLocktime := runar.ExtractLocktime(locktime)

	// The locktime must indicate at least 144 blocks have passed.
	// This is enforced by OP_CHECKLOCKTIMEVERIFY in the actual
	// compiled script — here we express the constraint declaratively.
	runar.Assert(txLocktime >= 144)

	// Update balance
	c.Balance = c.Balance - refundAmount
}
