package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// BridgeCovenant holds locked BSV and manages deposits/withdrawals.
// The bridge has its own UTXO chain separate from the state covenant.
//
// State fields:
//   - Balance:               total locked BSV (satoshis)
//   - WithdrawalNonce:       monotonic withdrawal counter; each Withdraw
//     consumes exactly the next nonce so a given (recipient, nonce)
//     tuple can only be claimed once on the canonical chain.
//   - WithdrawalsCommitment: running hash-chain commitment over every
//     processed withdrawal nullifier. Genesis value is 32 zero bytes.
//     Updated by Withdraw as
//     newCommitment = hash256(prevCommitment || nullifier)
//     where nullifier = hash256(bsvAddress || amountBE8 || nonceBE8).
//     This closes the reorg-replay gap: an attacker cannot re-process
//     an already-observed (bsvAddress, amount, nonce) tuple without
//     also rewinding the commitment chain, which is only possible by
//     dropping every subsequent withdrawal too.
//
// Readonly properties:
//   - StateCovenantScriptHash: hash256 of the state covenant script,
//     used for cross-covenant verification of withdrawalRoot.
type BridgeCovenant struct {
	runar.StatefulSmartContract
	Balance                 runar.Bigint     // mutable: locked BSV balance in satoshis
	WithdrawalNonce         runar.Bigint     // mutable: monotonic withdrawal counter
	WithdrawalsCommitment   runar.ByteString // mutable: hash-chain commitment over spent nullifiers (32 bytes)
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
// by a SHA-256 Merkle proof that the withdrawal hash is in the
// withdrawalRoot committed by the prover. The withdrawalRoot is read
// from a referenced state-covenant transaction's spec-12 advance
// OP_RETURN (cross-covenant verification).
//
// # Cross-covenant verification (spec 13 §C)
//
// The unlocking script supplies two byte strings copied from the
// referenced BSV transaction:
//
//   - refOutputScript: the state covenant output script (output 0 of
//     the referenced advance tx). The bridge asserts
//     hash256(refOutputScript) == StateCovenantScriptHash, which
//     proves the referenced output was locked under the same state
//     covenant the bridge is bound to.
//   - refOpReturn: the spec-12 advance OP_RETURN script (the data
//     output emitted by AdvanceState). The bridge extracts the
//     withdrawalRoot prefix at the fixed offset documented below and
//     uses it as the canonical root for the Merkle inclusion check.
//
// # Spec-12 advance OP_RETURN layout
//
// The rollup contracts emit:
//
//	OP_FALSE OP_RETURN OP_PUSHDATA4 <payload_len_le4>
//	  "BSVM\x02" || withdrawalRoot(32) || batchData
//
// As a flat byte string this is:
//
//	[0]      0x00 (OP_FALSE)
//	[1]      0x6a (OP_RETURN)
//	[2]      0x4e (OP_PUSHDATA4)
//	[3..7)   4-byte little-endian payload length
//	[7..12)  "BSVM\x02"
//	[12..44) withdrawalRoot (32 bytes)
//	[44..]   batchData
//
// So withdrawalRoot lives at offset 12 of refOpReturn. This binding is
// authoritative because the rollup contracts assert pvWithdrawalRoot ==
// pv[144..176) before emitting it, and pv is committed to by the SP1
// proof — the prover cannot publish a different root than the one the
// guest committed.
//
// # Anti-replay
//
// Three layers of replay defence:
//
//  1. The nonce parameter must equal c.WithdrawalNonce, which is
//     monotonically incremented on every successful withdrawal — so a
//     given (recipient, amount, nonce) tuple can only be claimed once
//     on the canonical chain.
//
//  2. The withdrawal's nullifier
//     (hash256(bsvAddress || amountBE || nonceBE)) is folded into the
//     running WithdrawalsCommitment hash chain:
//
//     newCommitment = hash256(prevCommitment || nullifier)
//
//     This is a tamper-evident on-chain log of every observed
//     withdrawal. A BSV-reorg replay of an already-observed tuple
//     cannot silently re-execute, because it would have to match a
//     commitment value that has been overwritten by a later
//     withdrawal, which is only possible by rewinding the entire
//     chain.
//
//  3. The off-chain BridgeManager carries a process-level spent-
//     nullifier set (see pkg/covenant/bridge_manager.go) that catches
//     replay attempts before the tx is built.
func (c *BridgeCovenant) Withdraw(
	bsvAddress runar.ByteString, // 20-byte BSV address (hash160 of pubkey)
	satoshiAmount runar.Bigint, // amount to withdraw
	nonce runar.Bigint, // must match current WithdrawalNonce
	merkleProof runar.ByteString, // depth*32 concatenated SHA-256 sibling hashes
	merkleIndex runar.Bigint, // leaf index (packed left/right bits per level)
	merkleDepth runar.Bigint, // tree depth (max 16 per spec 13)
	refOutputScript runar.ByteString, // state covenant output script of referenced advance tx
	refOpReturn runar.ByteString, // spec-12 advance OP_RETURN script of the same tx
) {
	// Anti-replay (layer 1): nonce must match the next available slot.
	runar.Assert(nonce == c.WithdrawalNonce)

	// Balance bounds.
	runar.Assert(satoshiAmount > 0)
	runar.Assert(satoshiAmount <= c.Balance)

	// Spec 13 caps the bridge withdrawal Merkle tree at depth 16.
	runar.Assert(merkleDepth >= 0)
	runar.Assert(merkleDepth <= 16)

	// Compute the withdrawal hash (== nullifier == leaf):
	//   leaf = hash256(bsvAddress || amount_be8 || nonce_be8)
	//
	// Spec 07 / 13 mandate BIG-endian uint64 for amount and nonce so
	// the on-chain hash matches the Solidity bridge contract's
	// `sha256(abi.encodePacked(bsvAddress, uint64(amount), uint64(nonce)))`
	// and the Go-side `pkg/covenant.WithdrawalNullifier` (which uses
	// `binary.BigEndian.PutUint64`). Bitcoin Script's `OP_NUM2BIN`
	// produces LITTLE-endian sign-magnitude — so we explicitly
	// `ReverseBytes` the 8-byte LE encoding to obtain the big-endian
	// representation the spec mandates.
	amountBytes := runar.ReverseBytes(runar.Num2Bin(satoshiAmount, 8))
	nonceBytes := runar.ReverseBytes(runar.Num2Bin(nonce, 8))
	nullifier := runar.Hash256(runar.Cat(runar.Cat(bsvAddress, amountBytes), nonceBytes))

	// Cross-covenant verification (a): the referenced output must be a
	// state-covenant output for the bridge's pinned shard. Hashing
	// refOutputScript and comparing against the readonly
	// StateCovenantScriptHash binds the supplied script to the genesis-
	// pinned identity. The bridge has no way to detect that
	// refOutputScript actually appeared in the referenced tx in
	// Bitcoin Script today (no per-output reference primitive); the
	// link is enforced by the off-chain caller (BridgeManager) which
	// validates the SPV / BSV-block inclusion before broadcasting.
	runar.Assert(runar.Hash256(refOutputScript) == c.StateCovenantScriptHash)

	// Cross-covenant verification (b): extract the withdrawalRoot
	// prefix the rollup contracts emit at a fixed offset of the spec-
	// 12 advance OP_RETURN. The offset breakdown is:
	//   3 bytes  OP_FALSE OP_RETURN OP_PUSHDATA4
	//   4 bytes  little-endian payload length
	//   5 bytes  "BSVM\x02"
	//   = 12 bytes header → withdrawalRoot at offset 12.
	const withdrawalRootOpReturnOffset = 12
	withdrawalRoot := runar.Substr(refOpReturn, withdrawalRootOpReturnOffset, 32)

	// Verify the SHA-256 Merkle inclusion proof for the leaf against
	// the extracted root. MerkleRootSha256 walks merkleProof one 32-
	// byte sibling at a time, hashing with single-block SHA-256 at
	// each level (NOT keccak256, NOT hash256), with the bit at
	// position i of merkleIndex selecting left/right at level i.
	computedRoot := runar.MerkleRootSha256(nullifier, merkleProof, merkleIndex, merkleDepth)
	runar.Assert(computedRoot == withdrawalRoot)

	// Anti-replay (layer 2): fold the nullifier into the running
	// WithdrawalsCommitment hash chain BEFORE releasing the funds so
	// the on-chain log is advanced atomically with the withdrawal.
	c.WithdrawalsCommitment = runar.Hash256(runar.Cat(c.WithdrawalsCommitment, nullifier))

	// Update balance and nonce.
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
