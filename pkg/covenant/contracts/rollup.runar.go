package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// RollupContract is the stateful UTXO chain covenant that guards the L2 state
// root on BSV. Each spend advances the state by providing a new state root,
// block number, public values blob, batch data, and proof data.
//
// The covenant verifies all bindings and enforces monotonic block number
// progression. The SP1 FRI verifier is not yet implemented — proof
// verification uses Baby Bear field arithmetic and SHA-256 Merkle checks
// as a placeholder that exercises the same primitives the full verifier
// will use.
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - StateRoot:   32-byte hash of current state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// Readonly properties (baked into locking script at compile time):
//   - VerifyingKeyHash: commitment hash (placeholder for SP1 VK)
//   - ChainId:          shard chain ID for cross-shard replay prevention
//   - GovernanceKey:    public key authorized for freeze/unfreeze
//
// Public values layout (272 bytes, matching SP1 guest output):
//
//	[0..32]    preStateRoot
//	[32..64]   postStateRoot
//	[64..96]   proofBlobHash      (hash256 of the proof blob)
//	[96..104]  gasUsed            (not verified by covenant)
//	[104..136] batchDataHash      (hash256, verified)
//	[136..144] chainId            (uint64, verified)
//	[144..176] withdrawalRoot     (covered by batchDataHash)
//	[176..272] remaining fields   (inbox roots, migration hash)
type RollupContract struct {
	runar.StatefulSmartContract
	StateRoot        runar.ByteString                    // mutable state
	BlockNumber      runar.Bigint                        // mutable state
	Frozen           runar.Bigint                        // mutable state: 0=active, 1=frozen
	VerifyingKeyHash runar.ByteString `runar:"readonly"` // SP1 VK hash placeholder
	ChainId          runar.Bigint     `runar:"readonly"` // shard chain ID
	GovernanceKey    runar.PubKey     `runar:"readonly"` // governance public key
}

// AdvanceState advances the covenant state with verified proof data.
// This is the core method — every L2 block produces a BSV transaction
// that calls this method with the new state root, a STARK proof, and
// the batch data.
//
// The proofBlob parameter carries ~165 KB of data (the STARK proof)
// and batchData carries ~20 KB (compressed transaction batch).
func (c *RollupContract) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	proofFieldA runar.Bigint,
	proofFieldB runar.Bigint,
	proofFieldC runar.Bigint,
	merkleLeaf runar.ByteString,
	merkleProof runar.ByteString,
	merkleIndex runar.Bigint,
) {
	// 0. Reject if shard is frozen by governance
	runar.Assert(c.Frozen == 0)

	// 1. Block number must be exactly previous + 1
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// 2. Simplified proof verification (placeholder for SP1Verify).
	//    Exercises Baby Bear field arithmetic — the critical primitive for
	//    FRI verification on BSV.
	runar.Assert(runar.BbFieldMul(proofFieldA, proofFieldB) == proofFieldC)

	// 3. Depth-20 Merkle proof verification (matching real FRI query depth).
	//    Each FRI query verifies a polynomial evaluation against a committed
	//    Merkle root at this depth.
	computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 20)
	runar.Assert(computedRoot == c.VerifyingKeyHash)

	// 4. Proof blob integrity: hash the full ~165 KB proof and verify it
	//    matches the proofBlobHash in public values (offset 64).
	//    Forces BSV to push and hash the entire proof on-chain.
	pvProofHash := runar.Substr(publicValues, 64, 32)
	runar.Assert(pvProofHash == runar.Hash256(proofBlob))

	// 5. Extract and verify public values at spec offsets.
	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)

	// 5a. Chain ID must match this shard (cross-shard replay prevention)
	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))

	// 5b. Pre-state root from proof must match current covenant state
	runar.Assert(pvPreStateRoot == c.StateRoot)

	// 6. Post-state root from proof must match the claimed new state
	runar.Assert(pvPostStateRoot == newStateRoot)

	// 7. Batch data hash binding (Layer 1: STARK → batch data).
	//    hash256 = double-SHA256, matching BSV's native OP_HASH256.
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))

	// 8. Update state — compiler auto-enforces output carries new state
	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0
}

// Freeze allows the governance key holder to freeze the shard, blocking
// all advanceState calls until unfrozen.
func (c *RollupContract) Freeze(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	runar.Assert(c.Frozen == 0)
	c.Frozen = 1
}

// Unfreeze allows the governance key holder to unfreeze the shard,
// re-enabling advanceState calls.
func (c *RollupContract) Unfreeze(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	runar.Assert(c.Frozen == 1)
	c.Frozen = 0
}

// Upgrade allows the governance key holder to replace the covenant script
// while preserving the UTXO value. The shard must be frozen first. This is
// a terminal spend — no state continuation output. The caller provides the
// new covenant script; the SDK/on-chain layer enforces the output carries it.
func (c *RollupContract) Upgrade(sig runar.Sig, newCovenantScript runar.ByteString) {
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	runar.Assert(c.Frozen == 1)
	// Terminal method: no state mutation, no continuation output.
	// The on-chain transaction's output 0 uses newCovenantScript.
	// Output enforcement is handled by the SDK (TerminalOutputs).
	_ = newCovenantScript
}
