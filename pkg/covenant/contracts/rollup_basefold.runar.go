package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// BasefoldRollupContract is the Basefold-only variant of the stateful rollup
// covenant. It verifies SP1 proofs natively on-chain using KoalaBear field
// arithmetic plus a Poseidon2 Merkle inclusion proof — no trusted setup.
//
// This file was split out of the original dual-mode rollup.runar.go contract
// so each compiled script carries only the verification logic it actually
// needs. The dual-mode contract compiled to ~5.8 MB and tripped the Rúnar
// `Invalid OP_SPLIT range` bug on regtest; splitting by mode reduces the
// readonly / argument surface dramatically.
//
// Mode 2 (generic Groth16) lives in rollup_groth16.runar.go and Mode 3
// (witness-assisted Groth16) in rollup_groth16_wa.runar.go. Do NOT add
// other verification modes to this file — keep each variant in its own
// source so the compiled locking script carries only its own logic.
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - StateRoot:   32-byte hash of current L2 state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// Readonly properties baked into the locking script at compile time:
//   - SP1VerifyingKeyHash: sha256(SP1 verifying key); in Basefold mode this
//     also doubles as the root of the Poseidon2 Merkle tree that the on-chain
//     leaf/proof/index must reconstruct to.
//   - ChainId:             shard chain ID for cross-shard replay prevention
//   - Governance*:         freeze / unfreeze / upgrade authorization
type BasefoldRollupContract struct {
	runar.StatefulSmartContract

	// ---- Mutable state ----
	StateRoot   runar.ByteString // 32-byte hash of current state
	BlockNumber runar.Bigint     // monotonically increasing block counter
	Frozen      runar.Bigint     // 0=active, 1=frozen by governance

	// ---- Readonly: shared with the Groth16 variant ----
	SP1VerifyingKeyHash runar.ByteString `runar:"readonly"` // sha256(SP1 vkey) / Merkle root
	ChainId             runar.Bigint     `runar:"readonly"` // shard chain ID

	// ---- Readonly: governance ----
	GovernanceMode      runar.Bigint `runar:"readonly"` // 0=none, 1=single_key, 2=multisig
	GovernanceThreshold runar.Bigint `runar:"readonly"` // M for M-of-N (1 for single_key, 0 for none)
	GovernanceKey       runar.PubKey `runar:"readonly"` // single-key governance key (or key 1 in multisig)
	GovernanceKey2      runar.PubKey `runar:"readonly"` // multisig key 2 (zeros if unused)
	GovernanceKey3      runar.PubKey `runar:"readonly"` // multisig key 3 (zeros if unused)
}

// AdvanceState advances the covenant state with a Basefold-verified proof.
// Invariants enforced (in order):
//  1. Shard must not be frozen.
//  2. New block number must be exactly previous + 1.
//  3. Basefold proof: KoalaBear field product check + Poseidon2 Merkle
//     inclusion of the provided leaf at the given index must reconstruct to
//     the SP1VerifyingKeyHash stored in the readonly property.
//  4. Public values offsets 0/32/104/136 must match StateRoot / newStateRoot
//     / hash256(batchData) / ChainId (little-endian 8 bytes) respectively.
//
// Note: the tautological `publicValues[64..96] == hash256(proofBlob)` check
// present before 2026-04-18 was removed (finding F04). That slot holds
// receiptsHash per spec 12 and is intentionally unverified by the covenant
// (nodes check it during batch replay); the prior assertion was either
// unsatisfiable by an honest prover (if publicValues came straight from
// the guest) or tautological (if the prover controlled publicValues).
func (c *BasefoldRollupContract) AdvanceState(
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
	// 0. Reject if shard is frozen by governance.
	runar.Assert(c.Frozen == 0)

	// 1. Block number must be exactly previous + 1.
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// 2. Basefold proof: KoalaBear field check + Poseidon2 Merkle verification.
	runar.Assert(runar.KbFieldMul(proofFieldA, proofFieldB) == proofFieldC)
	computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 20)
	runar.Assert(computedRoot == c.SP1VerifyingKeyHash)

	// 3. Extract and verify public values at spec offsets.
	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvPostStateRoot == newStateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))

	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = proofBlob
}

// ---------------------------------------------------------------------------
// Governance methods — split per mode to satisfy Rúnar's affine value checker
// ---------------------------------------------------------------------------
//
// The Rúnar affine type checker tracks Sig consumption with a method-global
// map: once a Sig identifier is passed to CheckSig / CheckMultiSig anywhere
// in a method body, it cannot be passed again — even on a mutually-exclusive
// branch of an if/else chain. To preserve all three governance modes (none,
// single_key, multisig 2-of-3 and 3-of-3) without reusing sig parameters
// across branches, each governance action is split into a separate method
// per mode + threshold. Spend-time selection happens by which method index
// the unlocking script invokes.
//
// Mode 0 (none) has no governance methods at all — the absence of any
// FreezeSingleKey / FreezeMultiSig* method makes governance unreachable, and
// a "none" shard cannot be frozen, unfrozen, or upgraded by anyone.
//
// The matrix is:
//   - FreezeSingleKey    / UnfreezeSingleKey    / UpgradeSingleKey   (mode 1)
//   - FreezeMultiSig2    / UnfreezeMultiSig2    / UpgradeMultiSig2   (mode 2, M=2)
//   - FreezeMultiSig3    / UnfreezeMultiSig3    / UpgradeMultiSig3   (mode 2, M=3)
//
// Each method asserts the contract is in the matching governance mode and
// (for multisig variants) the matching threshold, so a mode-1 shard cannot
// be frozen by a mode-2 method and vice versa.

// ---- Freeze ----

// FreezeSingleKey freezes the shard under single-key governance.
func (c *BasefoldRollupContract) FreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 1
}

// FreezeMultiSig2 freezes the shard under 2-of-3 multisig governance.
func (c *BasefoldRollupContract) FreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 2)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))
	c.Frozen = 1
}

// FreezeMultiSig3 freezes the shard under 3-of-3 multisig governance.
func (c *BasefoldRollupContract) FreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 3)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2, sig3},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))
	c.Frozen = 1
}

// ---- Unfreeze ----

// UnfreezeSingleKey unfreezes the shard under single-key governance.
func (c *BasefoldRollupContract) UnfreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 0
}

// UnfreezeMultiSig2 unfreezes the shard under 2-of-3 multisig governance.
func (c *BasefoldRollupContract) UnfreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 2)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))
	c.Frozen = 0
}

// UnfreezeMultiSig3 unfreezes the shard under 3-of-3 multisig governance.
func (c *BasefoldRollupContract) UnfreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 3)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2, sig3},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))
	c.Frozen = 0
}

// ---- Upgrade ----
//
// Upgrade replaces the covenant script. The shard must be frozen first. A
// valid Basefold proof for the next block must be provided and the new
// covenant script hash must appear in the public values migration slot
// ([240..272]).

// UpgradeSingleKey upgrades the covenant under single-key governance.
//
// proofBlob is accepted as a public parameter to preserve the unlock-script
// argument layout but is not consumed inside the script body — only the
// proof field elements and Merkle inclusion proof are checked, plus the
// public values bindings (including the migration hash slot).
func (c *BasefoldRollupContract) UpgradeSingleKey(
	sig runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	proofFieldA runar.Bigint,
	proofFieldB runar.Bigint,
	proofFieldC runar.Bigint,
	merkleLeaf runar.ByteString,
	merkleProof runar.ByteString,
	merkleIndex runar.Bigint,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	runar.Assert(runar.KbFieldMul(proofFieldA, proofFieldB) == proofFieldC)
	computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 20)
	runar.Assert(computedRoot == c.SP1VerifyingKeyHash)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvMigrationHash := runar.Substr(publicValues, 240, 32)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))
	runar.Assert(pvMigrationHash == runar.Hash256(newCovenantScript))

	c.StateRoot = pvPostStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
	_ = proofBlob
}

// UpgradeMultiSig2 upgrades the covenant under 2-of-3 multisig governance.
func (c *BasefoldRollupContract) UpgradeMultiSig2(
	sig1 runar.Sig,
	sig2 runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	proofFieldA runar.Bigint,
	proofFieldB runar.Bigint,
	proofFieldC runar.Bigint,
	merkleLeaf runar.ByteString,
	merkleProof runar.ByteString,
	merkleIndex runar.Bigint,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 2)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	runar.Assert(runar.KbFieldMul(proofFieldA, proofFieldB) == proofFieldC)
	computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 20)
	runar.Assert(computedRoot == c.SP1VerifyingKeyHash)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvMigrationHash := runar.Substr(publicValues, 240, 32)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))
	runar.Assert(pvMigrationHash == runar.Hash256(newCovenantScript))

	c.StateRoot = pvPostStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
	_ = proofBlob
}

// UpgradeMultiSig3 upgrades the covenant under 3-of-3 multisig governance.
func (c *BasefoldRollupContract) UpgradeMultiSig3(
	sig1 runar.Sig,
	sig2 runar.Sig,
	sig3 runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	proofFieldA runar.Bigint,
	proofFieldB runar.Bigint,
	proofFieldC runar.Bigint,
	merkleLeaf runar.ByteString,
	merkleProof runar.ByteString,
	merkleIndex runar.Bigint,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 3)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2, sig3},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	runar.Assert(runar.KbFieldMul(proofFieldA, proofFieldB) == proofFieldC)
	computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 20)
	runar.Assert(computedRoot == c.SP1VerifyingKeyHash)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvMigrationHash := runar.Substr(publicValues, 240, 32)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))
	runar.Assert(pvMigrationHash == runar.Hash256(newCovenantScript))

	c.StateRoot = pvPostStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
	_ = proofBlob
}
