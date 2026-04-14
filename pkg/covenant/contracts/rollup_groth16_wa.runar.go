package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// Groth16WARollupContract is the witness-assisted Groth16 ("Mode 3") variant
// of the stateful rollup covenant. It verifies SP1 proofs on-chain via a
// BN254 Groth16 pairing check whose verifier is inlined as a method-entry
// preamble by the Rúnar codegen. The SP1 Groth16 verifying key is baked in
// at compile time via CompileOptions.Groth16WAVKey — no VK readonly fields
// are carried on the contract struct.
//
// Compared to the generic Groth16 variant (rollup_groth16.runar.go), the
// witness-assisted path ships a much smaller locking script (~50-700 KB
// vs ~5.6 MB) and verifies in ~400 ms on BSV because the expensive final-
// exponentiation and Miller-loop gradient witnesses come in as spend-time
// stack pushes rather than being recomputed in-script.
//
// The preamble marker is runar.AssertGroth16WitnessAssisted(), and it MUST
// be the first statement of AdvanceState. At most one method per contract
// may use the witness-assisted preamble; governance methods (Freeze /
// Unfreeze / Upgrade) run without it.
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - StateRoot:   32-byte hash of current L2 state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// Readonly properties baked into the locking script at compile time:
//   - SP1VerifyingKeyHash: sha256(SP1 verifying key) — cross-system binding
//     with the BSV-EVM proof tracking hash. NOT consumed by the on-chain
//     pairing verifier (the real VK is baked by the preamble emitter).
//   - ChainId:             shard chain ID for cross-shard replay prevention
//   - Governance*:         freeze / unfreeze / upgrade authorization
type Groth16WARollupContract struct {
	runar.StatefulSmartContract

	// ---- Mutable state ----
	StateRoot   runar.ByteString // 32-byte hash of current state
	BlockNumber runar.Bigint     // monotonically increasing block counter
	Frozen      runar.Bigint     // 0=active, 1=frozen by governance

	// ---- Readonly: shared with the Basefold and Groth16 variants ----
	SP1VerifyingKeyHash runar.ByteString `runar:"readonly"` // sha256(SP1 vkey) — bsv-evm binding
	ChainId             runar.Bigint     `runar:"readonly"` // shard chain ID

	// ---- Readonly: governance ----
	GovernanceMode      runar.Bigint `runar:"readonly"` // 0=none, 1=single_key, 2=multisig
	GovernanceThreshold runar.Bigint `runar:"readonly"` // M for M-of-N (1 for single_key, 0 for none)
	GovernanceKey       runar.PubKey `runar:"readonly"` // single-key governance key (or key 1 in multisig)
	GovernanceKey2      runar.PubKey `runar:"readonly"` // multisig key 2 (zeros if unused)
	GovernanceKey3      runar.PubKey `runar:"readonly"` // multisig key 3 (zeros if unused)
}

// AdvanceState advances the covenant state after a witness-assisted Groth16
// pairing check on an SP1 proof. Invariants enforced (in order):
//  1. Witness-assisted Groth16 verifier preamble (inlined by codegen).
//     MUST be the first statement of the method body.
//  2. Shard must not be frozen.
//  3. New block number must be exactly previous + 1.
//  4. proofBlobHash at public values offset 64 must equal hash256(proofBlob).
//  5. Public values offsets 0/32/104/136 must match StateRoot / newStateRoot
//     / hash256(batchData) / ChainId (little-endian 8 bytes) respectively.
//
// Only 5 runtime args — the witness-assisted preamble consumes its witness
// bundle from the top of the stack (pushed there by the Rúnar SDK's
// CallOptions.Groth16WAWitness field) before the declared params are bound.
func (c *Groth16WARollupContract) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
) {
	// 0. Witness-assisted Groth16 verifier preamble. MUST be the first
	//    statement of the method body — the codegen recognises it as the
	//    marker for inlining the verifier ops with the baked-in VK, and
	//    the witness stack pushes only live on top of the stack at method
	//    entry.
	runar.AssertGroth16WitnessAssisted()

	// 1. Reject if shard is frozen by governance.
	runar.Assert(c.Frozen == 0)

	// 2. Block number must be exactly previous + 1.
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// 3. Proof blob integrity: hash the full proof and verify it matches
	//    the proofBlobHash in public values (offset 64).
	pvProofHash := runar.Substr(publicValues, 64, 32)
	runar.Assert(pvProofHash == runar.Hash256(proofBlob))

	// 4. Extract and verify public values at spec offsets.
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
}

// ---------------------------------------------------------------------------
// Governance methods — split per mode to satisfy Rúnar's affine value checker
// ---------------------------------------------------------------------------
//
// See rollup_basefold.runar.go for the full rationale. Briefly: the Rúnar
// affine type checker tracks Sig consumption with a method-global map and
// does not understand branch exclusivity, so a single Freeze/Unfreeze/Upgrade
// method that branches on c.GovernanceMode and reuses sig1 across branches
// is rejected. Splitting per mode preserves all three governance modes.
//
// The matrix is:
//   - FreezeSingleKey    / UnfreezeSingleKey    / UpgradeSingleKey   (mode 1)
//   - FreezeMultiSig2    / UnfreezeMultiSig2    / UpgradeMultiSig2   (mode 2, M=2)
//   - FreezeMultiSig3    / UnfreezeMultiSig3    / UpgradeMultiSig3   (mode 2, M=3)
//
// Mode 0 (none) has no governance methods at all.
//
// None of these methods use the witness-assisted preamble — that slot is
// reserved for AdvanceState in this contract.

// ---- Freeze ----

// FreezeSingleKey freezes the shard under single-key governance.
func (c *Groth16WARollupContract) FreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 1
}

// FreezeMultiSig2 freezes the shard under 2-of-3 multisig governance.
func (c *Groth16WARollupContract) FreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *Groth16WARollupContract) FreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
func (c *Groth16WARollupContract) UnfreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 0
}

// UnfreezeMultiSig2 unfreezes the shard under 2-of-3 multisig governance.
func (c *Groth16WARollupContract) UnfreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *Groth16WARollupContract) UnfreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
// Upgrade replaces the covenant script. The shard must be frozen first.
// Because at most one method per contract may use the witness-assisted
// preamble (and that slot is taken by AdvanceState), Upgrade does NOT
// perform a pairing check — the governance signatures are the sole
// authorization. State is bumped to the next block but no proof / public
// values bindings are validated.

// UpgradeSingleKey upgrades the covenant under single-key governance.
func (c *Groth16WARollupContract) UpgradeSingleKey(
	sig runar.Sig,
	newCovenantScript runar.ByteString,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
}

// UpgradeMultiSig2 upgrades the covenant under 2-of-3 multisig governance.
func (c *Groth16WARollupContract) UpgradeMultiSig2(
	sig1 runar.Sig,
	sig2 runar.Sig,
	newCovenantScript runar.ByteString,
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

	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
}

// UpgradeMultiSig3 upgrades the covenant under 3-of-3 multisig governance.
func (c *Groth16WARollupContract) UpgradeMultiSig3(
	sig1 runar.Sig,
	sig2 runar.Sig,
	sig3 runar.Sig,
	newCovenantScript runar.ByteString,
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

	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
}
