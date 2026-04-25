package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// FRIRollupContract is Mode 1 of the BSVM rollup covenant: the on-chain
// SP1 FRI / STARK verifier (Gate 0a Full landed; previously the
// trust-minimized FRI bridge).
//
// # Security model
//
// Mode 1 verifies the SP1 v6.0.2 STARK proof on-chain via the
// `runar.VerifySP1FRI` intrinsic. The compiled Bitcoin Script absorbs
// the proof, public values, and the pinned SP1 verifying key hash into
// the Fiat-Shamir transcript, replays the FRI argument (KoalaBear
// field arithmetic + Poseidon2 KoalaBear Merkle openings + colinearity
// folds + final-poly Horner check), and fails OP_VERIFY on any
// mismatch. This is a complete validity proof, not a trie-integrity-
// only proof — every opcode, storage write, and balance transfer
// inside the SP1 guest is covered.
//
// In addition to the proof, the covenant binds shard-specific values
// (state roots, batch hash, chain id, block number) by extracting
// fixed offsets from the public-values blob and asserting they match
// the covenant's current state and the caller-supplied advance args.
// The proof guarantees the public-values blob is what the guest
// committed; the covenant guarantees that blob is the right one for
// THIS shard's advance.
//
// Mode 1 is mainnet-eligible (the previous PrepareGenesis guardrail
// has been lifted now that the on-chain verifier lands real proofs).
//
// # State fields (persisted across UTXO spends via OP_PUSH_TX)
//
//   - StateRoot:   32-byte hash of current L2 state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// # Readonly properties baked into the locking script
//
//   - SP1VerifyingKeyHash: keccak256(SP1 verifying key). Bound at
//     compile time and consumed by VerifySP1FRI on every advance so a
//     malicious unlocking script cannot supply it.
//   - ChainId:             shard chain ID for cross-shard replay prevention
//   - Governance*:         freeze / unfreeze / upgrade authorization
type FRIRollupContract struct {
	runar.StatefulSmartContract

	// ---- Mutable state ----
	StateRoot   runar.ByteString // 32-byte hash of current state
	BlockNumber runar.Bigint     // monotonically increasing block counter
	Frozen      runar.Bigint     // 0=active, 1=frozen by governance

	// ---- Readonly ----
	SP1VerifyingKeyHash runar.ByteString `runar:"readonly"` // sha256(SP1 vkey); reserved for future FRI verifier
	ChainId             runar.Bigint     `runar:"readonly"` // shard chain ID

	// ---- Readonly: governance ----
	GovernanceMode      runar.Bigint `runar:"readonly"` // 0=none, 1=single_key, 2=multisig
	GovernanceThreshold runar.Bigint `runar:"readonly"` // M for M-of-N (1 for single_key, 0 for none)
	GovernanceKey       runar.PubKey `runar:"readonly"` // single-key governance key (or key 1 in multisig)
	GovernanceKey2      runar.PubKey `runar:"readonly"` // multisig key 2 (zeros if unused)
	GovernanceKey3      runar.PubKey `runar:"readonly"` // multisig key 3 (zeros if unused)
}

// AdvanceState advances the covenant state in Mode 1 by verifying an
// SP1 v6.0.2 STARK proof on-chain via runar.VerifySP1FRI.
//
// On-chain invariants enforced (in order):
//  1. Shard must not be frozen.
//  2. SP1 FRI proof verifies against the pinned SP1VerifyingKeyHash
//     and absorbs publicValues into the Fiat-Shamir transcript. A
//     mismatched proof, vkey, or pv blob fails OP_VERIFY inside the
//     verifier body — `runar.VerifySP1FRI` returns false only if the
//     entire STARK argument replays cleanly.
//  3. New block number must be exactly previous + 1.
//  4. Public-value offsets bind to their inputs:
//     [0..32)   preStateRoot  == c.StateRoot
//     [32..64)  postStateRoot == newStateRoot
//     [104..136) batchDataHash == hash256(batchData)
//     [136..144) chainId       == c.ChainId (little-endian 8 bytes)
//     [272..280) blockNumber   == newBlockNumber (little-endian 8 bytes)
//
// The blockNumber binding (C4) ensures the proof's public-values slot
// commits to the same block the covenant is advancing to, so a proof
// produced for one height cannot be replayed against another height.
//
// # Data availability
//
// Every advance emits a spec-12 BSVM\x02 OP_RETURN output carrying the
// raw batchData. The runar-go SDK resolves `addDataOutput` ANF bindings
// at call time and emits the output between the contract continuation
// and the change output, so the tx's hashOutputs matches the compiled
// script's continuation-hash assertion. This gives indexers direct
// access to batch payloads via BSV tx iteration without needing to
// parse the covenant input script.
func (c *FRIRollupContract) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
) {
	runar.Assert(c.Frozen == 0)

	// Verify the SP1 STARK proof on-chain. VerifySP1FRI absorbs
	// proofBlob + publicValues + sp1VKeyHash into the Fiat-Shamir
	// transcript and replays the full FRI argument. Fails OP_VERIFY
	// internally on any STARK / Merkle / colinearity mismatch.
	runar.Assert(runar.VerifySP1FRI(proofBlob, publicValues, c.SP1VerifyingKeyHash))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvBlockNumber := runar.Substr(publicValues, 272, 8)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvPostStateRoot == newStateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))
	runar.Assert(pvBlockNumber == runar.Num2Bin(newBlockNumber, 8))

	// F07 (post-R7/R9): emit the spec-12 advance OP_RETURN output —
	// see the Mode 2 AdvanceState for the format rationale.
	opReturnHdr := runar.ByteString("\x00\x6a\x4e") // OP_FALSE + OP_RETURN + OP_PUSHDATA4
	bsvmMagic := runar.ByteString("BSVM\x02")
	payload := runar.Cat(bsvmMagic, batchData)
	lenBytes := runar.Num2Bin(runar.Len(payload), 4)
	opReturnScript := runar.Cat(runar.Cat(opReturnHdr, lenBytes), payload)
	c.AddDataOutput(0, opReturnScript)

	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0
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
// per mode + threshold.
//
// Mode 0 (none) has no governance methods at all — the absence of any
// FreezeSingleKey / FreezeMultiSig* method makes governance unreachable, and
// a "none" shard cannot be frozen, unfrozen, or upgraded by anyone. Under
// Mode 1 (trust-minimized FRI) this also removes the only safety backstop
// against a malicious advance. Use GovernanceNone with Mode 1 only for
// deterministic testing.

// ---- Freeze ----

// FreezeSingleKey freezes the shard under single-key governance.
func (c *FRIRollupContract) FreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 1
}

// FreezeMultiSig2 freezes the shard under 2-of-3 multisig governance.
func (c *FRIRollupContract) FreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *FRIRollupContract) FreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
func (c *FRIRollupContract) UnfreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 0
}

// UnfreezeMultiSig2 unfreezes the shard under 2-of-3 multisig governance.
func (c *FRIRollupContract) UnfreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *FRIRollupContract) UnfreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
// Mode 1 Upgrade does NOT carry an on-chain FRI proof check (same trust
// model as AdvanceState) — governance key holders are trusted to
// validate the new covenant script and its migration hash out-of-band.
// The new covenant script hash must appear in the public values
// migration slot ([240..272]).

// UpgradeSingleKey upgrades the covenant under single-key governance.
//
// proofBlob is accepted as a public parameter to preserve the unlock-script
// argument layout against the future on-chain FRI verifier upgrade; it is
// not consumed inside the script body.
func (c *FRIRollupContract) UpgradeSingleKey(
	sig runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))

	// Verify the SP1 STARK proof on-chain. Same VerifySP1FRI binding
	// as AdvanceState — the upgrade path can only execute on a valid
	// proof, in addition to the governance signatures above.
	runar.Assert(runar.VerifySP1FRI(proofBlob, publicValues, c.SP1VerifyingKeyHash))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvMigrationHash := runar.Substr(publicValues, 240, 32)
	pvBlockNumber := runar.Substr(publicValues, 272, 8)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))
	runar.Assert(pvMigrationHash == runar.Hash256(newCovenantScript))
	runar.Assert(pvBlockNumber == runar.Num2Bin(newBlockNumber, 8))

	c.StateRoot = pvPostStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
}

// UpgradeMultiSig2 upgrades the covenant under 2-of-3 multisig governance.
func (c *FRIRollupContract) UpgradeMultiSig2(
	sig1 runar.Sig,
	sig2 runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 2)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))

	// Verify the SP1 STARK proof on-chain. Same VerifySP1FRI binding
	// as AdvanceState — the upgrade path can only execute on a valid
	// proof, in addition to the governance signatures above.
	runar.Assert(runar.VerifySP1FRI(proofBlob, publicValues, c.SP1VerifyingKeyHash))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvMigrationHash := runar.Substr(publicValues, 240, 32)
	pvBlockNumber := runar.Substr(publicValues, 272, 8)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))
	runar.Assert(pvMigrationHash == runar.Hash256(newCovenantScript))
	runar.Assert(pvBlockNumber == runar.Num2Bin(newBlockNumber, 8))

	c.StateRoot = pvPostStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
}

// UpgradeMultiSig3 upgrades the covenant under 3-of-3 multisig governance.
func (c *FRIRollupContract) UpgradeMultiSig3(
	sig1 runar.Sig,
	sig2 runar.Sig,
	sig3 runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 3)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2, sig3},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))

	// Verify the SP1 STARK proof on-chain. Same VerifySP1FRI binding
	// as AdvanceState — the upgrade path can only execute on a valid
	// proof, in addition to the governance signatures above.
	runar.Assert(runar.VerifySP1FRI(proofBlob, publicValues, c.SP1VerifyingKeyHash))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvMigrationHash := runar.Substr(publicValues, 240, 32)
	pvBlockNumber := runar.Substr(publicValues, 272, 8)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))
	runar.Assert(pvMigrationHash == runar.Hash256(newCovenantScript))
	runar.Assert(pvBlockNumber == runar.Num2Bin(newBlockNumber, 8))

	c.StateRoot = pvPostStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
}
