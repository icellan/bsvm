package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// DevKeyRollupContract is the devnet-only rollup covenant used by spec 16
// "mock" and "execute" proving modes. Its on-chain invariants are
// structurally identical to FRIRollupContract (the trust-minimized FRI
// bridge) — state continuity, block increment, chain-ID binding, batch
// data hash binding, OP_RETURN data-availability output — with one
// additional requirement: AdvanceState carries a governance-key signature.
//
// # Purpose
//
// Spec 16 maps the three developer-facing proving modes as follows:
//
//   - mock:    fast local dev; SP1 mock runtime; covenant uses DevKey sig
//   - execute: dual-EVM correctness; SP1 full execute; covenant uses DevKey sig
//   - prove:   production-equivalent; real STARK; covenant uses FRI/Groth16
//
// For mock and execute, the on-chain script should NOT trust arbitrary
// advances — otherwise any party running a node could race the dev into
// a divergent state before the dev's own prover emits a STARK. A single
// CheckSig gated on the operator's own governance key prevents that
// scenario and keeps the covenant identical to production everywhere
// except the proof-verification step.
//
// # Security model
//
// Devnet-only. Reuses GovernanceKey (slot 0) as the "dev key" rather
// than introducing a distinct DevKey constructor arg — the devnet
// operator IS the governance admin, so one key holder controls freeze,
// unfreeze, upgrade, and state advance. This collapses the "prover
// authorization" and "governance" roles, which would be unsafe on
// mainnet but is exactly what spec 16 wants for local development.
//
// GovernanceNone is rejected at genesis time for this mode because
// without a governance key there is no key for AdvanceState to check
// the signature against. Spec 16 mandates single_key for devnet.
//
// # Compatibility
//
// Advance-time public-values offsets match FRIRollupContract and
// GrothRollupContract exactly:
//
//	[0..32)    preStateRoot
//	[32..64)   postStateRoot
//	[104..136) batchDataHash
//	[136..144) chainId (little-endian 8 bytes)
//
// The spec-12 OP_RETURN data-availability output uses the same BSVM\x02
// magic prefix as the production contracts.
type DevKeyRollupContract struct {
	runar.StatefulSmartContract

	// ---- Mutable state ----
	StateRoot   runar.ByteString // 32-byte hash of current state
	BlockNumber runar.Bigint     // monotonically increasing block counter
	Frozen      runar.Bigint     // 0=active, 1=frozen by governance

	// ---- Readonly ----
	SP1VerifyingKeyHash runar.ByteString `runar:"readonly"` // sha256(SP1 vkey); reserved for future FRI verifier wiring
	ChainId             runar.Bigint     `runar:"readonly"` // shard chain ID

	// ---- Readonly: governance ----
	GovernanceMode      runar.Bigint `runar:"readonly"` // 0=none, 1=single_key, 2=multisig
	GovernanceThreshold runar.Bigint `runar:"readonly"` // M for M-of-N (1 for single_key, 0 for none)
	GovernanceKey       runar.PubKey `runar:"readonly"` // single-key governance key (or key 1 in multisig) — also the dev key
	GovernanceKey2      runar.PubKey `runar:"readonly"` // multisig key 2 (zeros if unused)
	GovernanceKey3      runar.PubKey `runar:"readonly"` // multisig key 3 (zeros if unused)
}

// AdvanceState advances the covenant state under devnet dev-key authorization.
// The batch is bound to the public values exactly as in Mode 1 (FRI bridge);
// the additional CheckSig against GovernanceKey prevents non-operator advances
// on a public regtest network.
//
// On-chain invariants enforced (in order):
//  1. Shard must not be frozen.
//  2. Advance signature must verify against GovernanceKey.
//  3. New block number must be exactly previous + 1.
//  4. Public-value offsets bind to their inputs (preStateRoot, postStateRoot,
//     batchDataHash, chainId).
//
// proofBlob is accepted for ABI parity with the production contracts — it is
// NOT consumed on-chain in devnet modes.
func (c *DevKeyRollupContract) AdvanceState(
	sig runar.Sig,
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)
	pvWithdrawalRoot := runar.Substr(publicValues, 144, 32)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvPostStateRoot == newStateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))

	// Spec-12 OP_RETURN data-availability output. Identical to the FRI and
	// Groth16 contracts so external observers can parse the batchData
	// without needing to branch on proof mode. The 32-byte withdrawalRoot
	// prefix (pv[144..176)) lets the bridge covenant read it via cross-
	// covenant output reference (spec 13 §C).
	opReturnHdr := runar.ByteString("\x00\x6a\x4e")
	bsvmMagic := runar.ByteString("BSVM\x02")
	payload := runar.Cat(runar.Cat(bsvmMagic, pvWithdrawalRoot), batchData)
	lenBytes := runar.Num2Bin(runar.Len(payload), 4)
	opReturnScript := runar.Cat(runar.Cat(opReturnHdr, lenBytes), payload)
	c.AddDataOutput(0, opReturnScript)

	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = proofBlob
}

// ---------------------------------------------------------------------------
// Governance methods — split per mode, identical to FRIRollupContract
// ---------------------------------------------------------------------------
//
// These mirror the FRI variant's governance surface verbatim because the
// devnet contract is meant to be a near-drop-in substitute. See the
// extensive comment block in rollup_fri.runar.go for why each action is
// split into SingleKey / MultiSig2 / MultiSig3 entry points.

// ---- Freeze ----

// FreezeSingleKey freezes the shard under single-key governance.
func (c *DevKeyRollupContract) FreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 1
}

// FreezeMultiSig2 freezes the shard under 2-of-3 multisig governance.
func (c *DevKeyRollupContract) FreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *DevKeyRollupContract) FreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
func (c *DevKeyRollupContract) UnfreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 0
}

// UnfreezeMultiSig2 unfreezes the shard under 2-of-3 multisig governance.
func (c *DevKeyRollupContract) UnfreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *DevKeyRollupContract) UnfreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
// Devnet upgrade does not carry a proof check (same trust model as
// AdvanceState) — governance key holders authorise the script swap.

// UpgradeSingleKey upgrades the covenant under single-key governance.
func (c *DevKeyRollupContract) UpgradeSingleKey(
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

	runar.Assert(newBlockNumber == c.BlockNumber+1)

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
func (c *DevKeyRollupContract) UpgradeMultiSig2(
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

	runar.Assert(newBlockNumber == c.BlockNumber+1)

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
func (c *DevKeyRollupContract) UpgradeMultiSig3(
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

	runar.Assert(newBlockNumber == c.BlockNumber+1)

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
