package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// FRIRollupContract is Mode 1 of the BSVM rollup covenant: the
// trust-minimized FRI bridge.
//
// # Security model
//
// Mode 1 does NOT verify the SP1 FRI proof on-chain. The covenant binds
// state transitions (block+1, state roots, batch hash, chain id) but
// performs no STARK arithmetic. Any prover can advance the state with a
// well-formed public-values blob and matching batchData — a malicious
// prover can therefore commit an invalid state transition.
//
// The safety model rests on two off-chain layers:
//
//  1. Nodes re-execute every batch locally and verify the SP1 FRI proof
//     (SP1 v6.0.2, KoalaBear field, SHA-256 outer Merkle hashing — see
//     spec 12). A node that observes an invalid advance can trigger the
//     on-chain governance freeze path (FreezeSingleKey / FreezeMultiSig*).
//  2. Governance freeze is the only recourse against a bad advance. Mode
//     1 shards MUST be configured with non-trivial governance (mode
//     single_key or multisig). A GovernanceNone shard in Mode 1 has no
//     safety backstop at all.
//
// Mode 1 is NOT mainnet-eligible. PrepareGenesis rejects a mainnet
// shard configured with VerifyFRI regardless of the VK trust policy.
// For mainnet, use Mode 2 (Groth16) or Mode 3 (Groth16-WA) which
// perform full BN254 pairing verification on-chain.
//
// # Future path
//
// A full on-chain FRI verifier using the primitives validated by Gate
// 0a (Baby Bear / KoalaBear field arithmetic, SHA-256 Merkle paths,
// colinearity checks, proof-of-work) is tracked as Gate 0a Full in
// spec 9 and spec 13. When that lands, Mode 1 upgrades from a bridge
// to a fully self-verifying rollup and the mainnet guardrail is
// lifted. Until then Mode 1 is testnet / experimental only.
//
// # State fields (persisted across UTXO spends via OP_PUSH_TX)
//
//   - StateRoot:   32-byte hash of current L2 state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// # Readonly properties baked into the locking script
//
//   - SP1VerifyingKeyHash: sha256(SP1 verifying key). Recorded for
//     indexing and future-upgrade continuity; the on-chain script
//     does NOT consult it in Mode 1 because there is no proof check.
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

// AdvanceState advances the covenant state in Mode 1 (trust-minimized
// FRI bridge). No SP1 STARK verification is performed on-chain.
//
// On-chain invariants enforced (in order):
//  1. Shard must not be frozen.
//  2. New block number must be exactly previous + 1.
//  3. Public-value offsets bind to their inputs:
//     [0..32)   preStateRoot  == c.StateRoot
//     [32..64)  postStateRoot == newStateRoot
//     [104..136) batchDataHash == hash256(batchData)
//     [136..144) chainId       == c.ChainId (little-endian 8 bytes)
//
// Spec-12 OP_RETURN data-availability output is emitted with the
// `BSVM\x02` magic. The continuation-hash binding ensures the on-chain
// tx carries batchData verbatim.
//
// proofBlob is accepted as a parameter so the ABI is stable against the
// future on-chain FRI verifier upgrade (Gate 0a Full). It is not
// consumed on-chain in Mode 1.
func (c *FRIRollupContract) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvPostStateRoot == newStateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))

	// Spec-12 OP_RETURN data-availability output:
	//   OP_FALSE OP_RETURN OP_PUSHDATA4 <payload_len_le4> "BSVM\x02" <batchData>
	// The continuation-hash check (Rúnar-injected) binds this output to
	// the tx so an on-chain observer can always read batchData without
	// parsing the covenant input script.
	opReturnHdr := runar.ByteString("\x00\x6a\x4e")
	bsvmMagic := runar.ByteString("BSVM\x02")
	payload := runar.Cat(bsvmMagic, batchData)
	lenBytes := runar.Num2Bin(runar.Len(payload), 4)
	opReturnScript := runar.Cat(runar.Cat(opReturnHdr, lenBytes), payload)
	c.AddDataOutput(0, opReturnScript)

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
