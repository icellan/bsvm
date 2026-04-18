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
// raw / ~1.35 MB with the MSM-binding preamble) and verifies in ~400 ms on
// BSV because the expensive final-exponentiation and Miller-loop gradient
// witnesses come in as spend-time stack pushes rather than being recomputed
// in-script.
//
// The preamble marker is runar.AssertGroth16WitnessAssistedWithMSM(), and
// it MUST be the first statement of AdvanceState. At most one method per
// contract may use the witness-assisted preamble; governance methods
// (Freeze / Unfreeze / Upgrade) run without it.
//
// Soundness status (post Rúnar R1 + R1b + R2 + R6 + R7 + R8):
//   - F02 closed — the MSM-binding preamble recomputes
//     IC[0] + Σ pub_i · IC[i+1] on-chain from the 5 witness-pushed
//     scalars and asserts equality with the prover-supplied prepared_inputs.
//   - F03 closed — the preamble runs G1 on-curve checks on proof.A /
//     proof.C and G2 on-curve + subgroup check on proof.B before the
//     Miller loop.
//   - F01 closed — the 5 SP1 public-input scalars are exposed to the
//     method body via runar.Groth16PublicInput(i) and bound to the
//     covenant's pinned SP1ProgramVkHashScalar / reduced publicValues
//     digest / exit-code / vkRoot via runar.Assert below.
//   - F04 closed — the tautological pvProofHash check at offset 64 was
//     removed; spec 12 defines that slot as receiptsHash (not verified
//     by the covenant).
//   - F05 closed — Upgrade* variants take a migrationHash arg bound to
//     Hash256(newCovenantScript).
//   - F08 closed — each Groth16PublicInput(i) is range-checked into
//     [0, r) to match SP1 / Solidity reference verifiers.
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - StateRoot:   32-byte hash of current L2 state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// Readonly properties baked into the locking script at compile time:
//   - SP1VerifyingKeyHash: sha256(SP1 verifying key) — cross-system binding
//     with the BSV-EVM proof tracking hash. NOT consumed by the on-chain
//     pairing verifier (the real VK is baked by the preamble emitter), and
//     NOT bound to any SP1 public input directly on-chain (see
//     SP1ProgramVkHashScalar below for the load-bearing binding).
//   - ChainId:                shard chain ID for cross-shard replay prevention.
//   - SP1ProgramVkHashScalar: SP1 guest vkey hash reduced into the BN254
//     scalar field, asserted equal to Groth16PublicInput(0). Without this,
//     any SP1 proof for any program would be accepted.
//   - Bn254ScalarMask:        2^253, used to reduce sha256(publicValues)
//     into the BN254 scalar field for the Groth16PublicInput(1) binding.
//   - Bn254ScalarOrder:       BN254 scalar field order r, used to
//     range-check each Groth16PublicInput(i).
//   - Governance*:            freeze / unfreeze / upgrade authorization.
type Groth16WARollupContract struct {
	runar.StatefulSmartContract

	// ---- Mutable state ----
	StateRoot   runar.ByteString // 32-byte hash of current state
	BlockNumber runar.Bigint     // monotonically increasing block counter
	Frozen      runar.Bigint     // 0=active, 1=frozen by governance

	// ---- Readonly: shared with the Basefold and Mode 2 variants ----
	SP1VerifyingKeyHash runar.ByteString `runar:"readonly"` // sha256(SP1 vkey) — bsv-evm binding
	ChainId             runar.Bigint     `runar:"readonly"` // shard chain ID

	// ---- Readonly: BN254 scalar field order (F08) ----
	Bn254ScalarOrder runar.Bigint `runar:"readonly"`

	// ---- Readonly: SP1 public-input bindings (F01) ----
	SP1ProgramVkHashScalar runar.Bigint `runar:"readonly"`
	Bn254ScalarMask        runar.Bigint `runar:"readonly"`

	// ---- Readonly: governance ----
	GovernanceMode      runar.Bigint `runar:"readonly"` // 0=none, 1=single_key, 2=multisig
	GovernanceThreshold runar.Bigint `runar:"readonly"` // M for M-of-N (1 for single_key, 0 for none)
	GovernanceKey       runar.PubKey `runar:"readonly"` // single-key governance key (or key 1 in multisig)
	GovernanceKey2      runar.PubKey `runar:"readonly"` // multisig key 2 (zeros if unused)
	GovernanceKey3      runar.PubKey `runar:"readonly"` // multisig key 3 (zeros if unused)
}

// reducePublicValuesToScalarWA mirrors reducePublicValuesToScalar from
// the Mode 2 contract: sha256(publicValues) BE → reverseBytes → pad 0x00
// → Bin2Num → % Bn254ScalarMask. The trailing 0x00 byte forces positive
// Script-number interpretation so sha256 outputs with the top bit set
// still reduce correctly.
func reducePublicValuesToScalarWA(c *Groth16WARollupContract, publicValues runar.ByteString) runar.Bigint {
	hashBE := runar.Sha256(publicValues)
	hashLE := runar.ReverseBytes(hashBE)
	zeroByte := runar.Num2Bin(0, 1)
	hashLEPadded := runar.Cat(hashLE, zeroByte)
	return runar.Bin2Num(hashLEPadded) % c.Bn254ScalarMask
}

// AdvanceState advances the covenant state after an MSM-binding
// witness-assisted Groth16 pairing check on an SP1 proof. Invariants
// enforced (in order):
//  1. MSM-binding Groth16 verifier preamble (inlined by codegen). MUST
//     be the first statement of the method body. The preamble:
//       - on-curve checks proof.A / proof.C (G1),
//       - on-curve + subgroup checks proof.B (G2),
//       - recomputes IC[0] + Σ pub_i · IC[i+1] on-chain from the 5
//         witness-pushed scalars and binds it to prepared_inputs,
//       - runs triple Miller loop × precomputed α·β Fp12 × final exp,
//       - leaves the 5 pub_i scalars reachable from the method body via
//         runar.Groth16PublicInput(i).
//  2. Shard must not be frozen.
//  3. New block number must be exactly previous + 1.
//  4. F08: each Groth16PublicInput(i) is in [0, r).
//  5. F01: the 5 SP1 public inputs are bound to domain values:
//       - Groth16PublicInput(0) == SP1ProgramVkHashScalar
//       - Groth16PublicInput(1) == reducePublicValuesToScalarWA(publicValues)
//       - Groth16PublicInput(2) == 0 (exit code)
//       - Groth16PublicInput(4) == 0 (vkRoot — single-program mode)
//       - Groth16PublicInput(3) (proofNonce) unconstrained per SP1 convention.
//  6. Public values offsets 0/32/104/136 must match StateRoot /
//     newStateRoot / hash256(batchData) / ChainId (little-endian 8 bytes).
//
// Only 5 runtime args — the MSM-binding preamble consumes its witness
// bundle (gradients, final-exp, 5 pub_i, prepared_inputs, A, B, C) from
// the top of the stack (pushed by the Rúnar SDK's
// CallOptions.Groth16WAWitness field) before the declared params are bound.
func (c *Groth16WARollupContract) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
) {
	// 0. MSM-binding witness-assisted Groth16 verifier preamble. MUST be
	//    the first statement — the codegen recognises it as the marker
	//    for inlining the MSM-binding verifier ops with the baked-in VK
	//    + IC, and the witness stack pushes only live on top of the
	//    stack at method entry.
	runar.AssertGroth16WitnessAssistedWithMSM()

	// 1. Reject if shard is frozen by governance.
	runar.Assert(c.Frozen == 0)

	// 2. Block number must be exactly previous + 1.
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// 3. F08: range-check each SP1 public-input scalar into [0, r).
	runar.Assert(runar.Groth16PublicInput(0) < c.Bn254ScalarOrder)
	runar.Assert(runar.Groth16PublicInput(1) < c.Bn254ScalarOrder)
	runar.Assert(runar.Groth16PublicInput(2) < c.Bn254ScalarOrder)
	runar.Assert(runar.Groth16PublicInput(3) < c.Bn254ScalarOrder)
	runar.Assert(runar.Groth16PublicInput(4) < c.Bn254ScalarOrder)

	// 4. F01: bind the 5 SP1 public inputs to domain values. The
	//    MSM-binding preamble already bound prepared_inputs to the
	//    circuit's public input coefficients; these assertions further
	//    bind each input to what the covenant expects for THIS shard.
	runar.Assert(runar.Groth16PublicInput(0) == c.SP1ProgramVkHashScalar)
	runar.Assert(runar.Groth16PublicInput(1) == reducePublicValuesToScalarWA(c, publicValues))
	runar.Assert(runar.Groth16PublicInput(2) == 0)
	runar.Assert(runar.Groth16PublicInput(4) == 0)

	// 5. Extract and verify public values at spec offsets.
	pvPreStateRoot := runar.Substr(publicValues, 0, 32)
	pvPostStateRoot := runar.Substr(publicValues, 32, 32)
	pvBatchDataHash := runar.Substr(publicValues, 104, 32)
	pvChainIdBytes := runar.Substr(publicValues, 136, 8)

	runar.Assert(pvChainIdBytes == runar.Num2Bin(c.ChainId, 8))
	runar.Assert(pvPreStateRoot == c.StateRoot)
	runar.Assert(pvPostStateRoot == newStateRoot)
	runar.Assert(pvBatchDataHash == runar.Hash256(batchData))

	// F07 (post-R7): emit the spec-12 advance OP_RETURN output —
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

	_ = proofBlob
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
// authorization.
//
// F05 fix: the caller MUST supply `migrationHash` alongside
// `newCovenantScript`, and the covenant asserts
// `migrationHash == Hash256(newCovenantScript)`. This is an on-chain
// commitment to the intended script, readable from the unlocking script
// after confirmation. Limitation: Rúnar's current state-continuation
// codegen emits `getStateScript()` rather than the supplied
// newCovenantScript, so an Upgrade* call does NOT actually install the
// new script today — it only unfreezes and bumps BlockNumber. The
// migrationHash binding becomes load-bearing the moment Rúnar honours
// newCovenantScript.

// UpgradeSingleKey upgrades the covenant under single-key governance.
func (c *Groth16WARollupContract) UpgradeSingleKey(
	sig runar.Sig,
	newCovenantScript runar.ByteString,
	migrationHash runar.ByteString,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))

	runar.Assert(migrationHash == runar.Hash256(newCovenantScript))
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
	migrationHash runar.ByteString,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 2)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))

	runar.Assert(migrationHash == runar.Hash256(newCovenantScript))
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
	migrationHash runar.ByteString,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 2)
	runar.Assert(c.GovernanceThreshold == 3)
	runar.Assert(runar.CheckMultiSig(
		[]runar.Sig{sig1, sig2, sig3},
		[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
	))

	runar.Assert(migrationHash == runar.Hash256(newCovenantScript))
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	c.BlockNumber = newBlockNumber
	c.Frozen = 0

	_ = newCovenantScript
}
