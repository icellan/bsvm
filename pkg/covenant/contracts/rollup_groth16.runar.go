package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// Groth16RollupContract is the Groth16-only variant of the stateful rollup
// covenant. It verifies SP1 proofs on-chain via a BN254 multi-pairing check
// against a baked-in Groth16 verification key (19 readonly VK components).
//
// This file was split out of the original dual-mode rollup.runar.go contract
// so each compiled script carries only the verification logic it actually
// needs. The dual-mode contract compiled to ~5.8 MB and tripped the Rúnar
// `Invalid OP_SPLIT range` bug on regtest; splitting by mode reduces the
// readonly / argument surface dramatically.
//
// This is the "generic" Groth16 path: proof inputs (proofA / proofC G1 plus
// the G2 coordinates for proofB) are passed verbatim as runtime arguments
// and combined with the VK readonly fields via the standard BN254 generic
// primitives (Bn254G1AddP, Bn254G1ScalarMulP, Bn254MultiPairing4).
//
// Mode 1 (Basefold) lives in rollup_basefold.runar.go and Mode 3
// (witness-assisted Groth16) in rollup_groth16_wa.runar.go. Mode 3 produces
// a much smaller locking script (~688 KB vs ~6 MB here) and is the
// recommended production target; Mode 2 is kept for architectural
// completeness and shard operators who prefer the on-chain pairing path.
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - StateRoot:   32-byte hash of current L2 state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// Readonly properties baked into the locking script at compile time:
//   - SP1VerifyingKeyHash: sha256(SP1 verifying key) — kept for public-values
//     binding parity with the Basefold variant even though the BN254 verifier
//     does not consume it at runtime.
//   - ChainId:             shard chain ID for cross-shard replay prevention
//   - Bn254ScalarOrder:    BN254 scalar field order r, used to range-check
//     g16Input0..g16Input4 (finding F08). See field doc below for rationale.
//   - Governance*:         freeze / unfreeze / upgrade authorization
//   - AlphaG1, BetaG2*, GammaG2*, DeltaG2*, IC0..IC5: Groth16 verification key
type Groth16RollupContract struct {
	runar.StatefulSmartContract

	// ---- Mutable state ----
	StateRoot   runar.ByteString // 32-byte hash of current state
	BlockNumber runar.Bigint     // monotonically increasing block counter
	Frozen      runar.Bigint     // 0=active, 1=frozen by governance

	// ---- Readonly: shared with the Basefold variant ----
	SP1VerifyingKeyHash runar.ByteString `runar:"readonly"` // sha256(SP1 vkey)
	ChainId             runar.Bigint     `runar:"readonly"` // shard chain ID

	// ---- Readonly: BN254 scalar field order (F08) ----
	// Bn254ScalarOrder is r = 21888242871839275222246405745257275088548364400416034343698204186575808495617,
	// the BN254 scalar field order. Used to bound each of g16Input0..g16Input4
	// into the canonical range [0, r). Without this bound, a prover could
	// submit a scalar s >= r that would still pair-verify on-chain (EC scalar
	// mul is periodic mod r) but would be ABI-rejected by SP1's Solidity /
	// in-circuit reference verifiers — a differential-oracle hazard for
	// fuzzing and conformance parity, not a direct cryptographic break.
	//
	// R4c: typed BigintBig so the Go-mock F08 range check runs over the real
	// 254-bit r via runar.BigintBigLess, not truncated to int64. Script emit
	// is unchanged (BigintBig is a bigint alias at AST level).
	Bn254ScalarOrder runar.BigintBig `runar:"readonly"`

	// ---- Readonly: SP1 public-input bindings (F01) ----
	// SP1ProgramVkHashScalar is the SP1 guest program's vkey hash reduced
	// into the BN254 scalar field (same reduction SP1's Groth16 wrapper
	// applies before committing it as public input 0). Asserted equal to
	// g16Input0 on every advance, binding the proof to the specific SP1
	// program baked in at genesis. Without this binding any SP1 proof for
	// any guest program would pair-verify. R4c: typed BigintBig so the
	// Go-mock F01 vkey-scalar equality runs over the real ~253-bit value.
	SP1ProgramVkHashScalar runar.BigintBig `runar:"readonly"`

	// Bn254ScalarMask is 2^253, used to reduce sha256(publicValues) into
	// the BN254 scalar field to match SP1's committedValuesDigest
	// convention. 2^253 < r, so the reduction result is always a valid
	// scalar. R4c: typed BigintBig — the mask is inherently >63 bits.
	Bn254ScalarMask runar.BigintBig `runar:"readonly"`

	// Bn254Zero is a pre-computed BigintBig zero used as the RHS of the
	// F01 g16Input2 / g16Input4 equality assertions. A readonly is
	// necessary because BigintBig is *big.Int under Go and we cannot spell
	// a BigintBig literal inside the .runar.go source (no type-conversion
	// from untyped int to *big.Int). Script emit is a constant OP_0.
	Bn254Zero runar.BigintBig `runar:"readonly"`

	// ---- Readonly: governance ----
	GovernanceMode      runar.Bigint `runar:"readonly"` // 0=none, 1=single_key, 2=multisig
	GovernanceThreshold runar.Bigint `runar:"readonly"` // M for M-of-N (1 for single_key, 0 for none)
	GovernanceKey       runar.PubKey `runar:"readonly"` // single-key governance key (or key 1 in multisig)
	GovernanceKey2      runar.PubKey `runar:"readonly"` // multisig key 2 (zeros if unused)
	GovernanceKey3      runar.PubKey `runar:"readonly"` // multisig key 3 (zeros if unused)

	// ---- Readonly: Groth16 verification key components ----
	AlphaG1   runar.Point  `runar:"readonly"` // alpha (G1)
	BetaG2X0  runar.Bigint `runar:"readonly"`
	BetaG2X1  runar.Bigint `runar:"readonly"`
	BetaG2Y0  runar.Bigint `runar:"readonly"`
	BetaG2Y1  runar.Bigint `runar:"readonly"`
	GammaG2X0 runar.Bigint `runar:"readonly"`
	GammaG2X1 runar.Bigint `runar:"readonly"`
	GammaG2Y0 runar.Bigint `runar:"readonly"`
	GammaG2Y1 runar.Bigint `runar:"readonly"`
	DeltaG2X0 runar.Bigint `runar:"readonly"`
	DeltaG2X1 runar.Bigint `runar:"readonly"`
	DeltaG2Y0 runar.Bigint `runar:"readonly"`
	DeltaG2Y1 runar.Bigint `runar:"readonly"`
	// IC points for public input linearization (SP1 has 5 public inputs).
	IC0 runar.Point `runar:"readonly"` // CONSTANT
	IC1 runar.Point `runar:"readonly"` // PUB_0
	IC2 runar.Point `runar:"readonly"` // PUB_1
	IC3 runar.Point `runar:"readonly"` // PUB_2
	IC4 runar.Point `runar:"readonly"` // PUB_3
	IC5 runar.Point `runar:"readonly"` // PUB_4
}

// reducePublicValuesToScalar is the Go-DSL expression of SP1's
// `committedValuesDigest = sha256(publicValues) & ((1<<253)-1)` reduction
// implemented on-chain via OP_SHA256 / OP_REVERSEBYTES / OP_BIN2NUM /
// OP_MOD. The trailing 0x00 byte forces positive Script-number
// interpretation so sha256 outputs with the top bit set still reduce
// correctly. R4c: returns runar.BigintBig and uses Bin2NumBig + BigintBigMod
// so the Go-mock reduction produces the full 253-bit digest instead of
// truncating at int64 — matching what the compiled Script emits.
func reducePublicValuesToScalar(c *Groth16RollupContract, publicValues runar.ByteString) runar.BigintBig {
	hashBE := runar.Sha256(publicValues)
	hashLE := runar.ReverseBytes(hashBE)
	zeroByte := runar.Num2Bin(0, 1)
	hashLEPadded := runar.Cat(hashLE, zeroByte)
	return runar.BigintBigMod(runar.Bin2NumBig(hashLEPadded), c.Bn254ScalarMask)
}

// AdvanceState advances the covenant state with a Groth16-verified proof.
// Invariants enforced (in order):
//  1. Shard must not be frozen.
//  2. New block number must be exactly previous + 1.
//  3. F08: each g16Input* is in [0, r) (BN254 scalar field order).
//  4. F01: SP1 public input bindings:
//     - g16Input0 == SP1ProgramVkHashScalar (proof targets the pinned
//     SP1 guest program, not an attacker-chosen program).
//     - g16Input1 == reducePublicValuesToScalar(publicValues) (binds the
//     on-chain publicValues to the SP1-circuit-committed digest).
//     - g16Input2 == 0 (SP1 exitCode — reject failed-guest proofs).
//     - g16Input4 == 0 (vkRoot — single-program mode only).
//     - g16Input3 (proofNonce) left unconstrained per SP1 convention.
//  5. Groth16 BN254 pairing check: prepared_inputs = IC0 + sum(input[i]*IC[i+1])
//     over the 5 SP1 public inputs, followed by the 4-pairing product
//     e(-A, B) * e(prepared_inputs, gamma) * e(C, delta) * e(alpha, -beta) == 1.
//  6. Public values offsets 0/32/104/136 must match StateRoot / newStateRoot
//     / hash256(batchData) / ChainId (little-endian 8 bytes) respectively.
//
// The tautological publicValues[64..96] == hash256(proofBlob) check present
// before F04 was removed: spec 12 defines that slot as receiptsHash
// (committed by the guest but not verified by the covenant). The prior
// assertion was either unsatisfiable by an honest prover or tautological
// (prover controls both sides).
func (c *Groth16RollupContract) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	// Groth16 proof points
	proofA runar.Point,
	proofBX0 runar.Bigint,
	proofBX1 runar.Bigint,
	proofBY0 runar.Bigint,
	proofBY1 runar.Bigint,
	proofC runar.Point,
	// SP1 Groth16 has 5 public inputs (BN254 scalar field elements). R4c:
	// typed BigintBig so the F01 / F08 assertions and the IC MSM run over
	// the real 254-bit scalar in the Go-mock, not truncated to int64.
	g16Input0 runar.BigintBig,
	g16Input1 runar.BigintBig,
	g16Input2 runar.BigintBig,
	g16Input3 runar.BigintBig,
	g16Input4 runar.BigintBig,
) {
	// 0. Reject if shard is frozen by governance.
	runar.Assert(c.Frozen == 0)

	// 1. Block number must be exactly previous + 1.
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// 2. F08: range-check each BN254 scalar public input into [0, r).
	//    SP1 and Solidity reference verifiers reduce inputs mod r before
	//    ABI-encoding them; accepting unreduced scalars here would produce
	//    the same pairing result (EC scalar mul is periodic mod r) but
	//    diverge from reference verifiers during fuzzing / conformance
	//    testing. Must appear before the MSM so the oracle-mismatch
	//    surface never enters Bn254G1ScalarMulBigP. R4c: BigintBigLess
	//    lowers to OP_LESSTHAN in Script and runs value comparison in
	//    the Go-mock (since `<` on *big.Int is a Go compile error).
	runar.Assert(runar.BigintBigLess(g16Input0, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input1, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input2, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input3, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input4, c.Bn254ScalarOrder))

	// 3. F01: bind the 5 SP1 public inputs to domain values. Must precede
	//    the pairing check so the pairing verifies a proof for inputs the
	//    covenant has pinned, not ones the prover chose. R4c: BigintBigEqual
	//    is value-equality (via big.Int.Cmp) matching Script OP_NUMEQUAL
	//    instead of pointer-equality (which is what `==` on *big.Int is in
	//    pure Go).
	runar.Assert(runar.BigintBigEqual(g16Input0, c.SP1ProgramVkHashScalar))
	runar.Assert(runar.BigintBigEqual(g16Input1, reducePublicValuesToScalar(c, publicValues)))
	runar.Assert(runar.BigintBigEqual(g16Input2, c.Bn254Zero))
	runar.Assert(runar.BigintBigEqual(g16Input4, c.Bn254Zero))

	// 4. Groth16: BN254 pairing verification with 5-input MSM. R4c: uses
	//    the *Big G1 scalar-mul variant so the Go-mock MSM runs over real
	//    254-bit scalars (prior Bn254G1ScalarMulP truncated to int64,
	//    silently producing wrong intermediate points under the mock).
	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulBigP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC5, g16Input4))
	runar.Assert(runar.Bn254G1OnCurveP(proofA))
	runar.Assert(runar.Bn254G1OnCurveP(proofC))
	runar.Assert(runar.Bn254G1OnCurveP(preparedInputs))
	negA := runar.Bn254G1NegateP(proofA)
	negBetaY0 := runar.Bn254FieldNegP(c.BetaG2Y0)
	negBetaY1 := runar.Bn254FieldNegP(c.BetaG2Y1)
	runar.Assert(runar.Bn254MultiPairing4(
		negA, proofBX0, proofBX1, proofBY0, proofBY1,
		preparedInputs, c.GammaG2X0, c.GammaG2X1, c.GammaG2Y0, c.GammaG2Y1,
		proofC, c.DeltaG2X0, c.DeltaG2X1, c.DeltaG2Y0, c.DeltaG2Y1,
		c.AlphaG1, c.BetaG2X0, c.BetaG2X1, negBetaY0, negBetaY1,
	))

	// 5. Extract and verify public values at spec offsets.
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

	// F07 (post-R7): emit the spec-12 advance OP_RETURN output
	//   OP_FALSE OP_RETURN OP_PUSHDATA4 <payload_len_le4> "BSVM\x02" <batchData>
	// addDataOutput includes the output in the continuation hash, so
	// the on-chain tx is cryptographically required to carry batchData
	// verbatim — giving overlay-node replay direct access via BSV
	// OP_RETURN without reading the covenant input script. The
	// "BSVM\x02" magic lets indexers filter covenant-advance OP_RETURNs
	// from unrelated traffic and mirrors the "BSVM\x01" genesis prefix.
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

// ---- Freeze ----

// FreezeSingleKey freezes the shard under single-key governance.
func (c *Groth16RollupContract) FreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 0)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 1
}

// FreezeMultiSig2 freezes the shard under 2-of-3 multisig governance.
func (c *Groth16RollupContract) FreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *Groth16RollupContract) FreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
func (c *Groth16RollupContract) UnfreezeSingleKey(sig runar.Sig) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))
	c.Frozen = 0
}

// UnfreezeMultiSig2 unfreezes the shard under 2-of-3 multisig governance.
func (c *Groth16RollupContract) UnfreezeMultiSig2(sig1 runar.Sig, sig2 runar.Sig) {
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
func (c *Groth16RollupContract) UnfreezeMultiSig3(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
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
// valid Groth16 proof for the next block must be provided and the new
// covenant script hash must appear in the public values migration slot
// ([240..272]).

// UpgradeSingleKey upgrades the covenant under single-key governance.
//
// proofBlob is accepted as a public parameter to preserve the unlock-script
// argument layout but is not consumed inside the script body.
func (c *Groth16RollupContract) UpgradeSingleKey(
	sig runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	proofA runar.Point,
	proofBX0 runar.Bigint,
	proofBX1 runar.Bigint,
	proofBY0 runar.Bigint,
	proofBY1 runar.Bigint,
	proofC runar.Point,
	g16Input0 runar.BigintBig,
	g16Input1 runar.BigintBig,
	g16Input2 runar.BigintBig,
	g16Input3 runar.BigintBig,
	g16Input4 runar.BigintBig,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// F08: range-check each BN254 scalar public input into [0, r). Applies
	// on the Upgrade path so a compromised governance set cannot use it to
	// sneak an unreduced scalar past the differential-oracle barrier. R4c:
	// BigintBigLess runs value comparison in the Go-mock over the real
	// 254-bit r instead of a truncated int64 placeholder.
	runar.Assert(runar.BigintBigLess(g16Input0, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input1, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input2, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input3, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input4, c.Bn254ScalarOrder))

	// F01: bind the SP1 public inputs on the Upgrade path too, so a
	// compromised governance set cannot tunnel a proof for a different
	// SP1 guest program via Upgrade. R4c: BigintBigEqual is value-equality
	// matching Script OP_NUMEQUAL.
	runar.Assert(runar.BigintBigEqual(g16Input0, c.SP1ProgramVkHashScalar))
	runar.Assert(runar.BigintBigEqual(g16Input1, reducePublicValuesToScalar(c, publicValues)))
	runar.Assert(runar.BigintBigEqual(g16Input2, c.Bn254Zero))
	runar.Assert(runar.BigintBigEqual(g16Input4, c.Bn254Zero))

	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulBigP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC5, g16Input4))
	runar.Assert(runar.Bn254G1OnCurveP(proofA))
	runar.Assert(runar.Bn254G1OnCurveP(proofC))
	runar.Assert(runar.Bn254G1OnCurveP(preparedInputs))
	negA := runar.Bn254G1NegateP(proofA)
	negBetaY0 := runar.Bn254FieldNegP(c.BetaG2Y0)
	negBetaY1 := runar.Bn254FieldNegP(c.BetaG2Y1)
	runar.Assert(runar.Bn254MultiPairing4(
		negA, proofBX0, proofBX1, proofBY0, proofBY1,
		preparedInputs, c.GammaG2X0, c.GammaG2X1, c.GammaG2Y0, c.GammaG2Y1,
		proofC, c.DeltaG2X0, c.DeltaG2X1, c.DeltaG2Y0, c.DeltaG2Y1,
		c.AlphaG1, c.BetaG2X0, c.BetaG2X1, negBetaY0, negBetaY1,
	))

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
	_ = proofBlob
}

// UpgradeMultiSig2 upgrades the covenant under 2-of-3 multisig governance.
func (c *Groth16RollupContract) UpgradeMultiSig2(
	sig1 runar.Sig,
	sig2 runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	proofA runar.Point,
	proofBX0 runar.Bigint,
	proofBX1 runar.Bigint,
	proofBY0 runar.Bigint,
	proofBY1 runar.Bigint,
	proofC runar.Point,
	g16Input0 runar.BigintBig,
	g16Input1 runar.BigintBig,
	g16Input2 runar.BigintBig,
	g16Input3 runar.BigintBig,
	g16Input4 runar.BigintBig,
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

	// F08: range-check each BN254 scalar public input into [0, r). R4c:
	// BigintBigLess runs value comparison in the Go-mock over the real
	// 254-bit r.
	runar.Assert(runar.BigintBigLess(g16Input0, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input1, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input2, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input3, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input4, c.Bn254ScalarOrder))

	// F01: bind the SP1 public inputs on the Upgrade path too, so a
	// compromised governance set cannot tunnel a proof for a different
	// SP1 guest program via Upgrade. R4c: BigintBigEqual is value-equality
	// matching Script OP_NUMEQUAL.
	runar.Assert(runar.BigintBigEqual(g16Input0, c.SP1ProgramVkHashScalar))
	runar.Assert(runar.BigintBigEqual(g16Input1, reducePublicValuesToScalar(c, publicValues)))
	runar.Assert(runar.BigintBigEqual(g16Input2, c.Bn254Zero))
	runar.Assert(runar.BigintBigEqual(g16Input4, c.Bn254Zero))

	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulBigP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC5, g16Input4))
	runar.Assert(runar.Bn254G1OnCurveP(proofA))
	runar.Assert(runar.Bn254G1OnCurveP(proofC))
	runar.Assert(runar.Bn254G1OnCurveP(preparedInputs))
	negA := runar.Bn254G1NegateP(proofA)
	negBetaY0 := runar.Bn254FieldNegP(c.BetaG2Y0)
	negBetaY1 := runar.Bn254FieldNegP(c.BetaG2Y1)
	runar.Assert(runar.Bn254MultiPairing4(
		negA, proofBX0, proofBX1, proofBY0, proofBY1,
		preparedInputs, c.GammaG2X0, c.GammaG2X1, c.GammaG2Y0, c.GammaG2Y1,
		proofC, c.DeltaG2X0, c.DeltaG2X1, c.DeltaG2Y0, c.DeltaG2Y1,
		c.AlphaG1, c.BetaG2X0, c.BetaG2X1, negBetaY0, negBetaY1,
	))

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
	_ = proofBlob
}

// UpgradeMultiSig3 upgrades the covenant under 3-of-3 multisig governance.
func (c *Groth16RollupContract) UpgradeMultiSig3(
	sig1 runar.Sig,
	sig2 runar.Sig,
	sig3 runar.Sig,
	newCovenantScript runar.ByteString,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	proofA runar.Point,
	proofBX0 runar.Bigint,
	proofBX1 runar.Bigint,
	proofBY0 runar.Bigint,
	proofBY1 runar.Bigint,
	proofC runar.Point,
	g16Input0 runar.BigintBig,
	g16Input1 runar.BigintBig,
	g16Input2 runar.BigintBig,
	g16Input3 runar.BigintBig,
	g16Input4 runar.BigintBig,
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

	// F08: range-check each BN254 scalar public input into [0, r). R4c:
	// BigintBigLess runs value comparison in the Go-mock over the real
	// 254-bit r.
	runar.Assert(runar.BigintBigLess(g16Input0, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input1, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input2, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input3, c.Bn254ScalarOrder))
	runar.Assert(runar.BigintBigLess(g16Input4, c.Bn254ScalarOrder))

	// F01: bind the SP1 public inputs on the Upgrade path too, so a
	// compromised governance set cannot tunnel a proof for a different
	// SP1 guest program via Upgrade. R4c: BigintBigEqual is value-equality
	// matching Script OP_NUMEQUAL.
	runar.Assert(runar.BigintBigEqual(g16Input0, c.SP1ProgramVkHashScalar))
	runar.Assert(runar.BigintBigEqual(g16Input1, reducePublicValuesToScalar(c, publicValues)))
	runar.Assert(runar.BigintBigEqual(g16Input2, c.Bn254Zero))
	runar.Assert(runar.BigintBigEqual(g16Input4, c.Bn254Zero))

	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulBigP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulBigP(c.IC5, g16Input4))
	runar.Assert(runar.Bn254G1OnCurveP(proofA))
	runar.Assert(runar.Bn254G1OnCurveP(proofC))
	runar.Assert(runar.Bn254G1OnCurveP(preparedInputs))
	negA := runar.Bn254G1NegateP(proofA)
	negBetaY0 := runar.Bn254FieldNegP(c.BetaG2Y0)
	negBetaY1 := runar.Bn254FieldNegP(c.BetaG2Y1)
	runar.Assert(runar.Bn254MultiPairing4(
		negA, proofBX0, proofBX1, proofBY0, proofBY1,
		preparedInputs, c.GammaG2X0, c.GammaG2X1, c.GammaG2Y0, c.GammaG2Y1,
		proofC, c.DeltaG2X0, c.DeltaG2X1, c.DeltaG2Y0, c.DeltaG2Y1,
		c.AlphaG1, c.BetaG2X0, c.BetaG2X1, negBetaY0, negBetaY1,
	))

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
	_ = proofBlob
}
