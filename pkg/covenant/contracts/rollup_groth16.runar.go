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

// AdvanceState advances the covenant state with a Groth16-verified proof.
// Invariants enforced (in order):
//  1. Shard must not be frozen.
//  2. New block number must be exactly previous + 1.
//  3. Groth16 BN254 pairing check: prepared_inputs = IC0 + sum(input[i]*IC[i+1])
//     over the 5 SP1 public inputs, followed by the 4-pairing product
//     e(-A, B) * e(prepared_inputs, gamma) * e(C, delta) * e(alpha, -beta) == 1.
//  4. proofBlobHash at public values offset 64 must equal hash256(proofBlob).
//  5. Public values offsets 0/32/104/136 must match StateRoot / newStateRoot
//     / hash256(batchData) / ChainId (little-endian 8 bytes) respectively.
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
	// SP1 Groth16 has 5 public inputs (BN254 scalar field elements)
	g16Input0 runar.Bigint,
	g16Input1 runar.Bigint,
	g16Input2 runar.Bigint,
	g16Input3 runar.Bigint,
	g16Input4 runar.Bigint,
) {
	// 0. Reject if shard is frozen by governance.
	runar.Assert(c.Frozen == 0)

	// 1. Block number must be exactly previous + 1.
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// 2. Groth16: BN254 pairing verification with 5-input MSM.
	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC5, g16Input4))
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
	g16Input0 runar.Bigint,
	g16Input1 runar.Bigint,
	g16Input2 runar.Bigint,
	g16Input3 runar.Bigint,
	g16Input4 runar.Bigint,
	newBlockNumber runar.Bigint,
) {
	runar.Assert(c.Frozen == 1)
	runar.Assert(c.GovernanceMode == 1)
	runar.Assert(runar.CheckSig(sig, c.GovernanceKey))

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC5, g16Input4))
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
	g16Input0 runar.Bigint,
	g16Input1 runar.Bigint,
	g16Input2 runar.Bigint,
	g16Input3 runar.Bigint,
	g16Input4 runar.Bigint,
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

	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC5, g16Input4))
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
	g16Input0 runar.Bigint,
	g16Input1 runar.Bigint,
	g16Input2 runar.Bigint,
	g16Input3 runar.Bigint,
	g16Input4 runar.Bigint,
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

	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulP(c.IC1, g16Input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC2, g16Input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC3, g16Input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC4, g16Input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC5, g16Input4))
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
