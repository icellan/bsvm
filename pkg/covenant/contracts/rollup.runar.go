package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// RollupContract is the stateful UTXO chain covenant that guards the L2 state
// root on BSV. Each spend advances the state by providing a new state root,
// block number, public values blob, batch data, and proof data.
//
// Two on-chain verification paths:
//   - Basefold (mode 0): KoalaBear field arithmetic + Poseidon2 Merkle checks
//   - Groth16  (mode 1): BN254 pairing verification of a 256-byte wrapped proof
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - StateRoot:   32-byte hash of current state
//   - BlockNumber: monotonically increasing block counter
//   - Frozen:      0 = active, 1 = frozen by governance
//
// Readonly properties (baked into locking script at compile time):
//   - VerifyingKeyHash:  commitment hash (Basefold mode) or SP1 VK hash
//   - ChainId:           shard chain ID for cross-shard replay prevention
//   - GovernanceKey:     public key authorized for freeze/unfreeze
//   - VerificationMode:  0 = Basefold, 1 = Groth16
//
// Groth16 VK readonly properties (only used in Groth16 mode):
//   - AlphaG1:           alpha element of Groth16 VK (G1 point)
//   - BetaG2X0..Y1:      beta element of VK (G2 point, 4 Fp components)
//   - GammaG2X0..Y1:     gamma element of VK (G2 point, 4 Fp components)
//   - DeltaG2X0..Y1:     delta element of VK (G2 point, 4 Fp components)
//   - IC0..IC5:          public input linearization points (G1)
type RollupContract struct {
	runar.StatefulSmartContract

	// ---- Mutable state ----
	StateRoot   runar.ByteString // 32-byte hash of current state
	BlockNumber runar.Bigint     // monotonically increasing block counter
	Frozen      runar.Bigint     // 0=active, 1=frozen by governance

	// ---- Readonly: shared properties ----
	VerifyingKeyHash runar.ByteString `runar:"readonly"` // SP1 VK hash (Basefold) or Groth16 VK hash
	ChainId          runar.Bigint     `runar:"readonly"` // shard chain ID
	VerificationMode runar.Bigint     `runar:"readonly"` // 0=Basefold, 1=Groth16

	// ---- Readonly: governance properties ----
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

// AdvanceState advances the covenant state with verified proof data.
//
// Parameters vary by verification mode:
//   - Basefold: proofFieldA/B/C, merkleLeaf, merkleProof, merkleIndex
//   - Groth16:  proofA (G1), proofBX0..Y1 (G2), proofC (G1), 5 public inputs
func (c *RollupContract) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	publicValues runar.ByteString,
	batchData runar.ByteString,
	proofBlob runar.ByteString,
	// Basefold proof elements
	proofFieldA runar.Bigint,
	proofFieldB runar.Bigint,
	proofFieldC runar.Bigint,
	merkleLeaf runar.ByteString,
	merkleProof runar.ByteString,
	merkleIndex runar.Bigint,
	// Groth16 proof elements
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
	// 0. Reject if shard is frozen by governance
	runar.Assert(c.Frozen == 0)

	// 1. Block number must be exactly previous + 1
	runar.Assert(newBlockNumber == c.BlockNumber+1)

	// 2. Proof verification — branch on verification mode.
	if c.VerificationMode == 0 {
		// Basefold: KoalaBear field check + Poseidon2 Merkle verification.
		runar.Assert(runar.KbFieldMul(proofFieldA, proofFieldB) == proofFieldC)
		computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 20)
		runar.Assert(computedRoot == c.VerifyingKeyHash)
	} else {
		// Groth16: BN254 pairing verification with 5-input MSM.
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
	}

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

// Freeze allows the governance key holder(s) to freeze the shard, blocking
// all AdvanceState calls until unfrozen.
//   - GovernanceMode 1 (single_key): only sig1 checked against GovernanceKey
//   - GovernanceMode 2 (multisig): CheckMultiSig with M-of-3 keys
//   - GovernanceMode 0 (none): GovernanceKey is zeros, CheckSig always fails
func (c *RollupContract) Freeze(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
	runar.Assert(c.Frozen == 0)
	if c.GovernanceMode == 1 {
		runar.Assert(runar.CheckSig(sig1, c.GovernanceKey))
	} else if c.GovernanceMode == 2 {
		if c.GovernanceThreshold == 2 {
			runar.Assert(runar.CheckMultiSig(
				[]runar.Sig{sig1, sig2},
				[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
			))
		} else {
			runar.Assert(runar.CheckMultiSig(
				[]runar.Sig{sig1, sig2, sig3},
				[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
			))
		}
	} else {
		runar.Assert(runar.CheckSig(sig1, c.GovernanceKey))
	}
	c.Frozen = 1
}

// Unfreeze allows the governance key holder(s) to unfreeze the shard.
func (c *RollupContract) Unfreeze(sig1 runar.Sig, sig2 runar.Sig, sig3 runar.Sig) {
	runar.Assert(c.Frozen == 1)
	if c.GovernanceMode == 1 {
		runar.Assert(runar.CheckSig(sig1, c.GovernanceKey))
	} else if c.GovernanceMode == 2 {
		if c.GovernanceThreshold == 2 {
			runar.Assert(runar.CheckMultiSig(
				[]runar.Sig{sig1, sig2},
				[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
			))
		} else {
			runar.Assert(runar.CheckMultiSig(
				[]runar.Sig{sig1, sig2, sig3},
				[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
			))
		}
	} else {
		runar.Assert(runar.CheckSig(sig1, c.GovernanceKey))
	}
	c.Frozen = 0
}

// Upgrade allows the governance key holder(s) to replace the covenant script.
// The shard must be frozen first.
func (c *RollupContract) Upgrade(
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
	if c.GovernanceMode == 1 {
		runar.Assert(runar.CheckSig(sig1, c.GovernanceKey))
	} else if c.GovernanceMode == 2 {
		if c.GovernanceThreshold == 2 {
			runar.Assert(runar.CheckMultiSig(
				[]runar.Sig{sig1, sig2},
				[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
			))
		} else {
			runar.Assert(runar.CheckMultiSig(
				[]runar.Sig{sig1, sig2, sig3},
				[]runar.PubKey{c.GovernanceKey, c.GovernanceKey2, c.GovernanceKey3},
			))
		}
	} else {
		runar.Assert(runar.CheckSig(sig1, c.GovernanceKey))
	}

	runar.Assert(newBlockNumber == c.BlockNumber+1)

	if c.VerificationMode == 0 {
		runar.Assert(runar.KbFieldMul(proofFieldA, proofFieldB) == proofFieldC)
		computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 20)
		runar.Assert(computedRoot == c.VerifyingKeyHash)
	} else {
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
	}

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
}
