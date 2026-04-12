package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// SP1Groth16Verifier verifies an SP1 Groth16 proof over BN254 with 5 public
// inputs. This is a stateless contract (SmartContract, not StatefulSmartContract)
// designed for Gate 0 validation of the BN254 multi-pairing check on BSV.
//
// SP1's Groth16 circuit has 5 public inputs:
//   [0] vkeyHash — hash of the SP1 guest program verifying key
//   [1] committedValuesDigest — hash of the public values committed by the guest
//   [2] exitCode — guest exit status (0 = success)
//   [3] proofNonce — replay prevention nonce
//   [4] vkRoot — Merkle root of verification keys (0 for single-program proofs)
//
// The verification equation checks:
//   e(-A, B) * e(prepared_inputs, gamma) * e(C, delta) * e(alpha, -beta) == 1
// where prepared_inputs = IC0 + sum(input[i] * IC[i+1]) for i=0..4.
type SP1Groth16Verifier struct {
	runar.SmartContract

	// Verification key (baked into locking script at compile time)
	AlphaG1    runar.Point  `runar:"readonly"`
	BetaG2X0   runar.Bigint `runar:"readonly"`
	BetaG2X1   runar.Bigint `runar:"readonly"`
	BetaG2Y0   runar.Bigint `runar:"readonly"`
	BetaG2Y1   runar.Bigint `runar:"readonly"`
	GammaG2X0  runar.Bigint `runar:"readonly"`
	GammaG2X1  runar.Bigint `runar:"readonly"`
	GammaG2Y0  runar.Bigint `runar:"readonly"`
	GammaG2Y1  runar.Bigint `runar:"readonly"`
	DeltaG2X0  runar.Bigint `runar:"readonly"`
	DeltaG2X1  runar.Bigint `runar:"readonly"`
	DeltaG2Y0  runar.Bigint `runar:"readonly"`
	DeltaG2Y1  runar.Bigint `runar:"readonly"`
	IC0        runar.Point  `runar:"readonly"`
	IC1        runar.Point  `runar:"readonly"`
	IC2        runar.Point  `runar:"readonly"`
	IC3        runar.Point  `runar:"readonly"`
	IC4        runar.Point  `runar:"readonly"`
	IC5        runar.Point  `runar:"readonly"`
}

// Verify checks an SP1 Groth16 proof with 5 public inputs.
func (c *SP1Groth16Verifier) Verify(
	proofA runar.Point,
	proofBX0 runar.Bigint,
	proofBX1 runar.Bigint,
	proofBY0 runar.Bigint,
	proofBY1 runar.Bigint,
	proofC runar.Point,
	input0 runar.Bigint,
	input1 runar.Bigint,
	input2 runar.Bigint,
	input3 runar.Bigint,
	input4 runar.Bigint,
) {
	// Step 1: Multi-scalar multiplication for public input linearization.
	// prepared_inputs = IC0 + input[0]*IC1 + input[1]*IC2 + input[2]*IC3 + input[3]*IC4 + input[4]*IC5
	preparedInputs := runar.Bn254G1AddP(c.IC0, runar.Bn254G1ScalarMulP(c.IC1, input0))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC2, input1))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC3, input2))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC4, input3))
	preparedInputs = runar.Bn254G1AddP(preparedInputs, runar.Bn254G1ScalarMulP(c.IC5, input4))

	// Step 2: Verify G1 points are on the BN254 curve (y^2 = x^3 + 3).
	runar.Assert(runar.Bn254G1OnCurveP(proofA))
	runar.Assert(runar.Bn254G1OnCurveP(proofC))
	runar.Assert(runar.Bn254G1OnCurveP(preparedInputs))

	// Step 3: Negate proof.A for the first pairing: e(-A, B).
	negA := runar.Bn254G1NegateP(proofA)

	// Step 4: Negate beta Y for the fourth pairing: e(alpha, -beta).
	negBetaY0 := runar.Bn254FieldNegP(c.BetaG2Y0)
	negBetaY1 := runar.Bn254FieldNegP(c.BetaG2Y1)

	// Step 5: Verify 4-pairing product equals 1 in GT (Fp12).
	// e(-A, B) * e(prepared_inputs, gamma) * e(C, delta) * e(alpha, -beta) == 1
	runar.Assert(runar.Bn254MultiPairing4(
		negA, proofBX0, proofBX1, proofBY0, proofBY1,
		preparedInputs, c.GammaG2X0, c.GammaG2X1, c.GammaG2Y0, c.GammaG2Y1,
		proofC, c.DeltaG2X0, c.DeltaG2X1, c.DeltaG2Y0, c.DeltaG2Y1,
		c.AlphaG1, c.BetaG2X0, c.BetaG2X1, negBetaY0, negBetaY1,
	))
}
