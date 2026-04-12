package covenant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
)

// CompiledCovenant holds the compiled covenant script and metadata.
type CompiledCovenant struct {
	LockingScript       []byte           // Compiled Bitcoin Script
	ANF                 []byte           // ANF IR (canonical JSON, for audit/verification)
	StateSize           int              // Number of state fields
	ScriptHash          [32]byte         // SHA256 of the locking script
	SP1VerifyingKeyHash [32]byte         // SHA256 of the SP1 verifying key (checked on-chain)
	ChainID             uint64           // Shard chain ID (readonly property)
	GovernanceConfig    GovernanceConfig // Governance configuration (readonly property)
}

// Groth16VK holds the decomposed Groth16 verification key components for
// BN254 pairing verification. Each G2 point is decomposed into 4 Fp field
// elements (Fp2 coordinates: x = x0 + x1*u, y = y0 + y1*u).
// G1 points are 64-byte uncompressed affine points (32-byte x || 32-byte y).
type Groth16VK struct {
	AlphaG1   []byte    // 64 bytes: G1 point (alpha)
	BetaG2    [4][]byte // [x0, x1, y0, y1] — each 32 bytes
	GammaG2   [4][]byte // [x0, x1, y0, y1]
	DeltaG2   [4][]byte // [x0, x1, y0, y1]
	IC0       []byte    // 64 bytes: G1 point (CONSTANT in SP1 verifier)
	IC1       []byte    // 64 bytes: G1 point (PUB_0)
	IC2       []byte    // 64 bytes: G1 point (PUB_1)
	IC3       []byte    // 64 bytes: G1 point (PUB_2)
	IC4       []byte    // 64 bytes: G1 point (PUB_3)
	IC5       []byte    // 64 bytes: G1 point (PUB_4)
}

// CompileCovenant compiles the rollup covenant contract with the given parameters.
// It reads the rollup.runar.go source file, compiles it through the Rúnar pipeline
// (parse, validate, typecheck, ANF lowering, stack lowering, script emit), and
// returns the compiled artifact.
//
// The sp1VerifyingKey, chainID, governanceConfig, and verificationMode are used
// to parameterize the contract's readonly properties via ConstructorArgs. The
// Rúnar compiler bakes these values into the locking script as compile-time
// constants, replacing OP_0 placeholders with real push data.
//
// verificationMode selects the on-chain proof verification strategy:
//   - VerifyGroth16: Uses the witness-assisted Groth16/BN254 verifier (~50-100 KB
//     script). SP1 wraps the STARK into a ~256 byte Groth16 proof. Recommended
//     for most shards. Requires groth16VK to be non-nil.
//   - VerifyBasefold: Native STARK verification using KoalaBear + Poseidon2 in
//     Script. Larger proof and script but no trusted setup. groth16VK may be nil.
func CompileCovenant(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, verificationMode VerificationMode, groth16VK *Groth16VK) (*CompiledCovenant, error) {
	// Validate all parameters before compilation.
	if err := governanceConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid governance config: %w", err)
	}
	if len(sp1VerifyingKey) == 0 {
		return nil, fmt.Errorf("sp1 verifying key must not be empty")
	}
	if chainID == 0 {
		return nil, fmt.Errorf("chain ID must not be zero")
	}
	if verificationMode == VerifyGroth16 && groth16VK == nil {
		return nil, fmt.Errorf("groth16 VK must be provided when using Groth16 verification mode")
	}

	contractPath := findContractSource()

	// Build constructor args to inject runtime parameters as compile-time
	// constants in the covenant script. Property names must match the
	// camelCase names produced by the Rúnar Go parser from the struct
	// field names in rollup.runar.go.
	args := buildConstructorArgs(sp1VerifyingKey, chainID, governanceConfig, verificationMode, groth16VK)

	artifact, err := gocompiler.CompileFromSource(contractPath, gocompiler.CompileOptions{
		ConstructorArgs: args,
	})
	if err != nil {
		return nil, fmt.Errorf("covenant compilation failed: %w", err)
	}

	scriptBytes, err := hexToBytes(artifact.Script)
	if err != nil {
		return nil, fmt.Errorf("decoding compiled script hex: %w", err)
	}

	var anfJSON []byte
	if artifact.ANF != nil {
		anfJSON, err = json.Marshal(artifact.ANF)
		if err != nil {
			return nil, fmt.Errorf("serializing ANF IR: %w", err)
		}
	}

	scriptHash := sha256.Sum256(scriptBytes)

	// Compute verifying key hash (what the covenant script checks against).
	vkHash := sha256.Sum256(sp1VerifyingKey)

	return &CompiledCovenant{
		LockingScript:       scriptBytes,
		ANF:                 anfJSON,
		StateSize:           len(artifact.StateFields),
		ScriptHash:          scriptHash,
		SP1VerifyingKeyHash: vkHash,
		ChainID:             chainID,
		GovernanceConfig:    governanceConfig,
	}, nil
}

// buildConstructorArgs creates the ConstructorArgs map for the Rúnar compiler.
// It maps readonly property names (camelCase, matching the Go parser output)
// to their values in the types the codegen expects:
//   - ByteString/PubKey properties: hex-encoded string
//   - Bigint properties: float64 (matching JSON number deserialization)
func buildConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, verificationMode VerificationMode, groth16VK *Groth16VK) map[string]interface{} {
	vkHash := sha256.Sum256(sp1VerifyingKey)

	args := map[string]interface{}{
		"verifyingKeyHash": hex.EncodeToString(vkHash[:]),
		"chainId":          float64(chainID),
		"governanceMode":   float64(governanceConfig.Mode),
		// Contract verification mode: 0 = Basefold, 1 = Groth16.
		// Our Go enum: VerifyGroth16 = 0, VerifyBasefold = 1.
		// Map to contract convention: Groth16 -> 1, Basefold -> 0.
		"verificationMode":    verificationModeToContract(verificationMode),
		"governanceThreshold": float64(governanceConfig.Threshold),
	}

	// Governance keys: up to 3 key slots. Unused slots are 33 zero bytes.
	// For none mode: all keys are zeros (CheckSig/CheckMultiSig always fails).
	// For single_key: GovernanceKey holds the key, Key2/Key3 are zeros.
	// For multisig: keys are distributed across GovernanceKey, Key2, Key3.
	zeroKey := hex.EncodeToString(make([]byte, 33))
	keys := [3]string{zeroKey, zeroKey, zeroKey}
	for i := 0; i < len(governanceConfig.Keys) && i < 3; i++ {
		keys[i] = hex.EncodeToString(governanceConfig.Keys[i])
	}
	args["governanceKey"] = keys[0]
	args["governanceKey2"] = keys[1]
	args["governanceKey3"] = keys[2]

	// Groth16 VK components — required when VerificationMode == Groth16.
	// Point type is ByteString (hex-encoded), Bigint fields use hex strings
	// for large BN254 field elements (> 2^53, cannot use float64).
	if groth16VK != nil {
		args["alphaG1"] = hex.EncodeToString(groth16VK.AlphaG1)
		args["betaG2X0"] = hex.EncodeToString(groth16VK.BetaG2[0])
		args["betaG2X1"] = hex.EncodeToString(groth16VK.BetaG2[1])
		args["betaG2Y0"] = hex.EncodeToString(groth16VK.BetaG2[2])
		args["betaG2Y1"] = hex.EncodeToString(groth16VK.BetaG2[3])
		args["gammaG2X0"] = hex.EncodeToString(groth16VK.GammaG2[0])
		args["gammaG2X1"] = hex.EncodeToString(groth16VK.GammaG2[1])
		args["gammaG2Y0"] = hex.EncodeToString(groth16VK.GammaG2[2])
		args["gammaG2Y1"] = hex.EncodeToString(groth16VK.GammaG2[3])
		args["deltaG2X0"] = hex.EncodeToString(groth16VK.DeltaG2[0])
		args["deltaG2X1"] = hex.EncodeToString(groth16VK.DeltaG2[1])
		args["deltaG2Y0"] = hex.EncodeToString(groth16VK.DeltaG2[2])
		args["deltaG2Y1"] = hex.EncodeToString(groth16VK.DeltaG2[3])
		args["iC0"] = hex.EncodeToString(groth16VK.IC0)
		args["iC1"] = hex.EncodeToString(groth16VK.IC1)
		args["iC2"] = hex.EncodeToString(groth16VK.IC2)
		args["iC3"] = hex.EncodeToString(groth16VK.IC3)
		args["iC4"] = hex.EncodeToString(groth16VK.IC4)
		args["iC5"] = hex.EncodeToString(groth16VK.IC5)
	} else {
		// Zero placeholders for Basefold mode. The compiler still needs all
		// readonly properties defined even if the Groth16 branch is dead code.
		zeroPoint := hex.EncodeToString(make([]byte, 64))
		zeroField := hex.EncodeToString(make([]byte, 32))
		args["alphaG1"] = zeroPoint
		args["betaG2X0"] = zeroField
		args["betaG2X1"] = zeroField
		args["betaG2Y0"] = zeroField
		args["betaG2Y1"] = zeroField
		args["gammaG2X0"] = zeroField
		args["gammaG2X1"] = zeroField
		args["gammaG2Y0"] = zeroField
		args["gammaG2Y1"] = zeroField
		args["deltaG2X0"] = zeroField
		args["deltaG2X1"] = zeroField
		args["deltaG2Y0"] = zeroField
		args["deltaG2Y1"] = zeroField
		args["iC0"] = zeroPoint
		args["iC1"] = zeroPoint
		args["iC2"] = zeroPoint
		args["iC3"] = zeroPoint
		args["iC4"] = zeroPoint
		args["iC5"] = zeroPoint
	}

	return args
}

// verificationModeToContract converts our Go VerificationMode enum to the
// contract's convention. Contract: 0 = Basefold, 1 = Groth16.
// Go enum: VerifyGroth16 = 0, VerifyBasefold = 1.
func verificationModeToContract(mode VerificationMode) float64 {
	switch mode {
	case VerifyGroth16:
		return 1 // contract: Groth16 = 1
	case VerifyBasefold:
		return 0 // contract: Basefold = 0
	default:
		return 1 // default to Groth16
	}
}

// findContractSource locates the rollup.runar.go source file relative to
// this package's source directory.
func findContractSource() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(thisFile)
		candidate := filepath.Join(dir, "contracts", "rollup.runar.go")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fallback: try relative to working directory.
	return filepath.Join("pkg", "covenant", "contracts", "rollup.runar.go")
}

// hexToBytes decodes a hex string to bytes. It handles the case where the
// hex string has no 0x prefix (standard compiler output).
func hexToBytes(hexStr string) ([]byte, error) {
	if len(hexStr) >= 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	b := make([]byte, len(hexStr)/2)
	for i := 0; i < len(b); i++ {
		high, err := hexDigit(hexStr[2*i])
		if err != nil {
			return nil, err
		}
		low, err := hexDigit(hexStr[2*i+1])
		if err != nil {
			return nil, err
		}
		b[i] = high<<4 | low
	}
	return b, nil
}

// hexDigit converts a single hex character to its value.
func hexDigit(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit: %c", c)
	}
}
