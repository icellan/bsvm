package covenant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
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
	Mode                VerificationMode // Which rollup contract was compiled
}

// Groth16VK holds the decomposed Groth16 verification key components for
// BN254 pairing verification. Each G2 point is decomposed into 4 Fp field
// elements (Fp2 coordinates: x = x0 + x1*u, y = y0 + y1*u).
// G1 points are 64-byte uncompressed affine points (32-byte x || 32-byte y).
type Groth16VK struct {
	AlphaG1 []byte    // 64 bytes: G1 point (alpha)
	BetaG2  [4][]byte // [x0, x1, y0, y1] — each 32 bytes
	GammaG2 [4][]byte // [x0, x1, y0, y1]
	DeltaG2 [4][]byte // [x0, x1, y0, y1]
	IC0     []byte    // 64 bytes: G1 point (CONSTANT in SP1 verifier)
	IC1     []byte    // 64 bytes: G1 point (PUB_0)
	IC2     []byte    // 64 bytes: G1 point (PUB_1)
	IC3     []byte    // 64 bytes: G1 point (PUB_2)
	IC4     []byte    // 64 bytes: G1 point (PUB_3)
	IC5     []byte    // 64 bytes: G1 point (PUB_4)
}

// CompileBasefoldRollup compiles the Basefold-only rollup covenant contract.
//
// The Basefold variant verifies SP1 proofs natively on-chain using KoalaBear
// field arithmetic plus a Poseidon2 Merkle inclusion proof. No trusted setup
// is required. Larger proof and larger script than the Groth16 variant.
//
// The sp1VerifyingKey, chainID, and governanceConfig are parameterized as
// readonly properties on the contract via ConstructorArgs. The Rúnar
// compiler bakes these into the locking script as compile-time constants.
func CompileBasefoldRollup(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) (*CompiledCovenant, error) {
	if err := governanceConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid governance config: %w", err)
	}
	if len(sp1VerifyingKey) == 0 {
		return nil, fmt.Errorf("sp1 verifying key must not be empty")
	}
	if chainID == 0 {
		return nil, fmt.Errorf("chain ID must not be zero")
	}

	contractPath := findBasefoldContractSource()
	args := buildBasefoldConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)

	return compileRollupContract(contractPath, args, "", sp1VerifyingKey, chainID, governanceConfig, VerifyBasefold)
}

// CompileGroth16Rollup compiles the Groth16-generic rollup covenant contract.
//
// The Groth16 variant verifies SP1 proofs on-chain via a BN254 multi-pairing
// check against a baked-in Groth16 verification key. SP1 wraps the STARK into
// a ~256 byte Groth16 proof. Requires trusted setup. groth16VK must be
// non-nil — every VK component is baked into the locking script as a
// compile-time constant.
func CompileGroth16Rollup(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, vk *Groth16VK) (*CompiledCovenant, error) {
	if err := governanceConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid governance config: %w", err)
	}
	if len(sp1VerifyingKey) == 0 {
		return nil, fmt.Errorf("sp1 verifying key must not be empty")
	}
	if chainID == 0 {
		return nil, fmt.Errorf("chain ID must not be zero")
	}
	if vk == nil {
		return nil, fmt.Errorf("groth16 VK must be provided when using Groth16 verification mode")
	}

	contractPath := findGroth16ContractSource()
	args := buildGroth16ConstructorArgs(sp1VerifyingKey, chainID, governanceConfig, vk)

	return compileRollupContract(contractPath, args, "", sp1VerifyingKey, chainID, governanceConfig, VerifyGroth16)
}

// CompileGroth16WARollup compiles the witness-assisted Groth16 rollup
// covenant contract ("Mode 3"). It routes through the Rúnar Go compiler
// with CompileOptions.Groth16WAVKey set, which causes any method that
// begins with runar.AssertGroth16WitnessAssisted() (i.e. AdvanceState) to
// have the BN254 Groth16 verifier inlined as a method-entry preamble with
// the SP1 VK baked in as pushdata.
//
// vkJSONPath MUST be the absolute path to a SP1-format vk.json file
// (schema matches tests/sp1/sp1_groth16_vk.json). Passing an empty path
// causes the compiler to reject AssertGroth16WitnessAssisted at stack
// lowering time — validate before calling.
//
// Unlike CompileGroth16Rollup, no Groth16VK readonly fields are populated
// on the contract — the VK is emitted as pushdata by the witness-assisted
// preamble, not as readonly constructor args.
func CompileGroth16WARollup(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, vkJSONPath string) (*CompiledCovenant, error) {
	if err := governanceConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid governance config: %w", err)
	}
	if len(sp1VerifyingKey) == 0 {
		return nil, fmt.Errorf("sp1 verifying key must not be empty")
	}
	if chainID == 0 {
		return nil, fmt.Errorf("chain ID must not be zero")
	}
	if vkJSONPath == "" {
		return nil, fmt.Errorf("groth16 WA vk.json path must be provided when using Groth16WA verification mode")
	}
	if _, err := os.Stat(vkJSONPath); err != nil {
		return nil, fmt.Errorf("groth16 WA vk.json not readable at %q: %w", vkJSONPath, err)
	}

	contractPath := findGroth16WAContractSource()
	args := buildGroth16WAConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)

	return compileRollupContract(contractPath, args, vkJSONPath, sp1VerifyingKey, chainID, governanceConfig, VerifyGroth16WA)
}

// compileRollupContract drives the Rúnar Go pipeline for one of the split
// rollup contracts and assembles the resulting CompiledCovenant metadata.
// groth16WAVKPath, when non-empty, is forwarded to the Rúnar compiler as
// CompileOptions.Groth16WAVKey so the witness-assisted Groth16 preamble
// emitter can bake the SP1 VK into the locking script.
func compileRollupContract(
	contractPath string,
	args map[string]interface{},
	groth16WAVKPath string,
	sp1VerifyingKey []byte,
	chainID uint64,
	governanceConfig GovernanceConfig,
	mode VerificationMode,
) (*CompiledCovenant, error) {
	artifact, err := gocompiler.CompileFromSource(contractPath, gocompiler.CompileOptions{
		ConstructorArgs: args,
		Groth16WAVKey:   groth16WAVKPath,
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
	vkHash := sha256.Sum256(sp1VerifyingKey)

	return &CompiledCovenant{
		LockingScript:       scriptBytes,
		ANF:                 anfJSON,
		StateSize:           len(artifact.StateFields),
		ScriptHash:          scriptHash,
		SP1VerifyingKeyHash: vkHash,
		ChainID:             chainID,
		GovernanceConfig:    governanceConfig,
		Mode:                mode,
	}, nil
}

// buildSharedConstructorArgs fills in the readonly properties that the
// Basefold and Groth16 variants have in common: the SP1 verifying key hash,
// the chain ID, and the governance configuration (mode, threshold, keys).
// Both contracts use the camelCase property names produced by the Rúnar Go
// parser from the struct field names.
func buildSharedConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) map[string]interface{} {
	vkHash := sha256.Sum256(sp1VerifyingKey)

	args := map[string]interface{}{
		"sP1VerifyingKeyHash": hex.EncodeToString(vkHash[:]),
		"chainId":             float64(chainID),
		"governanceMode":      float64(governanceConfig.Mode),
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

	return args
}

// buildBasefoldConstructorArgs creates the ConstructorArgs map for the
// Basefold rollup contract. Only the shared readonly fields are populated —
// the Basefold variant has no mode-specific readonly properties.
func buildBasefoldConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) map[string]interface{} {
	return buildSharedConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)
}

// buildGroth16ConstructorArgs creates the ConstructorArgs map for the
// Groth16 rollup contract. It populates the shared readonly fields plus
// the 19 Groth16 verification key components.
//
// Encoding rules (must match the Rúnar Go compiler's
// options.applyConstructorArgs / codegen.pushPropertyValue dispatch):
//
//   - Point fields (AlphaG1, IC0..IC5) are runar.Point = ByteString on the
//     contract side and are passed as hex strings so the compiler emits a
//     raw 64-byte push (OP_PUSHDATA).
//   - Bigint fields (BetaG2*, GammaG2*, DeltaG2*) are runar.Bigint on the
//     contract side and MUST be passed as *big.Int. The compiler emits
//     them via encodePushBigInt, producing the little-endian sign-magnitude
//     Bitcoin Script number encoding that BN254 field operations
//     (Bn254G1ScalarMulP, Bn254MultiPairing4) read at runtime.
//
// Passing the Fp field elements as hex strings would silently compile but
// push a 32-byte big-endian blob instead of a LE-SM script number, causing
// BN254 arithmetic to read the wrong field value. This bug is invisible for
// zero-valued placeholders (both encodings resolve to OP_0) but fatal for
// real SP1 verification keys — which is why the Mode 2 tests stayed red
// until this loader started passing *big.Int.
func buildGroth16ConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, vk *Groth16VK) map[string]interface{} {
	args := buildSharedConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)

	args["alphaG1"] = hex.EncodeToString(vk.AlphaG1)
	args["betaG2X0"] = bytesToBigInt(vk.BetaG2[0])
	args["betaG2X1"] = bytesToBigInt(vk.BetaG2[1])
	args["betaG2Y0"] = bytesToBigInt(vk.BetaG2[2])
	args["betaG2Y1"] = bytesToBigInt(vk.BetaG2[3])
	args["gammaG2X0"] = bytesToBigInt(vk.GammaG2[0])
	args["gammaG2X1"] = bytesToBigInt(vk.GammaG2[1])
	args["gammaG2Y0"] = bytesToBigInt(vk.GammaG2[2])
	args["gammaG2Y1"] = bytesToBigInt(vk.GammaG2[3])
	args["deltaG2X0"] = bytesToBigInt(vk.DeltaG2[0])
	args["deltaG2X1"] = bytesToBigInt(vk.DeltaG2[1])
	args["deltaG2Y0"] = bytesToBigInt(vk.DeltaG2[2])
	args["deltaG2Y1"] = bytesToBigInt(vk.DeltaG2[3])
	args["iC0"] = hex.EncodeToString(vk.IC0)
	args["iC1"] = hex.EncodeToString(vk.IC1)
	args["iC2"] = hex.EncodeToString(vk.IC2)
	args["iC3"] = hex.EncodeToString(vk.IC3)
	args["iC4"] = hex.EncodeToString(vk.IC4)
	args["iC5"] = hex.EncodeToString(vk.IC5)

	return args
}

// bytesToBigInt interprets a big-endian byte slice as a non-negative
// *big.Int. Nil or empty input returns a zero-valued *big.Int. Used to
// convert the 32-byte Fp coordinate storage in Groth16VK into the
// *big.Int form expected by the Rúnar compiler for Bigint constructor
// args.
func bytesToBigInt(b []byte) *big.Int {
	if len(b) == 0 {
		return new(big.Int)
	}
	return new(big.Int).SetBytes(b)
}

// buildGroth16WAConstructorArgs creates the ConstructorArgs map for the
// witness-assisted Groth16 rollup contract. Only the shared readonly fields
// are populated — the BN254 verifying key is baked by the witness-assisted
// preamble emitter at compile time via CompileOptions.Groth16WAVKey, not
// as readonly constructor args. This is why the Mode 3 contract has no
// Groth16VK readonly fields on its struct.
func buildGroth16WAConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) map[string]interface{} {
	return buildSharedConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)
}

// findBasefoldContractSource locates the Basefold rollup source file.
func findBasefoldContractSource() string {
	return findContractSourceNamed("rollup_basefold.runar.go")
}

// findGroth16ContractSource locates the Groth16 rollup source file.
func findGroth16ContractSource() string {
	return findContractSourceNamed("rollup_groth16.runar.go")
}

// findGroth16WAContractSource locates the witness-assisted Groth16 rollup
// source file (Mode 3).
func findGroth16WAContractSource() string {
	return findContractSourceNamed("rollup_groth16_wa.runar.go")
}

// findContractSourceNamed locates the named contract source file relative
// to this package's source directory.
func findContractSourceNamed(name string) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(thisFile)
		candidate := filepath.Join(dir, "contracts", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fallback: try relative to working directory.
	return filepath.Join("pkg", "covenant", "contracts", name)
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
