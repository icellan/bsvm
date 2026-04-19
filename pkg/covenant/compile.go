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

// CompileFRIRollup compiles the Mode 1 rollup covenant contract (trust-
// minimized FRI bridge).
//
// Mode 1 does NOT verify the SP1 FRI proof on-chain. The covenant binds
// state transitions (block+1, state roots, batch hash, chain id) via
// public-value offset checks and emits the spec-12 OP_RETURN batch-data
// output, but performs no STARK arithmetic. Off-chain nodes verify the
// proof and trigger governance freeze on an invalid advance. See
// rollup_fri.runar.go for the full security model and Gate 0a Full
// upgrade path. Mode 1 is NOT mainnet-eligible — PrepareGenesis rejects
// Mainnet=true with VerifyFRI.
//
// The sp1VerifyingKey, chainID, and governanceConfig are parameterized as
// readonly properties on the contract via ConstructorArgs. The Rúnar
// compiler bakes these into the locking script as compile-time constants.
// SP1VerifyingKeyHash is recorded as a readonly property for indexing and
// future-upgrade continuity; the Mode 1 locking script does not consult
// it because there is no on-chain proof check.
func CompileFRIRollup(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) (*CompiledCovenant, error) {
	if err := governanceConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid governance config: %w", err)
	}
	if len(sp1VerifyingKey) == 0 {
		return nil, fmt.Errorf("sp1 verifying key must not be empty")
	}
	if chainID == 0 {
		return nil, fmt.Errorf("chain ID must not be zero")
	}

	contractPath := findFRIContractSource()
	args, err := buildFRIConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)
	if err != nil {
		return nil, fmt.Errorf("building FRI constructor args: %w", err)
	}

	return compileRollupContract(contractPath, args, "", sp1VerifyingKey, chainID, governanceConfig, VerifyFRI)
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
	args, err := buildGroth16ConstructorArgs(sp1VerifyingKey, chainID, governanceConfig, vk)
	if err != nil {
		return nil, fmt.Errorf("building groth16 constructor args: %w", err)
	}

	return compileRollupContract(contractPath, args, "", sp1VerifyingKey, chainID, governanceConfig, VerifyGroth16)
}

// CompileGroth16WARollup compiles the Mode 3 witness-assisted Groth16
// rollup contract with the VK's sha256 digest NOT pinned. This is the
// historical entry point; it is equivalent to
// CompileGroth16WARollupPinned(..., VKTrustPolicyAllowUnpinned) and must
// NOT be used to produce a mainnet locking script. Use
// CompileGroth16WARollupPinned with VKTrustPolicyMainnet for any shard
// that will hold real funds.
func CompileGroth16WARollup(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, vkJSONPath string) (*CompiledCovenant, error) {
	return CompileGroth16WARollupPinned(sp1VerifyingKey, chainID, governanceConfig, vkJSONPath, VKTrustPolicyAllowUnpinned)
}

// CompileGroth16WARollupPinned compiles the Mode 3 witness-assisted
// Groth16 rollup contract AND enforces a VK trust policy (F06). It
// routes through the Rúnar Go compiler with CompileOptions.Groth16WAVKey
// set, which causes any method that begins with
// runar.AssertGroth16WitnessAssisted() (i.e. AdvanceState) to have the
// BN254 Groth16 verifier inlined as a method-entry preamble with the
// SP1 VK baked in as pushdata.
//
// vkJSONPath MUST be the absolute path to a SP1-format vk.json file
// (schema matches tests/sp1/sp1_groth16_vk.json). The VK bytes are
// sha256'd and compared against PinnedSP1Groth16VKHashes per the given
// policy; a mismatch fails the compile before any Rúnar work happens.
//
// Unlike CompileGroth16Rollup, no Groth16VK readonly fields are populated
// on the contract — the VK is emitted as pushdata by the witness-assisted
// preamble, not as readonly constructor args.
func CompileGroth16WARollupPinned(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, vkJSONPath string, policy VKTrustPolicy) (*CompiledCovenant, error) {
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
	// F06: verify the VK sha256 matches the pinned allowlist for the
	// active policy BEFORE handing the path to Rúnar.
	if err := VerifyPinnedVKHash(vkJSONPath, policy); err != nil {
		return nil, fmt.Errorf("compile: groth16 WA vk.json failed pinning check: %w", err)
	}

	contractPath := findGroth16WAContractSource()
	args, err := buildGroth16WAConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)
	if err != nil {
		return nil, fmt.Errorf("building groth16 WA constructor args: %w", err)
	}

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
//
// F11 defence-in-depth: this helper re-validates the shape of the active
// governance key slots via assertGovernanceKeysShape before emitting them.
// GovernanceConfig.Validate() already rejects zero-prefixed and malformed
// keys, but a future refactor that forgets to call Validate must not
// silently produce a covenant whose CheckSig / CheckMultiSig slots carry
// zero pubkeys — that script would compile cleanly but never accept a
// signature, locking the shard's governance out forever.
func buildSharedConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) (map[string]interface{}, error) {
	if err := assertGovernanceKeysShape(governanceConfig); err != nil {
		return nil, err
	}

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

	return args, nil
}

// assertGovernanceKeysShape verifies that the governance key slots that
// should hold a real compressed secp256k1 pubkey actually do, regardless
// of whether GovernanceConfig.Validate() was called first. This is a
// defence-in-depth check for F11 — it mirrors validateCompressedPubKey
// on each active slot and explicitly rejects zero-prefixed bytes that
// would otherwise be baked into the covenant as a dead CheckSig /
// CheckMultiSig target.
//
// Slot semantics (matches buildSharedConstructorArgs):
//   - GovernanceNone: all slots must be empty (len(Keys) == 0). Any key
//     present is a caller-side misuse.
//   - GovernanceSingleKey: slot 0 must be a valid 33-byte compressed
//     pubkey (prefix 0x02 / 0x03). Slots 1 and 2 are unused.
//   - GovernanceMultiSig: slots 0..len(Keys)-1 must each be valid
//     compressed pubkeys. Slots above len(Keys) stay as the zero
//     placeholder and are not checked.
func assertGovernanceKeysShape(governanceConfig GovernanceConfig) error {
	switch governanceConfig.Mode {
	case GovernanceNone:
		if len(governanceConfig.Keys) != 0 {
			return fmt.Errorf("governance mode none must have no keys, got %d", len(governanceConfig.Keys))
		}
		return nil

	case GovernanceSingleKey:
		if len(governanceConfig.Keys) != 1 {
			return fmt.Errorf("governance mode single_key requires exactly 1 key, got %d", len(governanceConfig.Keys))
		}
		if err := validateCompressedPubKey(governanceConfig.Keys[0]); err != nil {
			return fmt.Errorf("governance key slot 0 invalid: %w", err)
		}
		return nil

	case GovernanceMultiSig:
		if len(governanceConfig.Keys) < 2 {
			return fmt.Errorf("governance mode multisig requires at least 2 keys, got %d", len(governanceConfig.Keys))
		}
		if len(governanceConfig.Keys) > 3 {
			return fmt.Errorf("governance mode multisig supports at most 3 keys, got %d", len(governanceConfig.Keys))
		}
		for i, key := range governanceConfig.Keys {
			if err := validateCompressedPubKey(key); err != nil {
				return fmt.Errorf("governance key slot %d invalid: %w", i, err)
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown governance mode %d", int(governanceConfig.Mode))
	}
}

// buildFRIConstructorArgs creates the ConstructorArgs map for the Mode 1
// FRI rollup contract. Only the shared readonly fields are populated —
// Mode 1 has no mode-specific readonly properties.
func buildFRIConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) (map[string]interface{}, error) {
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
func buildGroth16ConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig, vk *Groth16VK) (map[string]interface{}, error) {
	args, err := buildSharedConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)
	if err != nil {
		return nil, err
	}

	// F08: BN254 scalar field order r baked into the script so
	// AdvanceState and the Upgrade* variants can enforce
	// g16Input_i < r. Without this bound, an unreduced scalar would
	// pair-verify on-chain (EC scalar mul is periodic mod r) but be
	// ABI-rejected by SP1's Solidity / in-circuit reference verifiers,
	// breaking differential-oracle parity during fuzzing and
	// conformance testing. Passed as *big.Int so the Rúnar compiler
	// emits the LE sign-magnitude Bitcoin Script number encoding the
	// BN254 primitives expect.
	bn254ScalarOrder, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		10,
	)
	args["bn254ScalarOrder"] = bn254ScalarOrder

	// F01: SP1 public input bindings. SP1ProgramVkHashScalar is the
	// pinned vkey hash reduced into the scalar field; Bn254ScalarMask
	// (= 2^253) is used by the on-chain reducePublicValuesToScalar to
	// match SP1's committedValuesDigest convention.
	args["sP1ProgramVkHashScalar"] = ReduceSP1ProgramVkHashScalar(sp1VerifyingKey)
	args["bn254ScalarMask"] = SP1Bn254ScalarMask()

	// R4c: Bn254Zero is a BigintBig readonly used as the RHS of the F01
	// g16Input2 / g16Input4 equality assertions. Baked as a compile-time
	// constant (OP_0 in Script) rather than spelled inline because
	// *big.Int has no untyped-zero conversion in Go source.
	args["bn254Zero"] = big.NewInt(0)

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

	return args, nil
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
// Mode 3 witness-assisted Groth16 rollup contract. Populates the shared
// readonly fields plus the three BN254-scalar domain-binding fields
// (F01 / F08):
//
//   - SP1ProgramVkHashScalar: sha256(sp1VerifyingKey) reduced into the
//     BN254 scalar field. Asserted equal to Groth16PublicInput(0) on
//     every advance.
//   - Bn254ScalarMask:        2^253, used by reducePublicValuesToScalarWA
//     to match SP1's committedValuesDigest convention.
//   - Bn254ScalarOrder:       r, used for F08 input range checks.
//
// The BN254 verifying key is baked by the witness-assisted preamble
// emitter at compile time via CompileOptions.Groth16WAVKey, not as
// readonly constructor args, so the Mode 3 contract still has no
// Groth16VK readonly fields on its struct.
func buildGroth16WAConstructorArgs(sp1VerifyingKey []byte, chainID uint64, governanceConfig GovernanceConfig) (map[string]interface{}, error) {
	args, err := buildSharedConstructorArgs(sp1VerifyingKey, chainID, governanceConfig)
	if err != nil {
		return nil, err
	}

	bn254ScalarOrder, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		10,
	)
	args["bn254ScalarOrder"] = bn254ScalarOrder
	args["sP1ProgramVkHashScalar"] = ReduceSP1ProgramVkHashScalar(sp1VerifyingKey)
	args["bn254ScalarMask"] = SP1Bn254ScalarMask()

	return args, nil
}

// findFRIContractSource locates the Mode 1 FRI rollup source file.
func findFRIContractSource() string {
	return findContractSourceNamed("rollup_fri.runar.go")
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
