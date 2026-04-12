package covenant

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
)

// VerifyANF checks that the ANF IR compiles to the expected locking script.
// This is used by nodes joining a shard to verify the covenant logic. The node
// receives the ANF IR (canonical JSON) from the genesis transaction and
// independently compiles it to verify the resulting script hash matches.
//
// The verification process:
//  1. Parse the ANF IR JSON
//  2. Compile it through the Runar pipeline (stack lowering, script emit)
//  3. Compute SHA256 of the resulting script
//  4. Compare against the expected script hash
func VerifyANF(anf []byte, expectedScriptHash [32]byte) error {
	if len(anf) == 0 {
		return fmt.Errorf("ANF IR must not be empty")
	}

	artifact, err := gocompiler.CompileFromIRBytes(anf)
	if err != nil {
		return fmt.Errorf("compiling ANF IR: %w", err)
	}

	scriptBytes, err := hexToBytes(artifact.Script)
	if err != nil {
		return fmt.Errorf("decoding compiled script hex: %w", err)
	}

	actualHash := sha256.Sum256(scriptBytes)
	if actualHash != expectedScriptHash {
		return fmt.Errorf("script hash mismatch: expected %x, got %x", expectedScriptHash, actualHash)
	}

	return nil
}

// VerifyANFJSON checks that the provided JSON bytes are valid ANF IR by
// parsing it into the ANFProgram structure.
func VerifyANFJSON(anf []byte) error {
	if len(anf) == 0 {
		return fmt.Errorf("ANF IR must not be empty")
	}

	var program struct {
		ContractName string `json:"contractName"`
	}
	if err := json.Unmarshal(anf, &program); err != nil {
		return fmt.Errorf("invalid ANF IR JSON: %w", err)
	}
	if program.ContractName == "" {
		return fmt.Errorf("ANF IR missing contract name")
	}

	return nil
}
