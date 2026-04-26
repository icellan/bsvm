// Helpers used by DeriveShardFromTx to locate the GenesisManifest
// OP_RETURN payload in the deploy transaction's outputs and to
// cross-validate the deployed locking script against the manifest by
// re-compiling the covenant with the manifest's claimed readonly
// inputs and comparing the resulting code section byte-for-byte
// against the deployed script.
//
// None of these helpers mutate state or touch the network.
package shard

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// findManifestPayload scans the transaction's outputs in order for an
// OP_FALSE OP_RETURN output whose first push starts with the
// GenesisManifestMagic prefix. Returns the pushed bytes (including the
// magic and length header — DecodeManifest expects the envelope).
//
// The deploy helper always places the manifest at vout 1, but we walk
// every output so future layouts with additional OP_RETURN outputs
// (e.g. operator-supplied metadata) don't break old nodes.
func findManifestPayload(tx *runar.TransactionData) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("manifest: tx must not be nil")
	}
	magic := []byte(GenesisManifestMagic)
	for i, out := range tx.Outputs {
		if i == 0 {
			// vout 0 is the covenant — skip.
			continue
		}
		scriptBytes, err := hex.DecodeString(out.Script)
		if err != nil {
			continue
		}
		// Expected prefix: OP_FALSE (0x00) OP_RETURN (0x6a).
		if len(scriptBytes) < 2 || scriptBytes[0] != 0x00 || scriptBytes[1] != 0x6a {
			continue
		}
		// Walk the push sequence after OP_FALSE OP_RETURN looking
		// for the magic.
		pos := 2
		for pos < len(scriptBytes) {
			op := scriptBytes[pos]
			pos++
			var dataLen int
			switch {
			case op >= 0x01 && op <= 0x4b:
				dataLen = int(op)
			case op == 0x4c: // OP_PUSHDATA1
				if pos+1 > len(scriptBytes) {
					break
				}
				dataLen = int(scriptBytes[pos])
				pos++
			case op == 0x4d: // OP_PUSHDATA2
				if pos+2 > len(scriptBytes) {
					break
				}
				dataLen = int(binary.LittleEndian.Uint16(scriptBytes[pos : pos+2]))
				pos += 2
			case op == 0x4e: // OP_PUSHDATA4
				if pos+4 > len(scriptBytes) {
					break
				}
				dataLen = int(binary.LittleEndian.Uint32(scriptBytes[pos : pos+4]))
				pos += 4
			default:
				dataLen = -1
			}
			if dataLen < 0 {
				break
			}
			if pos+dataLen > len(scriptBytes) {
				break
			}
			payload := scriptBytes[pos : pos+dataLen]
			pos += dataLen
			if bytes.HasPrefix(payload, magic) {
				return payload, nil
			}
		}
	}
	return nil, fmt.Errorf("manifest: no OP_RETURN output with magic %q found", GenesisManifestMagic)
}

// verifyCovenantCodeMatches re-compiles the covenant with the given
// (manifest-supplied) readonly inputs and compares the resulting code
// section — everything before the stateful OP_RETURN separator —
// against the code portion of the on-chain locking script. Any byte
// mismatch means the manifest lied about one or more readonly fields.
//
// The stateful portion (stateRoot, blockNumber, frozen) is not
// compared here because it depends on runtime state rather than
// manifest content; the caller verifies the genesis state root
// separately against InitGenesis.
//
// This check subsumes cross-validation of chainID, governance, and
// SP1 VK hash — all three are compile-time pushdata that go into
// the code section. It also catches any future readonly field that
// gets added to the covenant contract without requiring a bespoke
// extractor here.
//
// Implementation note: the production deploy path constructs the
// locking script via runar.NewRunarContract.GetLockingScript, which
// wraps the gocompiler output with a method-dispatch prelude. The
// bare CompileFRIRollup output doesn't include that wrapper, so we
// have to reproduce the runtime wrapper here by re-running the same
// SDK flow against the gocompiler artifact.
func verifyCovenantCodeMatches(mode covenant.VerificationMode, deployedScriptHex string, sp1VK []byte, chainID uint64, gov covenant.GovernanceConfig) error {
	artifact, err := recompileBakedArtifact(mode, sp1VK, chainID, gov)
	if err != nil {
		return fmt.Errorf("recompile: %w", err)
	}
	// Runtime state values for a fresh genesis: stateRoot can be
	// anything (we only care about the code section); blockNumber
	// and frozen must be 0. We pass a dummy stateRoot because
	// GetLockingScript appends state AFTER the code separator, so
	// the code portion is independent of the stateRoot value.
	dummyStateRoot := "00000000000000000000000000000000000000000000000000000000000000ff"
	contract := runar.NewRunarContract(artifact, []interface{}{
		dummyStateRoot,
		int64(0), // blockNumber
		int64(0), // frozen
		int64(0), // advancesSinceInbox (spec 10)
	})
	expectedFull := contract.GetLockingScript()
	expectedCode := stripStatefulSuffix(expectedFull)
	deployedCode := stripStatefulSuffix(deployedScriptHex)
	if deployedCode != expectedCode {
		return fmt.Errorf(
			"deployed code section (%d bytes) does not match expected (%d bytes) — "+
				"one or more manifest readonly fields (chainID, governance, SP1 VK) disagree with the deployed covenant",
			len(deployedCode)/2, len(expectedCode)/2,
		)
	}
	return nil
}

// recompileBakedArtifact runs the mode-specific compile with the
// constructor args the manifest implies and returns the
// runar.RunarArtifact that NewRunarContract wraps into the final
// locking script.
func recompileBakedArtifact(mode covenant.VerificationMode, sp1VK []byte, chainID uint64, gov covenant.GovernanceConfig) (*runar.RunarArtifact, error) {
	var (
		srcName string
		args    map[string]interface{}
		err     error
	)
	switch mode {
	case covenant.VerifyFRI:
		srcName = "rollup_fri.runar.go"
		args, err = covenant.BuildFRIConstructorArgsExported(sp1VK, chainID, gov)
	case covenant.VerifyDevKey:
		// Devkey reuses the shared readonly layout.
		srcName = "rollup_devkey.runar.go"
		args, err = covenant.BuildFRIConstructorArgsExported(sp1VK, chainID, gov)
	default:
		return nil, fmt.Errorf("recompile not implemented for mode %s", mode.String())
	}
	if err != nil {
		return nil, fmt.Errorf("build constructor args: %w", err)
	}
	src := findCovenantContractPath(srcName)
	compiled, compErr := gocompiler.CompileFromSource(src, gocompiler.CompileOptions{
		ConstructorArgs: args,
	})
	if compErr != nil {
		return nil, fmt.Errorf("compile %s: %w", srcName, compErr)
	}
	return gocompilerArtifactToSDK(compiled)
}

// stripStatefulSuffix returns the code portion of a locking script
// (everything before the LAST OP_RETURN), which is the portion our
// re-compile reproduces. Stateful contracts always have an OP_RETURN
// separating the code from the serialized state; stateless contracts
// return the whole script unchanged.
func stripStatefulSuffix(scriptHex string) string {
	pos := runar.FindLastOpReturn(scriptHex)
	if pos < 0 {
		return scriptHex
	}
	return scriptHex[:pos]
}

// extractScriptGenesisStateRoot reads the stateful stateRoot slot
// from the locking script's trailing data section. Uses the Rúnar
// SDK's ExtractStateFromScript against the template artifact for the
// given mode.
func extractScriptGenesisStateRoot(mode covenant.VerificationMode, scriptHex string) (types.Hash, error) {
	var out types.Hash
	artifact, err := loadTemplateArtifact(mode)
	if err != nil {
		return out, err
	}
	state := runar.ExtractStateFromScript(artifact, scriptHex)
	raw, ok := state["stateRoot"]
	if !ok {
		return out, fmt.Errorf("script state missing stateRoot")
	}
	hexStr, ok := raw.(string)
	if !ok {
		return out, fmt.Errorf("script stateRoot has unexpected type %T", raw)
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return out, fmt.Errorf("decode stateRoot hex: %w", err)
	}
	if len(decoded) != 32 {
		return out, fmt.Errorf("stateRoot expected 32 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}

// loadTemplateArtifact compiles the Rúnar source for the given
// verification mode WITHOUT ConstructorArgs, so the artifact keeps
// its ConstructorSlots / StateFields metadata. Used by
// extractScriptGenesisStateRoot so the runar state decoder knows
// where the state section starts and how to interpret each field.
func loadTemplateArtifact(mode covenant.VerificationMode) (*runar.RunarArtifact, error) {
	var srcName string
	switch mode {
	case covenant.VerifyFRI:
		srcName = "rollup_fri.runar.go"
	case covenant.VerifyDevKey:
		srcName = "rollup_devkey.runar.go"
	case covenant.VerifyGroth16:
		srcName = "rollup_groth16.runar.go"
	case covenant.VerifyGroth16WA:
		srcName = "rollup_groth16_wa.runar.go"
	default:
		return nil, fmt.Errorf("no template source for mode %s", mode.String())
	}
	src := findCovenantContractPath(srcName)
	compiled, err := gocompiler.CompileFromSource(src, gocompiler.CompileOptions{})
	if err != nil {
		return nil, fmt.Errorf("compile template %s: %w", srcName, err)
	}
	return gocompilerArtifactToSDK(compiled)
}

// gocompilerArtifactToSDK JSON-round-trips a gocompiler.Artifact into
// a runar.RunarArtifact. The two shapes share JSON tags.
func gocompilerArtifactToSDK(a *gocompiler.Artifact) (*runar.RunarArtifact, error) {
	blob, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal gocompiler artifact: %w", err)
	}
	var out runar.RunarArtifact
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("unmarshal runar artifact: %w", err)
	}
	return &out, nil
}

// findCovenantContractPath locates a Rúnar contract source file by
// name, first relative to the bsv-evm repo's pkg/covenant/contracts
// directory (dev workflow), then relative to the current working
// directory (Docker WORKDIR=/app layout).
func findCovenantContractPath(name string) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(thisFile)
		candidate := filepath.Join(dir, "..", "covenant", "contracts", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("pkg", "covenant", "contracts", name)
}
