// Script-pattern matching for DetectVerificationMode. Isolated from
// compile.go so the public API (DetectVerificationMode) stays clean
// and the Rúnar SDK / gocompiler dependencies don't bleed through the
// rest of compile.go.
package covenant

import (
	"encoding/json"
	"fmt"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// matchesCompiledTemplate is the concrete script-matcher used by
// DetectVerificationMode. Given a known VerificationMode, it re-runs
// the Rúnar Go compiler against the corresponding source file WITHOUT
// constructor args so the resulting artifact preserves its
// ConstructorSlots metadata (which MatchesArtifact walks to skip over
// per-shard pushdata). That template artifact is then matched against
// the on-chain hex script.
//
// Compiling WITHOUT constructor args is essential: when the compiler
// receives ConstructorArgs, it bakes those values into the script as
// ordinary pushdata and drops ConstructorSlots. MatchesArtifact then
// has nothing to skip over and falls back to a byte-exact comparison,
// which fails for any deployed script whose readonly values differ
// from the detector's placeholders.
//
// The _ *CompiledCovenant receiver is unused but retained so the
// signature advertises that the matcher is keyed off the same type
// the covenant package uses elsewhere; future refactors could extract
// per-mode routing data from cov without touching call sites.
func matchesCompiledTemplate(_ *CompiledCovenant, mode VerificationMode, scriptHex string) bool {
	srcPath, err := templateSource(mode)
	if err != nil {
		return false
	}
	artifact, err := compileTemplateArtifact(srcPath)
	if err != nil {
		return false
	}
	return runar.MatchesArtifact(artifact, scriptHex)
}

// templateSource returns the Rúnar source file path for the given
// VerificationMode. Only modes the detector can match are enumerated;
// callers handle the unsupported case explicitly.
func templateSource(mode VerificationMode) (string, error) {
	switch mode {
	case VerifyFRI:
		return findFRIContractSource(), nil
	case VerifyDevKey:
		return findDevKeyContractSource(), nil
	case VerifyGroth16:
		return findGroth16ContractSource(), nil
	case VerifyGroth16WA:
		return findGroth16WAContractSource(), nil
	default:
		return "", fmt.Errorf("detect: verification mode %s has no known source template", mode.String())
	}
}

// compileTemplateArtifact compiles the named template source file
// WITHOUT constructor args so the resulting artifact retains its
// ConstructorSlots, then JSON-round-trips the gocompiler.Artifact
// into a runar.RunarArtifact (the shape MatchesArtifact consumes —
// both structs share JSON tags).
func compileTemplateArtifact(srcPath string) (*runar.RunarArtifact, error) {
	compiled, err := gocompiler.CompileFromSource(srcPath, gocompiler.CompileOptions{})
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", srcPath, err)
	}
	blob, err := json.Marshal(compiled)
	if err != nil {
		return nil, fmt.Errorf("marshal artifact: %w", err)
	}
	var out runar.RunarArtifact
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("unmarshal artifact: %w", err)
	}
	return &out, nil
}
