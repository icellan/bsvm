// Script-pattern matching for DetectVerificationMode. Isolated from
// compile.go so the public API (DetectVerificationMode) stays clean
// and the Rúnar SDK / gocompiler dependencies don't bleed through the
// rest of compile.go.
package covenant

import (
	"fmt"
	"sync"

	runar "github.com/icellan/runar/packages/runar-go"
)

// maxDetectScriptHexLen is the upper bound on input accepted by
// DetectVerificationMode. The largest known on-chain covenant template
// today is the FRI rollup at roughly 1.7 MB hex (~849 KB raw), so 4 MB
// hex leaves comfortable room for growth while preventing pathological
// inputs (or hostile callers) from spinning the matcher on multi-
// gigabyte blobs. A previous regression where this bound was missing
// — combined with per-call template recompilation — caused
// DetectVerificationMode to hang test runs for minutes.
//
// TODO(spec): spec/12 does not currently pin a maximum locking-script
// size. Once that bound is published, mirror it here and drop the
// "well above the largest known template" justification.
const maxDetectScriptHexLen = 4 * 1024 * 1024

// templateArtifactCacheEntry memoises the result of compiling one
// VerificationMode's template source. Each entry guards its own
// sync.Once so concurrent first-callers block on the single in-flight
// compile and every subsequent caller (in any goroutine) reuses the
// same *runar.RunarArtifact / error pair without re-running the Rúnar
// compiler.
type templateArtifactCacheEntry struct {
	once     sync.Once
	artifact *runar.RunarArtifact
	err      error
}

// templateArtifactCache holds one entry per VerificationMode. The
// outer mutex guards the brief insert path (creating a fresh entry on
// first observation of a mode); the per-entry sync.Once handles the
// expensive compile path without holding the outer mutex.
//
// Rationale: each call to DetectVerificationMode used to invoke
// matchesCompiledTemplate for every candidate mode, and each call
// re-read the template source from disk and re-ran the Rúnar Go
// compiler. The Mode 1 FRI template alone takes single-digit seconds
// to compile, so a single Detect call on garbage input cost tens of
// seconds and any hot path that called Detect repeatedly hung the
// process for minutes. The cache turns those repeated compiles into
// O(1) map lookups after the first miss.
var (
	templateArtifactCacheMu sync.Mutex
	templateArtifactCache   = make(map[VerificationMode]*templateArtifactCacheEntry)
)

// cachedTemplateArtifact returns the compiled template artifact for
// the given VerificationMode, compiling it on first request and
// reusing the cached result thereafter. Concurrent first-callers
// block on the same sync.Once so the Rúnar compiler runs at most
// once per mode for the lifetime of the process.
func cachedTemplateArtifact(mode VerificationMode) (*runar.RunarArtifact, error) {
	templateArtifactCacheMu.Lock()
	entry, ok := templateArtifactCache[mode]
	if !ok {
		entry = &templateArtifactCacheEntry{}
		templateArtifactCache[mode] = entry
	}
	templateArtifactCacheMu.Unlock()

	entry.once.Do(func() {
		srcPath, err := templateSource(mode)
		if err != nil {
			entry.err = err
			return
		}
		entry.artifact, entry.err = compileTemplateArtifact(srcPath)
	})

	return entry.artifact, entry.err
}

// matchesCompiledTemplate is the concrete script-matcher used by
// DetectVerificationMode. Given a known VerificationMode, it pulls
// the corresponding template artifact from the per-mode cache (which
// compiles WITHOUT constructor args so the artifact preserves its
// ConstructorSlots metadata — what MatchesArtifact walks to skip over
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
	artifact, err := cachedTemplateArtifact(mode)
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
