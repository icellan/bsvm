package covenant

import (
	"testing"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// Test_RunarAPISmoke is a fail-fast import-surface check for the three
// runar APIs the BSVM project depends on most heavily (per
// docs/decisions/U-runar-api-pinning.md):
//
//   - runar.MatchesArtifact      — covenant detect (pkg/covenant/detect.go)
//   - gocompiler.CompileFromSource — covenant template compile
//     (pkg/covenant/compile.go)
//   - runar.VerifySP1FRI         — Mode 1 on-chain SP1 STARK verifier
//     intrinsic (pkg/covenant/contracts/rollup_fri.runar.go)
//
// The sole purpose of this test is to break loudly if a sibling-repo
// runar bump ever drops or renames any of these symbols. It does NOT
// re-test their correctness — that's the responsibility of the unit
// tests in runar's own repo. We only assert: "the symbol is present,
// is callable with the documented signature, and produces a result of
// the documented type." If THIS test fails to compile, we have an API
// break and the BSVM bump must not land.
//
// Runtime cost: trivial. The MatchesArtifact call uses a known-bad
// hex string so we don't need to compile anything. The VerifySP1FRI
// call is the off-chain Go runtime stub which always returns true.
// The compiler import is checked via package-level type assertion
// (no actual compile invoked here — that's exercised by the existing
// TestCompileFRIRollup tests).
func Test_RunarAPISmoke(t *testing.T) {
	t.Run("MatchesArtifact_signature", func(t *testing.T) {
		// Signature pin: func MatchesArtifact(artifact *RunarArtifact, scriptHex string) bool
		//
		// We feed an empty (but non-nil) artifact and a clearly-wrong
		// hex script. The call must return false (no match) without
		// panicking. A signature/return-type change here breaks
		// compilation; a behaviour change (e.g., a nil-deref or a
		// thrown error) would surface as a test failure.
		artifact := &runar.RunarArtifact{Script: ""}
		got := runar.MatchesArtifact(artifact, "deadbeef")
		if got {
			t.Errorf("MatchesArtifact(empty-artifact, \"deadbeef\") expected false; got true")
		}
	})

	t.Run("VerifySP1FRI_signature", func(t *testing.T) {
		// Signature pin: func VerifySP1FRI(proofBlob, publicValues, sp1VKeyHash ByteString) bool
		//
		// The Go runtime body is the off-chain stub (returns true).
		// In compiled Bitcoin Script this lowers to the full SP1 v6
		// STARK verifier (lowerVerifySP1FRI in
		// runar/compilers/go/codegen/sp1_fri.go). Asserting on the
		// off-chain return value is the most we can do here without
		// dragging in a real SP1 proof — and that's all we need; the
		// codegen-side correctness lives behind the Mode 1 e2e
		// regtest gate, not this fast smoke test.
		var proof, pv, vkHash runar.ByteString
		ok := runar.VerifySP1FRI(proof, pv, vkHash)
		if !ok {
			t.Errorf("VerifySP1FRI off-chain stub should always return true; got false")
		}
	})

	t.Run("CompileFromSource_symbol_present", func(t *testing.T) {
		// Symbol pin: a non-nil function value at the documented import
		// path. Calling it with a real source file is exercised by the
		// existing TestCompileFRIRollup* tests in compile_test.go; here
		// we only confirm the symbol still exists at the import path
		// the BSVM compile pipeline depends on.
		//
		// The function-pointer trick forces the compiler to resolve
		// the symbol as a value, which fails compilation if the symbol
		// has been removed or renamed. This is the desired fail-fast
		// behaviour: a broken bump cannot land.
		fn := gocompiler.CompileFromSource
		if fn == nil {
			t.Fatal("gocompiler.CompileFromSource is nil — runar API surface broken")
		}
	})
}
