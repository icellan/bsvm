package contracts

import (
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
)

// TestBridgeContract_CompilesToNonZeroScript locks in the WW-bridge-
// compile fix: bridge.runar.go now hard-codes MerkleRootSha256's depth
// argument at 16 so the runar-go static checker accepts it. The
// resulting Bitcoin Script is non-zero. Before the fix, the runar
// compiler rejected the contract with "depth (4th argument) must be
// a compile-time constant integer literal" and the deploy pipeline
// silently emitted a 0-byte bridge script.
//
// Keeping this assertion in the same package as the contract source
// means a future refactor that re-introduces a runtime depth — or
// otherwise breaks the runar checker — fails fast in CI rather than
// surfacing as an empty deploy artifact downstream.
func TestBridgeContract_CompilesToNonZeroScript(t *testing.T) {
	srcPath := bridgeContractSourcePath(t)

	// hex-encode an arbitrary 32-byte value as the readonly
	// StateCovenantScriptHash — its concrete value doesn't affect
	// whether the script compiles, only the bytes embedded in the
	// PUSHDATA at the top.
	scriptHash := strings.Repeat("ab", 32)

	args := map[string]interface{}{
		"stateCovenantScriptHash": scriptHash,
	}
	artifact, err := gocompiler.CompileFromSource(srcPath, gocompiler.CompileOptions{
		ConstructorArgs: args,
	})
	if err != nil {
		t.Fatalf("compile bridge.runar.go: %v", err)
	}

	scriptHex := strings.TrimPrefix(artifact.Script, "0x")
	if len(scriptHex)%2 != 0 {
		scriptHex = "0" + scriptHex
	}
	scriptBytes, err := hex.DecodeString(scriptHex)
	if err != nil {
		t.Fatalf("decode bridge script hex %q: %v", artifact.Script, err)
	}
	if len(scriptBytes) == 0 {
		t.Fatal("bridge script compiled to 0 bytes (regression of WW-bridge-compile fix)")
	}
	// Soft sanity floor: the bridge has hash-chain folding, a 16-deep
	// SHA-256 Merkle walk, OP_RETURN extraction and a state encode/
	// decode pipeline — comfortably more than 1 KB of script. A
	// suspiciously small value points to a codegen regression even if
	// non-zero. Pinning the magnitude rather than the exact size keeps
	// the test robust against benign script-layout tweaks in runar-go.
	if len(scriptBytes) < 1024 {
		t.Errorf("bridge script unusually small: %d bytes; suspect codegen regression", len(scriptBytes))
	}
	t.Logf("bridge script len=%d bytes", len(scriptBytes))
}

// bridgeContractSourcePath resolves the absolute path of
// bridge.runar.go relative to the test source directory so the test
// works from any cwd.
func bridgeContractSourcePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "bridge.runar.go")
}
