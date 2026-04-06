//go:build integration

package integration

import (
	"path/filepath"
	"runtime"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// bsvmRoot returns the absolute path to the BSVM project root.
func bsvmRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// compileContract compiles a .runar.go contract from the BSVM repo
// using the Rúnar SDK compilation pipeline.
func compileContract(relPath string) (*runar.RunarArtifact, error) {
	absPath := filepath.Join(bsvmRoot(), relPath)
	return helpers.CompileToSDKArtifactAbs(absPath)
}
