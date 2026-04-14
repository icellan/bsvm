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

// compileContractGroth16WA compiles a Mode 3 stateful rollup contract from
// the BSVM repo with vkAbsPath baked into the witness-assisted Groth16
// verifier preamble. vkAbsPath must be an absolute path to an SP1-format
// vk.json file (e.g. tests/sp1/sp1_groth16_vk.json).
func compileContractGroth16WA(relPath, vkAbsPath string) (*runar.RunarArtifact, error) {
	absPath := filepath.Join(bsvmRoot(), relPath)
	return helpers.CompileToSDKArtifactAbsWithGroth16WAVKey(absPath, vkAbsPath)
}
