// Binary deploy is the operator entry point for compiling and
// broadcasting a fresh shard's bridge + rollup covenant pair.
//
// Build: go build -o build/deploy-covenant ./deploy/covenant/cmd/deploy
// Run:   ./build/deploy-covenant --config ./operator.json --dry-run
//
// All real work is in package covenantdeploy; this file is a 30-line
// flag parser so the integration test can call covenantdeploy.RunDeploy
// directly without going through os.Args.
package main

import (
	"flag"
	"fmt"
	"os"

	covenantdeploy "github.com/icellan/bsvm/deploy/covenant"
)

func main() {
	opts := covenantdeploy.RunOptions{}
	flag.StringVar(&opts.ConfigPath, "config", "", "path to operator config JSON (required)")
	flag.BoolVar(&opts.DryRun, "dry-run", true, "compile + emit summary; do NOT broadcast (default)")
	flag.BoolVar(&opts.Broadcast, "broadcast", false, "compile + sign + broadcast via ARC (requires fundingTxId, fundingScriptHex, fundingSats, arcEndpoint in config)")
	flag.StringVar(&opts.OutPath, "out", "", "write JSON summary to this path in addition to stdout")
	flag.BoolVar(&opts.ANFPublish, "anf-publish", false,
		"in --broadcast mode, ALSO publish the canonical ANF inscription tx to BSV. "+
			"The genesis tx itself only carries the rollup script bytes; this flag publishes "+
			"the FULL canonical document (script + runar-go ANF IR + governance) so off-chain "+
			"observers can audit the contract source without re-running the deploy tool. "+
			"Default: false (operator dry-runs, inspects --anf-doc, then opts in)")
	flag.StringVar(&opts.AnfDocPath, "anf-doc", "",
		"write the canonical ANF document JSON to this path (default: <config-dir>/deploy.anf.json)")
	flag.Parse()

	if err := covenantdeploy.RunDeploy(opts); err != nil {
		fmt.Fprintln(os.Stderr, "deploy-covenant: ", err)
		os.Exit(1)
	}
}
