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
	flag.Parse()

	if err := covenantdeploy.RunDeploy(opts); err != nil {
		fmt.Fprintln(os.Stderr, "deploy-covenant: ", err)
		os.Exit(1)
	}
}
