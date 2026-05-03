// Binary rotate-vk handles the SP1 verifying-key rotation procedure
// for a deployed BSVM shard.
//
// Build: go build -o build/rotate-vk ./deploy/covenant/cmd/rotate-vk
// Run:   ./build/rotate-vk --config ./rotation.json --dry-run
//
// Per spec 12, governance keys can upgrade the rollup covenant
// (swapping in a freshly-compiled locking script under a new VK hash)
// but cannot advance state. This binary builds + signs that upgrade.
package main

import (
	"flag"
	"fmt"
	"os"

	covenantdeploy "github.com/icellan/bsvm/deploy/covenant"
)

func main() {
	opts := covenantdeploy.RotateOptions{}
	flag.StringVar(&opts.ConfigPath, "config", "", "path to rotate-vk config JSON (required)")
	flag.StringVar(&opts.OldVKFile, "old-vk-hash-file", "", "path to the OLD SP1VerifyingKeyHash.txt (optional, for the diff in the JSON summary)")
	flag.BoolVar(&opts.DryRun, "dry-run", true, "compile + emit summary; do NOT broadcast (default)")
	flag.BoolVar(&opts.Broadcast, "broadcast", false, "compile + sign + broadcast via ARC")
	flag.StringVar(&opts.OutPath, "out", "", "write JSON summary to this path in addition to stdout")
	flag.BoolVar(&opts.ANFPublish, "anf-publish", false,
		"in --broadcast mode, ALSO publish the canonical ANF inscription tx to BSV. "+
			"The on-chain hash256(NewCovenantAnfHash) is bound regardless; this flag controls "+
			"only whether the JSON document is broadcast so off-chain observers can fetch it. "+
			"Default: false (operator dry-runs, inspects --anf-doc, then opts in)")
	flag.StringVar(&opts.AnfDocPath, "anf-doc", "",
		"write the canonical ANF document JSON to this path (default: <config-dir>/rotate-vk.anf.json)")
	flag.Parse()

	if err := covenantdeploy.RunRotateVK(opts); err != nil {
		fmt.Fprintln(os.Stderr, "rotate-vk: ", err)
		os.Exit(1)
	}
}
