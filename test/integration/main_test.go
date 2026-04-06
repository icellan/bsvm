//go:build integration

package integration

import (
	"fmt"
	"os"
	"testing"

	"runar-integration/helpers"
)

func TestMain(m *testing.M) {
	nodeType := helpers.NodeType()
	fmt.Fprintf(os.Stderr, "BSVM integration tests using node type: %s\n", nodeType)

	if !helpers.IsNodeAvailable() {
		fmt.Fprintln(os.Stderr, "Regtest node not running. Skipping integration tests.")
		fmt.Fprintln(os.Stderr, "Start with: cd ../../../runar/integration && ./regtest.sh start")
		os.Exit(0)
	}

	currentHeight, err := helpers.GetBlockCount()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get block count: %v\n", err)
		os.Exit(1)
	}

	targetHeight := 101
	if helpers.IsTeranode() {
		targetHeight = 10_101
	}

	blocksNeeded := targetHeight - currentHeight
	if blocksNeeded > 0 {
		fmt.Fprintf(os.Stderr, "Mining %d blocks (current: %d, target: %d)...\n", blocksNeeded, currentHeight, targetHeight)
		if err := helpers.Mine(blocksNeeded); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to mine: %v\n", err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}
