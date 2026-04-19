package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/icellan/bsvm/pkg/shard"
)

// PrintStartupBanner writes the spec-16 devnet banner to stdout when the
// node identifies itself as the primary devnet node (BSVM_NODE_NAME=node1).
// Other nodes print a single-line readiness marker. Non-devnet nodes
// (no BSVM_NODE_NAME set) print nothing here — the production logging
// path already carries the relevant info.
//
// The banner is written to stdout, not via slog, so Docker / journald
// captures it verbatim without JSON wrapping.
func PrintStartupBanner(proveMode string, chainID int64, rpcAddr, p2pAddr string) {
	nodeName := NodeNameFromEnv()
	if nodeName == "" {
		return
	}

	if nodeName != "node1" {
		fmt.Printf("%s ready on %s (chain %d)\n", nodeName, rpcAddr, chainID)
		return
	}

	if proveMode == "" {
		proveMode = "mock"
	}
	rpc8545 := strings.TrimPrefix(rpcAddr, "0.0.0.0:")
	_ = rpc8545

	accounts := shard.HardhatDefaultAccounts()
	accountLines := make([]string, 0, 5)
	for i, a := range accounts {
		if i >= 5 {
			break
		}
		hex := a.Address.Hex()
		short := fmt.Sprintf("%s...%s", hex[:6], hex[len(hex)-4:])
		accountLines = append(accountLines, fmt.Sprintf("    #%d  %s", i, short))
	}

	banner := fmt.Sprintf(`
======================================================
  BSVM Devnet is running!

  Prove mode:  %s (switch with BSVM_PROVE_MODE=execute|prove)

  Node 1 (prover):   http://localhost:8545
  Node 2 (prover):   http://localhost:8546
  Node 3 (follower): http://localhost:8547

  Chain ID:    %d
  Gas Price:   1 gwei
  Block Gas:   30,000,000

  Explorer:    http://localhost:8545   (pending — spec 15)
  Admin:       http://localhost:8545/admin (pending — spec 15)

  Pre-funded accounts (1000 wBSV each):
%s
    ... (5 more)

  MetaMask: Add network → RPC URL: http://localhost:8545
                           Chain ID: %d
                           Symbol:   wBSV

  Hardhat:  networks: { bsvm: { url: "http://localhost:8545" } }
  Foundry:  forge script --rpc-url http://localhost:8545
======================================================
`,
		proveMode,
		chainID,
		strings.Join(accountLines, "\n"),
		chainID,
	)

	if _, err := os.Stdout.WriteString(banner); err != nil {
		// Non-fatal: stdout closed in an unusual environment. Keep starting.
		_ = err
	}
}
