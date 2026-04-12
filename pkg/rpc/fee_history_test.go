package rpc

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/types"
)

func TestFeeHistory_SingleBlock(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Genesis is block 0 -- request 1 block of history.
	result, err := ts.server.EthAPI().FeeHistory(1, 0)
	if err != nil {
		t.Fatalf("FeeHistory failed: %v", err)
	}

	if result["oldestBlock"] != "0x0" {
		t.Errorf("oldestBlock = %v, want 0x0", result["oldestBlock"])
	}

	baseFees, ok := result["baseFeePerGas"].([]string)
	if !ok {
		t.Fatalf("baseFeePerGas type = %T, want []string", result["baseFeePerGas"])
	}
	// blockCount=1 => baseFeePerGas has 2 entries (blockCount + 1).
	if len(baseFees) != 2 {
		t.Fatalf("baseFeePerGas length = %d, want 2", len(baseFees))
	}

	ratios, ok := result["gasUsedRatio"].([]float64)
	if !ok {
		t.Fatalf("gasUsedRatio type = %T, want []float64", result["gasUsedRatio"])
	}
	if len(ratios) != 1 {
		t.Fatalf("gasUsedRatio length = %d, want 1", len(ratios))
	}
}

func TestFeeHistory_MultipleBlocks(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process 2 blocks.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))
	ts.processOneTx(t, 1, recipient, uint256.NewInt(2000))

	// Request 10 blocks of history -- more than available (3: genesis + 2).
	result, err := ts.server.EthAPI().FeeHistory(10, 2)
	if err != nil {
		t.Fatalf("FeeHistory failed: %v", err)
	}

	// Should be capped to 3 blocks (0, 1, 2).
	if result["oldestBlock"] != "0x0" {
		t.Errorf("oldestBlock = %v, want 0x0", result["oldestBlock"])
	}

	baseFees, ok := result["baseFeePerGas"].([]string)
	if !ok {
		t.Fatalf("baseFeePerGas type = %T, want []string", result["baseFeePerGas"])
	}
	// Capped to 3 blocks => 4 baseFee entries.
	if len(baseFees) != 4 {
		t.Fatalf("baseFeePerGas length = %d, want 4", len(baseFees))
	}

	ratios, ok := result["gasUsedRatio"].([]float64)
	if !ok {
		t.Fatalf("gasUsedRatio type = %T, want []float64", result["gasUsedRatio"])
	}
	if len(ratios) != 3 {
		t.Fatalf("gasUsedRatio length = %d, want 3", len(ratios))
	}
}

func TestFeeHistory_BaseFeeAlwaysZero(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a block to have some data.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	result, err := ts.server.EthAPI().FeeHistory(2, 1)
	if err != nil {
		t.Fatalf("FeeHistory failed: %v", err)
	}

	baseFees, ok := result["baseFeePerGas"].([]string)
	if !ok {
		t.Fatalf("baseFeePerGas type = %T, want []string", result["baseFeePerGas"])
	}

	for i, fee := range baseFees {
		if fee != "0x0" {
			t.Errorf("baseFeePerGas[%d] = %s, want 0x0", i, fee)
		}
	}
}

func TestFeeHistory_GasUsedRatio(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a block with a transaction (21000 gas used for a simple transfer).
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	result, err := ts.server.EthAPI().FeeHistory(1, 1)
	if err != nil {
		t.Fatalf("FeeHistory failed: %v", err)
	}

	ratios, ok := result["gasUsedRatio"].([]float64)
	if !ok {
		t.Fatalf("gasUsedRatio type = %T, want []float64", result["gasUsedRatio"])
	}
	if len(ratios) != 1 {
		t.Fatalf("gasUsedRatio length = %d, want 1", len(ratios))
	}

	// Block 1 should have some gas used (21000 for a simple transfer).
	// The ratio should be > 0 (gas was used) and < 1 (not full).
	if ratios[0] <= 0 {
		t.Errorf("gasUsedRatio[0] = %f, expected > 0", ratios[0])
	}
	if ratios[0] >= 1 {
		t.Errorf("gasUsedRatio[0] = %f, expected < 1", ratios[0])
	}

	// Genesis block (block 0) should have ratio 0.
	result2, err := ts.server.EthAPI().FeeHistory(1, 0)
	if err != nil {
		t.Fatalf("FeeHistory for genesis failed: %v", err)
	}
	ratios2 := result2["gasUsedRatio"].([]float64)
	if ratios2[0] != 0 {
		t.Errorf("genesis gasUsedRatio = %f, want 0", ratios2[0])
	}
}

func TestFeeHistory_LatestBlock(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a block.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	// Use resolveBlockNumber with "latest" (-1) to get the newest block.
	latest, err := ts.server.EthAPI().resolveBlockNumber(-1)
	if err != nil {
		t.Fatalf("resolveBlockNumber failed: %v", err)
	}
	if latest != 1 {
		t.Fatalf("latest block = %d, want 1", latest)
	}

	result, err := ts.server.EthAPI().FeeHistory(1, latest)
	if err != nil {
		t.Fatalf("FeeHistory failed: %v", err)
	}

	if result["oldestBlock"] != "0x1" {
		t.Errorf("oldestBlock = %v, want 0x1", result["oldestBlock"])
	}

	baseFees := result["baseFeePerGas"].([]string)
	if len(baseFees) != 2 {
		t.Fatalf("baseFeePerGas length = %d, want 2", len(baseFees))
	}
}
