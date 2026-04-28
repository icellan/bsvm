package chaintracks

import (
	"math/big"
	"testing"

	"github.com/icellan/bsvm/pkg/metrics"
)

// TestStreamHub_MetricsReorgCounter confirms acceptReorg increments
// ChaintracksReorgsTotal once per adopted reorg.
func TestStreamHub_MetricsReorgCounter(t *testing.T) {
	parent := mineHeader(t, nil, 0x207fffff, 500)
	tip := mineHeader(t, parent, 0x207fffff, 501)
	fork1 := mineHeader(t, parent, 0x207fffff, 501)
	fork2 := mineHeader(t, fork1, 0x207fffff, 502)

	hub, err := newStreamHub("http://example.invalid/", "", StreamConfig{Path: "/", Checkpoints: nil})
	if err != nil {
		t.Fatalf("newStreamHub: %v", err)
	}
	c := metrics.DisabledCounters()
	hub.metrics = c
	tipWork, _ := WorkForBits(tip.Bits)
	tip.Work = new(big.Int).Set(tipWork)
	hub.SetTip(tip)

	if err := hub.acceptReorg(parent.Hash, []*BlockHeader{fork1, fork2}); err != nil {
		t.Fatalf("acceptReorg: %v", err)
	}

	if got := metrics.CounterValue(c.ChaintracksReorgsTotal); got != 1 {
		t.Errorf("ChaintracksReorgsTotal want 1 got %v", got)
	}
}
