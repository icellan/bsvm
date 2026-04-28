package prover

import (
	"context"
	"testing"

	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/types"
)

// TestSP1Prover_MetricsObservation confirms a successful Prove() call
// records both a duration sample and a proof-size sample on the
// supplied Counters set.
func TestSP1Prover_MetricsObservation(t *testing.T) {
	prover := NewSP1Prover(Config{
		Mode:         ProverMock,
		SP1ProofMode: "compressed",
	})
	c := metrics.DisabledCounters()
	prover.SetMetrics(c)

	input := &ProveInput{
		PreStateRoot: types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		StateExport:  []byte(`{"pre_state_root":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","accounts":[]}`),
		Transactions: [][]byte{{0xf8, 0x65}},
		BlockContext: BlockContext{
			Number:    1,
			Timestamp: 1700000000,
			Coinbase:  types.HexToAddress("0x0000000000000000000000000000000000000001"),
			GasLimit:  30000000,
			BaseFee:   1000000000,
		},
	}
	if _, err := prover.Prove(context.Background(), input); err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if got := metrics.HistogramSampleCount(c.ProverProofDurationSeconds); got != 1 {
		t.Errorf("ProverProofDurationSeconds sample count want 1 got %d", got)
	}
	if got := metrics.HistogramSampleCount(c.ProverProofSizeBytes); got != 1 {
		t.Errorf("ProverProofSizeBytes sample count want 1 got %d", got)
	}
}
