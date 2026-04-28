package bridge

import (
	"testing"

	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

func readCounter(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	return metrics.CounterValue(c)
}

// TestBridgeMonitor_MetricsPersistDeposit confirms PersistDeposit
// drives BridgeDepositsTotal when a fresh Counters is wired.
func TestBridgeMonitor_MetricsPersistDeposit(t *testing.T) {
	m, _ := newTestMonitor(t)
	c := metrics.DisabledCounters()
	m.SetMetrics(c)

	if got := readCounter(t, c.BridgeDepositsTotal); got != 0 {
		t.Fatalf("baseline BridgeDepositsTotal want 0 got %v", got)
	}

	dep := NewDepositWithVout(
		types.HexToHash("0xaabbccdd"),
		0,
		100,
		types.HexToAddress("0x1111111111111111111111111111111111111111"),
		50_000,
	)
	dep.Confirmed = true
	if err := m.PersistDeposit(dep); err != nil {
		t.Fatalf("PersistDeposit: %v", err)
	}

	if got := readCounter(t, c.BridgeDepositsTotal); got != 1 {
		t.Errorf("BridgeDepositsTotal want 1 got %v", got)
	}
}

// TestBridgeMonitor_MetricsRetractDeposits confirms RetractDepositsAbove
// drives BridgeRetractsTotal once per call regardless of how many
// deposits are dropped.
func TestBridgeMonitor_MetricsRetractDeposits(t *testing.T) {
	m, _ := newTestMonitor(t)
	c := metrics.DisabledCounters()
	m.SetMetrics(c)

	m.RetractDepositsAbove(0)
	m.RetractDepositsAbove(1)

	if got := readCounter(t, c.BridgeRetractsTotal); got != 2 {
		t.Errorf("BridgeRetractsTotal want 2 got %v", got)
	}
}

// TestWithdrawer_MetricsClaimBroadcastOK confirms a successful claim
// path (broadcaster returns nil) drives both
// BridgeWithdrawalsClaimedTotal and ClaimBroadcastTotal{result=ok}.
func TestWithdrawer_MetricsClaimBroadcastOK(t *testing.T) {
	broadcaster := &mockBroadcaster{}
	scanner := &mockWithdrawalScanner{
		withdrawals: []*PendingWithdrawal{
			{
				Nonce:          0,
				BSVAddress:     make([]byte, 20),
				AmountSatoshis: 100_000_000,
				L2BlockNum:     10,
			},
		},
	}
	advanceFinder := &mockAdvanceFinder{
		tx: &BSVTransaction{
			TxID:    types.HexToHash("0xbeef"),
			Outputs: []BSVOutput{{Script: []byte{0x76}, Value: 1000}},
		},
	}
	bridgeUTXO := NewBridgeUTXO(
		types.HexToHash("0xaaaa"),
		0,
		10_000_000_000,
		[]byte{0x76, 0xa9},
	)
	c := metrics.DisabledCounters()
	w := NewWithdrawer(broadcaster, bridgeUTXO, scanner, advanceFinder, DefaultWithdrawalConfig()).
		WithMetrics(c)

	if err := w.ProcessFinalizedWithdrawals(); err != nil {
		t.Fatalf("ProcessFinalizedWithdrawals: %v", err)
	}

	if got := readCounter(t, c.BridgeWithdrawalsClaimedTotal); got != 1 {
		t.Errorf("BridgeWithdrawalsClaimedTotal want 1 got %v", got)
	}
	if got := c.CounterVecValue(c.ClaimBroadcastTotal, "ok"); got != 1 {
		t.Errorf("ClaimBroadcastTotal{ok} want 1 got %v", got)
	}
}
