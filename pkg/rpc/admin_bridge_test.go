package rpc

import (
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/types"
)

// TestAdminAPI_BridgeHealth_NoMonitor verifies that with no
// BridgeMonitor wired, BridgeHealth returns a fully-formed response
// with monitorAttached=false and a guidance note rather than
// crashing.
func TestAdminAPI_BridgeHealth_NoMonitor(t *testing.T) {
	a := &AdminAPI{}
	resp := a.BridgeHealth()
	if got, want := resp["monitorAttached"], false; got != want {
		t.Errorf("monitorAttached = %v, want %v", got, want)
	}
	if note, ok := resp["note"].(string); !ok || !strings.Contains(note, "bridge monitor not attached") {
		t.Errorf("note = %v, want one mentioning 'bridge monitor not attached'", resp["note"])
	}
	if _, ok := resp["totalLocked"]; !ok {
		t.Errorf("response missing totalLocked field")
	}
}

// TestAdminAPI_BridgeHealth_WithMonitor verifies that with a wired
// monitor and a seeded BridgeUTXO snapshot, BridgeHealth surfaces
// the live (txid, balance, lastClaimedNonce) tuple plus the
// horizon/pending counters.
func TestAdminAPI_BridgeHealth_WithMonitor(t *testing.T) {
	mon := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil)
	mon.SetLocalShardID(1234)
	utxo := bridge.NewBridgeUTXO(types.Hash{0xab, 0xcd}, 0, 87_000_000_000, []byte{0x76, 0xa9})
	mon.SetBridgeUTXO(utxo)

	a := &AdminAPI{bridgeMonitor: mon}
	resp := a.BridgeHealth()

	if got, want := resp["monitorAttached"], true; got != want {
		t.Errorf("monitorAttached = %v, want %v", got, want)
	}
	if got, want := resp["rescannerWired"], false; got != want {
		t.Errorf("rescannerWired = %v, want %v (no SetBridgeRescanner called)", got, want)
	}
	if got, want := resp["totalLocked"], "87000000000"; got != want {
		t.Errorf("totalLocked = %v, want %v", got, want)
	}
	subs, ok := resp["subCovenants"].([]map[string]interface{})
	if !ok {
		t.Fatalf("subCovenants not a slice: %T", resp["subCovenants"])
	}
	if len(subs) != 1 {
		t.Fatalf("subCovenants len = %d, want 1", len(subs))
	}
	if got, want := subs[0]["balance"], uint64(87_000_000_000); got != want {
		t.Errorf("subCovenants[0].balance = %v, want %v", got, want)
	}
}

// TestAdminAPI_RescanDeposits_NoMonitor verifies that without a
// monitor, RescanDeposits returns the structured "monitor not
// attached" error instead of pretending to schedule work.
func TestAdminAPI_RescanDeposits_NoMonitor(t *testing.T) {
	a := &AdminAPI{}
	_, err := a.RescanDeposits(800_000)
	if err == nil {
		t.Fatal("expected error when monitor not wired")
	}
	if !strings.Contains(err.Error(), "monitor not attached") {
		t.Errorf("error = %q, want it to mention 'monitor not attached'", err.Error())
	}
}

// TestAdminAPI_RescanDeposits_NoRescanner verifies that with a
// monitor but no rescanner callback wired, the operator-facing
// error references the WW-bridge-rescanner-attach tracking ID so
// the gap is discoverable from the RPC response alone.
func TestAdminAPI_RescanDeposits_NoRescanner(t *testing.T) {
	mon := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil)
	a := &AdminAPI{bridgeMonitor: mon}
	_, err := a.RescanDeposits(800_000)
	if err == nil {
		t.Fatal("expected error when rescanner not wired")
	}
	if !strings.Contains(err.Error(), "WW-bridge-rescanner-attach") {
		t.Errorf("error = %q, want it to reference WW-bridge-rescanner-attach tracking ID", err.Error())
	}
}

// TestAdminAPI_RescanDeposits_DelegatesToCallback verifies the happy
// path: a wired callback receives the fromHeight argument and its
// scheduled-count is reflected in the response.
func TestAdminAPI_RescanDeposits_DelegatesToCallback(t *testing.T) {
	mon := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil)
	a := &AdminAPI{bridgeMonitor: mon}

	var called bool
	var calledFrom uint64
	a.SetBridgeRescanner(func(from uint64) (uint64, error) {
		called = true
		calledFrom = from
		return 42, nil
	})

	resp, err := a.RescanDeposits(800_000)
	if err != nil {
		t.Fatalf("RescanDeposits: %v", err)
	}
	if !called {
		t.Fatal("rescanner callback was not invoked")
	}
	if calledFrom != 800_000 {
		t.Errorf("callback fromHeight = %d, want 800000", calledFrom)
	}
	if got, want := resp["scheduled"], uint64(42); got != want {
		t.Errorf("scheduled = %v, want %v", got, want)
	}
	if got, want := resp["fromHeight"], uint64(800_000); got != want {
		t.Errorf("fromHeight = %v, want %v", got, want)
	}
}
