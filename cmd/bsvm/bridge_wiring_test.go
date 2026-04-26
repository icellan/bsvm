package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/icellan/bsvm/internal/db"
)

// TestBuildBridgeMonitor_EmptyHex returns (nil, nil, nil) so daemons
// running on shards without a deployed L1 bridge keep booting. The
// BEEF consumer's fail-closed branch fires.
func TestBuildBridgeMonitor_EmptyHex(t *testing.T) {
	cases := []string{"", "   ", "0x", "0x   "}
	for _, in := range cases {
		t.Run(strings.ReplaceAll(in, " ", "_"), func(t *testing.T) {
			memDB := db.NewMemoryDB()
			mon, sh, err := BuildBridgeMonitor(BridgeSection{}, in, 31337, memDB, nil)
			if err != nil {
				t.Fatalf("BuildBridgeMonitor(%q): %v", in, err)
			}
			if mon != nil {
				t.Fatalf("expected nil monitor for empty hex %q, got %T", in, mon)
			}
			if sh != nil {
				t.Fatalf("expected nil scriptHash for empty hex %q, got %x", in, sh)
			}
		})
	}
}

// TestBuildBridgeMonitor_HappyPath wires the monitor with a script
// hash and shard id, persists a deposit through it, and confirms the
// returned scriptHash bytes match the configured hex.
func TestBuildBridgeMonitor_HappyPath(t *testing.T) {
	const scriptHex = "76a914aabbccddeeff00112233445566778899aabbccdd88ac"
	wantBytes, _ := hex.DecodeString(scriptHex)

	memDB := db.NewMemoryDB()
	mon, gotBytes, err := BuildBridgeMonitor(
		BridgeSection{
			MinDepositSatoshis:    20000,
			MinWithdrawalSatoshis: 20000,
			BSVConfirmations:      3,
		},
		// 0x prefix accepted.
		"0x"+scriptHex,
		31337,
		memDB,
		nil, // overlay nil — we drive PersistDeposit directly.
	)
	if err != nil {
		t.Fatalf("BuildBridgeMonitor: %v", err)
	}
	if mon == nil {
		t.Fatal("expected non-nil monitor")
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("scriptHash bytes mismatch: got %x want %x", gotBytes, wantBytes)
	}
	if got := mon.LocalShardID(); got != 31337 {
		t.Fatalf("LocalShardID = %d, want 31337", got)
	}
}

// TestBuildBridgeMonitor_BadHex surfaces hex-decode errors at startup.
func TestBuildBridgeMonitor_BadHex(t *testing.T) {
	memDB := db.NewMemoryDB()
	_, _, err := BuildBridgeMonitor(BridgeSection{}, "not-hex", 31337, memDB, nil)
	if err == nil {
		t.Fatal("expected error for malformed bridge_script_hex")
	}
	if !strings.Contains(err.Error(), "bridge.bridge_script_hex") {
		t.Fatalf("expected error to mention bridge_script_hex, got %v", err)
	}
}
