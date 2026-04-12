package rpc

import "testing"

// mockPeerCounter is a simple PeerCounter for testing.
type mockPeerCounter struct {
	count int
}

func (m *mockPeerCounter) PeerCount() int {
	return m.count
}

func TestNetAPI_PeerCount_WithPeers(t *testing.T) {
	api := NewNetAPI(1)
	api.SetPeerCounter(&mockPeerCounter{count: 5})

	got := api.PeerCount()
	if got != "0x5" {
		t.Errorf("PeerCount() = %q, want %q", got, "0x5")
	}
}

func TestNetAPI_PeerCount_NoPeers(t *testing.T) {
	api := NewNetAPI(1)
	api.SetPeerCounter(&mockPeerCounter{count: 0})

	got := api.PeerCount()
	if got != "0x0" {
		t.Errorf("PeerCount() = %q, want %q", got, "0x0")
	}
}

func TestNetAPI_PeerCount_NilCounter(t *testing.T) {
	api := NewNetAPI(1)

	got := api.PeerCount()
	if got != "0x0" {
		t.Errorf("PeerCount() = %q, want %q", got, "0x0")
	}
}
