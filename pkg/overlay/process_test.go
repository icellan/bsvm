package overlay

import "testing"

func TestShouldSettleAsyncForLongRunningSP1Modes(t *testing.T) {
	for _, mode := range []string{"execute", "prove"} {
		node := &OverlayNode{config: OverlayConfig{ProveMode: mode}}
		if !node.shouldSettleAsync() {
			t.Fatalf("shouldSettleAsync(%q) = false, want true", mode)
		}
	}

	node := &OverlayNode{config: OverlayConfig{ProveMode: "mock"}}
	if node.shouldSettleAsync() {
		t.Fatal("shouldSettleAsync(mock) = true, want false")
	}
}
