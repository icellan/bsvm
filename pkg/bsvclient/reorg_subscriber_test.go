package bsvclient

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/chaintracks"
)

func TestReorgSubscriberDispatch(t *testing.T) {
	c := chaintracks.NewInMemoryClient()
	var (
		mu   sync.Mutex
		seen []*chaintracks.ReorgEvent
	)
	sub := NewReorgSubscriber(c, func(ev *chaintracks.ReorgEvent) {
		mu.Lock()
		seen = append(seen, ev)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sub.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sub.Stop()

	ev := &chaintracks.ReorgEvent{OldChainLen: 5, NewChainLen: 6}
	c.EmitReorg(ev)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("got %d events, want 1", len(seen))
	}
}

func TestReorgSubscriberStop(t *testing.T) {
	c := chaintracks.NewInMemoryClient()
	sub := NewReorgSubscriber(c, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sub.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sub.Stop()
	// idempotent
	sub.Stop()
}
