package bsvclient

import (
	"context"
	"log/slog"
	"sync"

	"github.com/icellan/bsvm/pkg/chaintracks"
)

// ReorgHandler is invoked for every ReorgEvent surfaced by chaintracks.
// Implementations decide what action to take (mark BEEFs unconfirmed,
// invoke overlay.Rollback above the finalized depth, etc.).
type ReorgHandler func(*chaintracks.ReorgEvent)

// ReorgSubscriber drives a goroutine that consumes ReorgEvents from a
// ChaintracksClient and dispatches them to the registered handler.
// Construct via NewReorgSubscriber, call Start to begin, Stop to wait
// for shutdown.
type ReorgSubscriber struct {
	client  chaintracks.ChaintracksClient
	handler ReorgHandler

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewReorgSubscriber returns a subscriber bound to client; handler is
// invoked synchronously for each ReorgEvent so callers should keep
// the work bounded or dispatch to a queue.
func NewReorgSubscriber(client chaintracks.ChaintracksClient, handler ReorgHandler) *ReorgSubscriber {
	return &ReorgSubscriber{client: client, handler: handler}
}

// Start begins consuming reorg events. Calling Start twice is a no-op.
func (s *ReorgSubscriber) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	ch, err := s.client.SubscribeReorgs(ctx)
	if err != nil {
		cancel()
		return err
	}
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.run(ctx, ch)
	return nil
}

// Stop signals the subscriber to exit and blocks until the goroutine
// has returned.
func (s *ReorgSubscriber) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}

func (s *ReorgSubscriber) run(ctx context.Context, ch <-chan *chaintracks.ReorgEvent) {
	defer close(s.done)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev == nil {
				continue
			}
			slog.Info("chaintracks reorg",
				"commonAncestor", ev.CommonAncestor,
				"oldChainLen", ev.OldChainLen,
				"newChainLen", ev.NewChainLen,
			)
			if s.handler != nil {
				s.handler(ev)
			}
		}
	}
}
