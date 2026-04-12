// Package event provides a typed event feed for intra-process pub/sub.
// It implements one-to-many subscriptions where the carrier of events is a channel,
// modelled after geth's event.Feed but with zero geth imports.
package event

import (
	"errors"
	"reflect"
	"sync"
)

// Subscription represents a feed subscription. It provides an error channel
// that signals when the subscription ends, and a method to cancel the subscription.
type Subscription interface {
	// Err returns the subscription error channel. It produces a value when
	// the subscription has ended due to an error or the feed being closed.
	// The error is nil if the subscriber called Unsubscribe.
	Err() <-chan error

	// Unsubscribe cancels the subscription. After calling Unsubscribe,
	// the Err channel is closed.
	Unsubscribe()
}

// ErrClosed is returned when a subscription is made to a closed feed.
var ErrClosed = errors.New("event: feed closed")

// subscription is the concrete implementation of Subscription returned by Feed.Subscribe.
type subscription struct {
	feed    *Feed
	channel reflect.Value // the subscriber's channel, stored as reflect.Value for TrySend
	once    sync.Once
	err     chan error
	removed bool // protected by feed.mu
}

// Unsubscribe cancels the subscription. It is safe to call multiple times.
// After calling Unsubscribe, the Err channel is closed with a nil error.
func (s *subscription) Unsubscribe() {
	s.once.Do(func() {
		s.feed.remove(s)
		close(s.err)
	})
}

// Err returns the subscription error channel.
func (s *subscription) Err() <-chan error {
	return s.err
}

// funcSub implements Subscription for NewSubscription. It runs a producer
// function in a goroutine and forwards any error to the error channel.
type funcSub struct {
	err     chan error
	quit    chan struct{}
	once    sync.Once
	unsubWg sync.WaitGroup
}

// Unsubscribe cancels the producer goroutine and closes the error channel.
func (s *funcSub) Unsubscribe() {
	s.once.Do(func() {
		close(s.quit)
		s.unsubWg.Wait()
		close(s.err)
	})
}

// Err returns the subscription error channel.
func (s *funcSub) Err() <-chan error {
	return s.err
}

// NewSubscription creates a new subscription that runs the producer function
// as a goroutine. The producer receives a quit channel; when the channel is
// closed, the producer should return. If the producer returns a non-nil error,
// it is sent on the error channel.
func NewSubscription(producer func(quit <-chan struct{}) error) Subscription {
	s := &funcSub{
		err:  make(chan error, 1),
		quit: make(chan struct{}),
	}
	s.unsubWg.Add(1)
	go func() {
		defer s.unsubWg.Done()
		err := producer(s.quit)
		if err != nil {
			select {
			case s.err <- err:
			default:
			}
		}
	}()
	return s
}
