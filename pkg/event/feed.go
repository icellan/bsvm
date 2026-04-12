package event

import (
	"fmt"
	"reflect"
	"sync"
)

// Feed implements one-to-many subscriptions where the carrier of events is a channel.
// Values sent to a Feed are delivered to all subscribed channels simultaneously.
//
// The zero value is ready to use.
//
// Subscribers are expected to provide buffered channels. If a subscriber's channel
// is full when Send is called, that subscriber is skipped for that event (non-blocking send).
type Feed struct {
	mu    sync.Mutex
	subs  []*subscription
	etype reflect.Type
}

// Subscribe adds a channel to the feed. The channel argument must be a
// bidirectional or send-only channel. Its element type must match the feed's
// established element type (set by the first call to Subscribe or Send).
//
// Returns a Subscription that can be used to unsubscribe.
//
// The panics below indicate programming errors (wrong channel type or
// type mismatch), following Go's convention for type-assertion failures.
// They cannot be triggered by user input — only by incorrect API usage
// in application code.
func (f *Feed) Subscribe(channel interface{}) Subscription {
	chanVal := reflect.ValueOf(channel)
	chanType := chanVal.Type()
	if chanType.Kind() != reflect.Chan {
		panic(fmt.Sprintf("event: Subscribe argument must be a channel, got %s", chanType))
	}
	if chanType.ChanDir()&reflect.SendDir == 0 {
		panic("event: Subscribe argument must be a sendable channel (chan or chan<-)")
	}

	elemType := chanType.Elem()

	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.typecheck(elemType) {
		panic(fmt.Sprintf("event: channel element type %s does not match feed type %s", elemType, f.etype))
	}

	sub := &subscription{
		feed:    f,
		channel: chanVal,
		err:     make(chan error, 1),
	}
	f.subs = append(f.subs, sub)
	return sub
}

// typecheck validates and sets the feed's element type. Returns true if the type
// is compatible. Must be called with f.mu held.
func (f *Feed) typecheck(elemType reflect.Type) bool {
	if f.etype == nil {
		f.etype = elemType
		return true
	}
	return f.etype == elemType
}

// Send delivers an event to all subscribed channels simultaneously using a
// non-blocking send. If a subscriber's channel buffer is full, that subscriber
// is skipped. Returns the number of subscribers the event was sent to.
//
// Send panics if the value's type does not match the feed's element type.
// This is a programming error (type mismatch), not a user-input error.
func (f *Feed) Send(value interface{}) int {
	rval := reflect.ValueOf(value)

	f.mu.Lock()

	if f.etype == nil {
		f.etype = rval.Type()
	} else if rval.Type() != f.etype {
		f.mu.Unlock()
		panic(fmt.Sprintf("event: Send value type %s does not match feed type %s", rval.Type(), f.etype))
	}

	// Take a snapshot of active subscriptions so we can release the lock
	// before doing the (potentially slow) channel sends.
	subs := make([]*subscription, 0, len(f.subs))
	for _, sub := range f.subs {
		if !sub.removed {
			subs = append(subs, sub)
		}
	}
	f.mu.Unlock()

	sent := 0
	for _, sub := range subs {
		// Non-blocking send. We use reflect because the channel type is dynamic.
		if sub.channel.TrySend(rval) {
			sent++
		}
	}
	return sent
}

// remove marks a subscription as removed and cleans up the subscription list.
func (f *Feed) remove(sub *subscription) {
	f.mu.Lock()
	defer f.mu.Unlock()

	sub.removed = true

	// Compact: remove all marked subscriptions.
	n := 0
	for _, s := range f.subs {
		if !s.removed {
			f.subs[n] = s
			n++
		}
	}
	// Clear trailing references to allow GC.
	for i := n; i < len(f.subs); i++ {
		f.subs[i] = nil
	}
	f.subs = f.subs[:n]
}
