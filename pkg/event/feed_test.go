package event

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSubscribeAndReceiveSingleEvent(t *testing.T) {
	var feed Feed
	ch := make(chan int, 1)
	sub := feed.Subscribe(ch)
	defer sub.Unsubscribe()

	feed.Send(42)

	select {
	case v := <-ch:
		if v != 42 {
			t.Fatalf("expected 42, got %d", v)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestMultipleSubscribersReceiveSameEvent(t *testing.T) {
	var feed Feed
	ch1 := make(chan string, 1)
	ch2 := make(chan string, 1)
	ch3 := make(chan string, 1)

	sub1 := feed.Subscribe(ch1)
	sub2 := feed.Subscribe(ch2)
	sub3 := feed.Subscribe(ch3)
	defer sub1.Unsubscribe()
	defer sub2.Unsubscribe()
	defer sub3.Unsubscribe()

	n := feed.Send("hello")
	if n != 3 {
		t.Fatalf("expected Send to return 3, got %d", n)
	}

	for i, ch := range []chan string{ch1, ch2, ch3} {
		select {
		case v := <-ch:
			if v != "hello" {
				t.Fatalf("subscriber %d: expected \"hello\", got %q", i, v)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out waiting for event", i)
		}
	}
}

func TestUnsubscribeStopsReceiving(t *testing.T) {
	var feed Feed
	ch := make(chan int, 1)
	sub := feed.Subscribe(ch)

	// Send before unsubscribe — should receive.
	feed.Send(1)
	select {
	case v := <-ch:
		if v != 1 {
			t.Fatalf("expected 1, got %d", v)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first event")
	}

	sub.Unsubscribe()

	// Send after unsubscribe — should not receive.
	feed.Send(2)
	select {
	case v := <-ch:
		t.Fatalf("received event %d after unsubscribe", v)
	case <-time.After(50 * time.Millisecond):
		// expected: no event received
	}
}

func TestUnsubscribeIsIdempotent(t *testing.T) {
	var feed Feed
	ch := make(chan int, 1)
	sub := feed.Subscribe(ch)

	// Calling Unsubscribe multiple times should not panic.
	sub.Unsubscribe()
	sub.Unsubscribe()
	sub.Unsubscribe()
}

func TestSendReturnsCorrectCount(t *testing.T) {
	var feed Feed

	// No subscribers.
	n := feed.Send(1)
	if n != 0 {
		t.Fatalf("expected 0 with no subscribers, got %d", n)
	}

	// One subscriber.
	ch1 := make(chan int, 1)
	sub1 := feed.Subscribe(ch1)
	n = feed.Send(2)
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
	<-ch1

	// Two subscribers.
	ch2 := make(chan int, 1)
	sub2 := feed.Subscribe(ch2)
	n = feed.Send(3)
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
	<-ch1
	<-ch2

	// Unsubscribe one, back to one.
	sub1.Unsubscribe()
	n = feed.Send(4)
	if n != 1 {
		t.Fatalf("expected 1 after unsubscribe, got %d", n)
	}
	<-ch2

	sub2.Unsubscribe()
	n = feed.Send(5)
	if n != 0 {
		t.Fatalf("expected 0 after all unsubscribed, got %d", n)
	}
}

func TestSubscribeWithDifferentBufferSizes(t *testing.T) {
	var feed Feed

	// Buffer size 0 (unbuffered) — TrySend will fail since no goroutine is receiving.
	chUnbuffered := make(chan int)
	subUnbuffered := feed.Subscribe(chUnbuffered)
	defer subUnbuffered.Unsubscribe()

	// Buffer size 1.
	chBuf1 := make(chan int, 1)
	subBuf1 := feed.Subscribe(chBuf1)
	defer subBuf1.Unsubscribe()

	// Buffer size 10.
	chBuf10 := make(chan int, 10)
	subBuf10 := feed.Subscribe(chBuf10)
	defer subBuf10.Unsubscribe()

	// Send should succeed for buffered channels and skip the unbuffered one.
	n := feed.Send(99)
	if n != 2 {
		t.Fatalf("expected 2 (buffered channels only), got %d", n)
	}

	v1 := <-chBuf1
	if v1 != 99 {
		t.Fatalf("chBuf1: expected 99, got %d", v1)
	}
	v10 := <-chBuf10
	if v10 != 99 {
		t.Fatalf("chBuf10: expected 99, got %d", v10)
	}
}

func TestFullBufferSkipsSubscriber(t *testing.T) {
	var feed Feed
	ch := make(chan int, 1)
	sub := feed.Subscribe(ch)
	defer sub.Unsubscribe()

	// Fill the buffer.
	feed.Send(1)
	// Second send should skip this subscriber since its buffer is full.
	n := feed.Send(2)
	if n != 0 {
		t.Fatalf("expected 0 (buffer full), got %d", n)
	}

	// Drain and verify we got the first event.
	v := <-ch
	if v != 1 {
		t.Fatalf("expected 1, got %d", v)
	}
}

func TestConcurrentSendSubscribe(t *testing.T) {
	var feed Feed
	var wg sync.WaitGroup
	const numGoroutines = 50
	const numSends = 100

	// Start subscriber goroutines.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch := make(chan int, numSends)
			sub := feed.Subscribe(ch)
			defer sub.Unsubscribe()

			// Drain events to avoid blocking.
			for j := 0; j < numSends; j++ {
				select {
				case <-ch:
				case <-time.After(2 * time.Second):
					return
				}
			}
		}()
	}

	// Start sender goroutines.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numSends; j++ {
				feed.Send(j)
			}
		}()
	}

	// If there's a data race, the race detector will catch it.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for concurrent test to complete")
	}
}

func TestSubscribePanicsOnNonChannel(t *testing.T) {
	var feed Feed
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for non-channel argument")
		}
	}()
	feed.Subscribe("not a channel")
}

func TestSubscribePanicsOnTypeMismatch(t *testing.T) {
	var feed Feed
	ch1 := make(chan int, 1)
	feed.Subscribe(ch1)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for mismatched channel type")
		}
	}()
	ch2 := make(chan string, 1)
	feed.Subscribe(ch2)
}

func TestSendPanicsOnTypeMismatch(t *testing.T) {
	var feed Feed
	ch := make(chan int, 1)
	feed.Subscribe(ch)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for mismatched Send type")
		}
	}()
	feed.Send("wrong type")
}

func TestNewSubscription(t *testing.T) {
	sub := NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})

	sub.Unsubscribe()

	// Err channel should be closed after Unsubscribe.
	select {
	case _, ok := <-sub.Err():
		if ok {
			t.Fatal("expected Err channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Err channel to close")
	}
}

func TestNewSubscriptionWithError(t *testing.T) {
	testErr := errors.New("test error")
	sub := NewSubscription(func(quit <-chan struct{}) error {
		return testErr
	})

	select {
	case err := <-sub.Err():
		if err != testErr {
			t.Fatalf("expected %v, got %v", testErr, err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for error")
	}

	sub.Unsubscribe()
}

func TestErrChannelClosedAfterUnsubscribe(t *testing.T) {
	var feed Feed
	ch := make(chan int, 1)
	sub := feed.Subscribe(ch)

	sub.Unsubscribe()

	// Err channel should be closed.
	select {
	case _, ok := <-sub.Err():
		if ok {
			t.Fatal("expected Err channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Err channel to close")
	}
}

type testEvent struct {
	ID   int
	Data string
}

func TestStructEvents(t *testing.T) {
	var feed Feed
	ch := make(chan testEvent, 1)
	sub := feed.Subscribe(ch)
	defer sub.Unsubscribe()

	ev := testEvent{ID: 1, Data: "test"}
	feed.Send(ev)

	select {
	case got := <-ch:
		if got.ID != ev.ID || got.Data != ev.Data {
			t.Fatalf("expected %+v, got %+v", ev, got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for struct event")
	}
}
