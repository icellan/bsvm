package sim

import (
	"context"
	"sync"
	"testing"

	"github.com/icellan/bsvm/pkg/sim/rpc"
)

// TestBorrowMonotonicNonce verifies that concurrent Borrow/release
// cycles on a single user never produce a duplicate nonce.
func TestBorrowMonotonicNonce(t *testing.T) {
	t.Parallel()

	// Start with chainID=31337; no RPC needed for non-dirty nonce path.
	mc := rpc.NewMultiClient([]string{"http://127.0.0.1:0"})
	pool, err := NewUserPool(31337, mc)
	if err != nil {
		t.Fatalf("NewUserPool: %v", err)
	}
	users := pool.Users()
	if len(users) == 0 {
		t.Fatal("expected seeded users")
	}
	target := users[0].ID

	const n = 100
	var wg sync.WaitGroup
	results := make(chan uint64, n)
	ctx := context.Background()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, nonce, release, err := pool.Borrow(ctx, target)
			if err != nil {
				t.Errorf("borrow: %v", err)
				return
			}
			results <- nonce
			release(true)
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[uint64]bool, n)
	for nonce := range results {
		if seen[nonce] {
			t.Fatalf("duplicate nonce %d", nonce)
		}
		seen[nonce] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d nonces, got %d", n, len(seen))
	}
}

// TestReleaseRollbackOnNotConsumed verifies that release(false) rolls
// back the nonce so the next caller can reuse it.
func TestReleaseRollbackOnNotConsumed(t *testing.T) {
	t.Parallel()

	mc := rpc.NewMultiClient([]string{"http://127.0.0.1:0"})
	pool, err := NewUserPool(31337, mc)
	if err != nil {
		t.Fatalf("NewUserPool: %v", err)
	}
	target := pool.Users()[0].ID
	ctx := context.Background()

	_, a, release, err := pool.Borrow(ctx, target)
	if err != nil {
		t.Fatalf("borrow1: %v", err)
	}
	release(false) // not consumed
	_, b, release2, err := pool.Borrow(ctx, target)
	if err != nil {
		t.Fatalf("borrow2: %v", err)
	}
	defer release2(true)
	if a != b {
		t.Fatalf("expected nonce rollback to return same nonce, got %d then %d", a, b)
	}
}
