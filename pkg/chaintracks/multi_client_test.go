package chaintracks

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

// fakeClient is a programmable in-memory ChaintracksClient used to
// drive MultiClient through specific quorum scenarios.
type fakeClient struct {
	mu        sync.Mutex
	tip       *BlockHeader
	tipErr    error
	byHeight  map[uint64]*BlockHeader
	byHash    map[[32]byte]*BlockHeader
	pingErr   error
	delay     time.Duration
	subs      []chan *ReorgEvent
	subsClose bool
}

func newFake(name byte, height uint64, hash [32]byte, work int64) *fakeClient {
	h := &BlockHeader{Height: height, Hash: hash, Work: big.NewInt(work)}
	return &fakeClient{
		tip:      h,
		byHeight: map[uint64]*BlockHeader{height: h},
		byHash:   map[[32]byte]*BlockHeader{hash: h},
	}
}

func (f *fakeClient) setTip(h *BlockHeader) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tip = h
	if h != nil {
		f.byHeight[h.Height] = h
		f.byHash[h.Hash] = h
	}
}

func (f *fakeClient) Tip(ctx context.Context) (*BlockHeader, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tipErr != nil {
		return nil, f.tipErr
	}
	if f.tip == nil {
		return nil, ErrUnknownHeader
	}
	dup := *f.tip
	return &dup, nil
}

func (f *fakeClient) HeaderByHash(ctx context.Context, hash [32]byte) (*BlockHeader, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.byHash[hash]
	if !ok {
		return nil, ErrUnknownHeader
	}
	dup := *h
	return &dup, nil
}

func (f *fakeClient) HeaderByHeight(ctx context.Context, height uint64) (*BlockHeader, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.byHeight[height]
	if !ok {
		return nil, ErrUnknownHeader
	}
	dup := *h
	return &dup, nil
}

func (f *fakeClient) MerkleRootAtHeight(ctx context.Context, height uint64) ([32]byte, error) {
	h, err := f.HeaderByHeight(ctx, height)
	if err != nil {
		return [32]byte{}, err
	}
	return h.MerkleRoot, nil
}

func (f *fakeClient) Confirmations(ctx context.Context, height uint64, hash [32]byte) (int64, error) {
	return 0, nil
}

func (f *fakeClient) SubscribeReorgs(ctx context.Context) (<-chan *ReorgEvent, error) {
	f.mu.Lock()
	ch := make(chan *ReorgEvent, 8)
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, s := range f.subs {
			if s == ch {
				f.subs = append(f.subs[:i], f.subs[i+1:]...)
				break
			}
		}
		close(ch)
	}()
	return ch, nil
}

func (f *fakeClient) emit(ev *ReorgEvent) {
	f.mu.Lock()
	subs := append([]chan *ReorgEvent(nil), f.subs...)
	f.mu.Unlock()
	for _, s := range subs {
		select {
		case s <- ev:
		default:
		}
	}
}

func (f *fakeClient) Ping(ctx context.Context) error { return f.pingErr }
func (f *fakeClient) Close() error                   { return nil }

func providers(fakes ...*fakeClient) []Provider {
	out := make([]Provider, 0, len(fakes))
	names := []string{"a", "b", "c", "d", "e"}
	for i, f := range fakes {
		out = append(out, Provider{Name: names[i], Client: f})
	}
	return out
}

// --- Quorum policy tests ------------------------------------------

func TestMultiClient_AllAgree(t *testing.T) {
	hash := mkHash(0x42)
	a := newFake('a', 100, hash, 10)
	b := newFake('b', 100, hash, 10)
	c := newFake('c', 100, hash, 10)

	mc, err := NewMultiClient(MultiConfig{
		Providers: providers(a, b, c),
		QuorumM:   2,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	tip, err := mc.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Hash != hash || tip.Height != 100 {
		t.Fatalf("tip mismatch: %+v", tip)
	}
}

func TestMultiClient_QuorumMet_OneDissents(t *testing.T) {
	hashGood := mkHash(0x42)
	hashBad := mkHash(0x43)
	a := newFake('a', 100, hashGood, 10)
	b := newFake('b', 100, hashGood, 10)
	c := newFake('c', 100, hashBad, 10) // dissenter

	mc, err := NewMultiClient(MultiConfig{
		Providers:          providers(a, b, c),
		QuorumM:            2,
		DisagreementAction: ActionDrop,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	tip, err := mc.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Hash != hashGood {
		t.Fatalf("expected good hash, got %x", tip.Hash)
	}
	// Dissenter should be marked.
	hs := mc.Health()
	var cStat ProviderHealth
	for _, h := range hs {
		if h.Name == "c" {
			cStat = h
		}
	}
	if cStat.Disagreements != 1 {
		t.Fatalf("expected c.Disagreements==1, got %d", cStat.Disagreements)
	}
	if cStat.SuspendedUntil.IsZero() {
		t.Fatalf("expected c to be suspended after ActionDrop")
	}
}

func TestMultiClient_QuorumNotMet_StrategyMOfN(t *testing.T) {
	a := newFake('a', 100, mkHash(0xa1), 10)
	b := newFake('b', 100, mkHash(0xb1), 10)
	c := newFake('c', 100, mkHash(0xc1), 10)

	mc, err := NewMultiClient(MultiConfig{
		Providers: providers(a, b, c),
		Strategy:  StrategyMOfN,
		QuorumM:   2,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	_, err = mc.Tip(context.Background())
	if !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("expected ErrQuorumUnavailable, got %v", err)
	}
}

func TestMultiClient_QuorumNotMet_HybridFallback(t *testing.T) {
	// Three different hashes, but provider 'b' has highest work.
	a := newFake('a', 100, mkHash(0xa1), 5)
	b := newFake('b', 100, mkHash(0xb1), 50)
	c := newFake('c', 100, mkHash(0xc1), 10)

	mc, err := NewMultiClient(MultiConfig{
		Providers: providers(a, b, c),
		Strategy:  StrategyHybrid,
		QuorumM:   2,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	tip, err := mc.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Hash != mkHash(0xb1) {
		t.Fatalf("expected highest-work winner b, got %x", tip.Hash)
	}
}

func TestMultiClient_OneDown_StillServesQuorum(t *testing.T) {
	hash := mkHash(0x77)
	a := newFake('a', 200, hash, 100)
	b := newFake('b', 200, hash, 100)
	c := newFake('c', 0, [32]byte{}, 0)
	c.tipErr = errors.New("provider c down")

	mc, err := NewMultiClient(MultiConfig{
		Providers: providers(a, b, c),
		QuorumM:   2,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	tip, err := mc.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Hash != hash {
		t.Fatalf("expected %x, got %x", hash, tip.Hash)
	}
	hs := mc.Health()
	for _, h := range hs {
		if h.Name == "c" && h.Errors == 0 {
			t.Fatalf("expected c.Errors > 0")
		}
	}
}

func TestMultiClient_AllDown(t *testing.T) {
	a := newFake('a', 0, [32]byte{}, 0)
	b := newFake('b', 0, [32]byte{}, 0)
	a.tipErr = errors.New("a down")
	b.tipErr = errors.New("b down")
	mc, err := NewMultiClient(MultiConfig{
		Providers: providers(a, b),
		QuorumM:   1,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	_, err = mc.Tip(context.Background())
	if !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("expected ErrQuorumUnavailable, got %v", err)
	}
}

func TestMultiClient_HaltAction(t *testing.T) {
	hash := mkHash(0xde)
	bad := mkHash(0xad)
	a := newFake('a', 100, hash, 10)
	b := newFake('b', 100, hash, 10)
	c := newFake('c', 100, bad, 10)
	mc, err := NewMultiClient(MultiConfig{
		Providers:          providers(a, b, c),
		QuorumM:            2,
		DisagreementAction: ActionHalt,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	if _, err := mc.Tip(context.Background()); err != nil {
		t.Fatalf("first Tip should succeed and only mark halt: %v", err)
	}
	if _, err := mc.Tip(context.Background()); !errors.Is(err, ErrHalted) {
		t.Fatalf("expected ErrHalted on second call, got %v", err)
	}
}

// --- Cross-checkpoint safety --------------------------------------

type fakeStore struct {
	height uint64
	hash   [32]byte
}

func (s fakeStore) DeepestCheckpoint() (uint64, [32]byte) { return s.height, s.hash }

func TestMultiClient_CrossCheckpointFork(t *testing.T) {
	good := mkHash(0xc0)
	bad := mkHash(0xc1)
	a := newFake('a', 50, good, 10)
	b := newFake('b', 50, good, 10)
	c := newFake('c', 50, bad, 10)
	mc, err := NewMultiClient(MultiConfig{
		Providers: providers(a, b, c),
		QuorumM:   2,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	mc.SetCheckpointStore(fakeStore{height: 50, hash: good})

	_, err = mc.HeaderByHeight(context.Background(), 50)
	if !errors.Is(err, ErrCheckpointFork) {
		t.Fatalf("expected ErrCheckpointFork, got %v", err)
	}
	// Subsequent calls should be halted.
	if _, err := mc.Tip(context.Background()); !errors.Is(err, ErrHalted) {
		t.Fatalf("expected ErrHalted post-fork, got %v", err)
	}
}

// --- Stream fan-out tests -----------------------------------------

func TestMultiClient_StreamQuorumWithSkew(t *testing.T) {
	a := newFake('a', 100, mkHash(0x10), 10)
	b := newFake('b', 100, mkHash(0x10), 10)
	c := newFake('c', 100, mkHash(0x10), 10)

	mc, err := NewMultiClient(MultiConfig{
		Providers:        providers(a, b, c),
		QuorumM:          2,
		StreamSkewWindow: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := mc.SubscribeReorgs(ctx)
	if err != nil {
		t.Fatalf("SubscribeReorgs: %v", err)
	}
	ev := &ReorgEvent{NewTip: mkHash(0xee), OldTip: mkHash(0x11), CommonAncestor: mkHash(0x99)}
	a.emit(ev)
	// Provider B emits 50ms later — quorum should reach within window.
	go func() {
		time.Sleep(50 * time.Millisecond)
		b.emit(ev)
	}()

	select {
	case got := <-out:
		if got == nil || got.NewTip != ev.NewTip {
			t.Fatalf("unexpected event: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for quorum reorg")
	}
}

func TestMultiClient_StreamBelowQuorumStrategyMOfN(t *testing.T) {
	a := newFake('a', 100, mkHash(0x10), 10)
	b := newFake('b', 100, mkHash(0x10), 10)
	c := newFake('c', 100, mkHash(0x10), 10)

	mc, err := NewMultiClient(MultiConfig{
		Providers:        providers(a, b, c),
		Strategy:         StrategyMOfN,
		QuorumM:          2,
		StreamSkewWindow: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := mc.SubscribeReorgs(ctx)
	if err != nil {
		t.Fatalf("SubscribeReorgs: %v", err)
	}
	// Only one provider emits — MOfN should drop after window.
	a.emit(&ReorgEvent{NewTip: mkHash(0xff)})

	select {
	case got, ok := <-out:
		if ok {
			t.Fatalf("did not expect event under MOfN below quorum: %+v", got)
		}
	case <-time.After(400 * time.Millisecond):
		// expected: nothing emitted
	}
}

// --- Misc ---------------------------------------------------------

func TestMultiClient_ConfigValidation(t *testing.T) {
	if _, err := NewMultiClient(MultiConfig{}); err == nil {
		t.Fatal("expected error on empty providers")
	}
	a := newFake('a', 0, mkHash(0x1), 1)
	if _, err := NewMultiClient(MultiConfig{Providers: providers(a), QuorumM: 5}); err == nil {
		t.Fatal("expected error on quorum_m > providers")
	}
	mc, err := NewMultiClient(MultiConfig{Providers: providers(a)})
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	if mc.cfg.Strategy != StrategyHybrid {
		t.Fatalf("expected default StrategyHybrid, got %q", mc.cfg.Strategy)
	}
	if mc.cfg.QuorumM != 1 {
		t.Fatalf("expected default QuorumM=1, got %d", mc.cfg.QuorumM)
	}
}

func TestMultiClient_PingQuorum(t *testing.T) {
	a := newFake('a', 0, mkHash(0x1), 1)
	b := newFake('b', 0, mkHash(0x1), 1)
	c := newFake('c', 0, mkHash(0x1), 1)
	c.pingErr = errors.New("c down")

	mc, _ := NewMultiClient(MultiConfig{Providers: providers(a, b, c), QuorumM: 2})
	if err := mc.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with 2/3 OK should succeed: %v", err)
	}
	b.pingErr = errors.New("b down")
	if err := mc.Ping(context.Background()); !errors.Is(err, ErrQuorumUnavailable) {
		t.Fatalf("expected ErrQuorumUnavailable, got %v", err)
	}
}

func TestMultiClient_SatisfiesInterface(t *testing.T) {
	var _ ChaintracksClient = (*MultiClient)(nil)
}
