package sim

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// WorkloadKind enumerates the workload types available to the sim.
type WorkloadKind string

const (
	KindValueTransfer WorkloadKind = "value-transfer"
	KindERC20Transfer WorkloadKind = "erc20-transfer"
	KindStorageSet    WorkloadKind = "storage-set"
	KindERC721Mint    WorkloadKind = "erc721-mint"
	KindWETHCycle     WorkloadKind = "weth-cycle"
	KindAMMSwap       WorkloadKind = "amm-swap"
	KindMultisig      WorkloadKind = "multisig"
)

// WorkloadStats is a point-in-time snapshot of a workload's counters.
type WorkloadStats struct {
	Kind            WorkloadKind
	Rate            int
	Running         bool
	Submitted       uint64
	Succeeded       uint64
	Failed          uint64
	LastErr         string
	LastLatencyMs   uint64
	RollingLatency1 uint64 // avg of the last N latencies (ms)
}

// Workload is one active traffic generator. Implementations serialise
// their own state — the registry only sequences start/stop.
type Workload interface {
	Kind() WorkloadKind
	Run(ctx context.Context)
	SetRate(tps int)
	Stats() WorkloadStats
}

// Registry owns the active workloads. Registry methods are goroutine-
// safe; start/stop never blocks producers.
type Registry struct {
	mu      sync.Mutex
	entries map[WorkloadKind]*regEntry
	// listener is called after every Stats change so the TUI can refresh.
	listener func(WorkloadStats)
}

type regEntry struct {
	wl     Workload
	cancel context.CancelFunc
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[WorkloadKind]*regEntry)}
}

// SetListener registers a callback invoked on every successful tx /
// failure. Invoked synchronously on the workload goroutine — the
// callback must not block.
func (r *Registry) SetListener(fn func(WorkloadStats)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listener = fn
}

// Register adds a workload without starting it. The returned handle is
// used by Start/Stop/Snapshot.
func (r *Registry) Register(w Workload) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[w.Kind()] = &regEntry{wl: w}
}

// Start begins generating traffic for the named workload. Returns an
// error if the kind isn't registered or is already running.
func (r *Registry) Start(parent context.Context, kind WorkloadKind) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[kind]
	if !ok {
		return fmt.Errorf("unknown workload %q", kind)
	}
	if e.cancel != nil {
		return fmt.Errorf("workload %q already running", kind)
	}
	ctx, cancel := context.WithCancel(parent)
	e.cancel = cancel
	go e.wl.Run(ctx)
	return nil
}

// Stop cancels the workload's context. The workload goroutine is
// responsible for draining on ctx.Done().
func (r *Registry) Stop(kind WorkloadKind) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[kind]
	if !ok {
		return fmt.Errorf("unknown workload %q", kind)
	}
	if e.cancel == nil {
		return nil
	}
	e.cancel()
	e.cancel = nil
	return nil
}

// SetRate updates the workload's target tx/s in place. Negative rates
// are treated as 0 (pause).
func (r *Registry) SetRate(kind WorkloadKind, tps int) error {
	r.mu.Lock()
	e, ok := r.entries[kind]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown workload %q", kind)
	}
	if tps < 0 {
		tps = 0
	}
	e.wl.SetRate(tps)
	return nil
}

// Get returns the concrete workload registered under kind, or nil.
func (r *Registry) Get(kind WorkloadKind) Workload {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[kind]; ok {
		return e.wl
	}
	return nil
}

// Snapshot returns a stable, deterministically-ordered list of stats.
func (r *Registry) Snapshot() []WorkloadStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]WorkloadStats, 0, len(r.entries))
	for _, e := range r.entries {
		s := e.wl.Stats()
		s.Running = e.cancel != nil
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// notify calls the listener if one is attached. Safe to call from
// workload goroutines.
func (r *Registry) notify(s WorkloadStats) {
	r.mu.Lock()
	fn := r.listener
	r.mu.Unlock()
	if fn != nil {
		fn(s)
	}
}

// baseStats is embedded by every concrete workload to provide the
// atomic counters + rate control. Implementations expose it via Stats().
type baseStats struct {
	kind        WorkloadKind
	rate        atomic.Int32
	submitted   atomic.Uint64
	succeeded   atomic.Uint64
	failed      atomic.Uint64
	lastErrMsg  atomic.Value // string
	lastFailAt  atomic.Int64 // ms
	lastLatency atomic.Uint64

	// rolling avg of the last N successful latencies (ms).
	latMu      sync.Mutex
	latWindow  []uint64
	latCursor  int
	latFill    int
	avgLatency atomic.Uint64
}

// initBaseStats populates an embedded baseStats in place. Using an
// initialiser avoids the noCopy vet warning that returning a baseStats
// value triggers because of the atomic fields.
func initBaseStats(b *baseStats, kind WorkloadKind, initialRate int, window int) {
	b.kind = kind
	b.latWindow = make([]uint64, window)
	b.rate.Store(int32(initialRate))
}

func (b *baseStats) snapshot() WorkloadStats {
	s := WorkloadStats{
		Kind:            b.kind,
		Rate:            int(b.rate.Load()),
		Submitted:       b.submitted.Load(),
		Succeeded:       b.succeeded.Load(),
		Failed:          b.failed.Load(),
		LastLatencyMs:   b.lastLatency.Load(),
		RollingLatency1: b.avgLatency.Load(),
	}
	if v := b.lastErrMsg.Load(); v != nil {
		s.LastErr = v.(string)
	}
	return s
}

func (b *baseStats) recordSuccess(latency time.Duration) {
	b.succeeded.Add(1)
	ms := uint64(latency / time.Millisecond)
	b.lastLatency.Store(ms)
	b.latMu.Lock()
	b.latWindow[b.latCursor] = ms
	b.latCursor = (b.latCursor + 1) % len(b.latWindow)
	if b.latFill < len(b.latWindow) {
		b.latFill++
	}
	var sum uint64
	for i := 0; i < b.latFill; i++ {
		sum += b.latWindow[i]
	}
	avg := sum / uint64(b.latFill)
	b.latMu.Unlock()
	b.avgLatency.Store(avg)
}

func (b *baseStats) recordFailure(err error) {
	b.failed.Add(1)
	if err != nil {
		b.lastErrMsg.Store(err.Error())
	}
	b.lastFailAt.Store(time.Now().UnixMilli())
}

// waitTick sleeps for the interval implied by the current rate, returning
// false if ctx is cancelled. Rate 0 sleeps for 500ms then re-checks so
// the workload doesn't spin. Recent mempool-backpressure failures extend
// the sleep so we stop pummelling the node.
func waitTick(ctx context.Context, b *baseStats) bool {
	r := b.rate.Load()
	var interval time.Duration
	if r <= 0 {
		interval = 500 * time.Millisecond
	} else {
		interval = time.Second / time.Duration(r)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
	}
	// If we failed in the last second, pause an extra beat — likely
	// mempool full or nonce reconcile in progress.
	if t := b.lastFailAt.Load(); t > 0 {
		if time.Since(time.UnixMilli(t)) < time.Second {
			interval += 500 * time.Millisecond
		}
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(interval):
		return true
	}
}
