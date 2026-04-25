package sim

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/sim/rpc"
	"github.com/icellan/bsvm/pkg/types"
)

// NodeStats is a point-in-time snapshot of one node's health signals.
type NodeStats struct {
	URL        string
	Healthy    bool
	BlockNum   uint64
	PeerCount  uint64
	ProveMode  string
	ProveState string
	LastPoll   time.Time
	Err        string
}

// EngineStats aggregates the simulator's rolling counters for the TUI /
// headless printer.
type EngineStats struct {
	ChainID   uint64
	TPS5s     float64
	TPS30s    float64
	Users     int
	Nodes     []NodeStats
	Workloads []WorkloadStats
	Events    []string
}

// Engine is the simulator's central coordinator: owns the user pool +
// workload registry + node monitor. All mutation paths flow through
// here; the TUI never pokes workload state directly.
type Engine struct {
	Pool *UserPool
	Reg  *Registry
	MC   *rpc.MultiClient

	Deploy  *Deployments
	ChainID uint64

	// Rolling tx counters for the TPS ticker.
	txCount atomic.Uint64
	tps     atomic.Value // tpsSnapshot

	// Node monitoring.
	nodeMu    sync.RWMutex
	nodeStats []NodeStats

	// Event log (latest N entries).
	evMu  sync.Mutex
	evBuf []string
	evCap int

	// observer receives per-tx stats + engine-wide state updates.
	observer atomic.Value // func(EngineStats)
}

// NewEngine constructs an engine bound to the pool + registry and
// records the initial node-stats snapshot.
func NewEngine(pool *UserPool, reg *Registry, chainID uint64) *Engine {
	e := &Engine{
		Pool:      pool,
		Reg:       reg,
		MC:        pool.MultiClient(),
		ChainID:   chainID,
		nodeStats: make([]NodeStats, pool.MultiClient().Len()),
		evCap:     60,
	}
	for i, c := range e.MC.All() {
		e.nodeStats[i].URL = c.URL()
	}
	reg.SetListener(func(WorkloadStats) {})
	return e
}

func (e *Engine) totalSucceeded() uint64 {
	var sum uint64
	for _, s := range e.Reg.Snapshot() {
		sum += s.Succeeded
	}
	return sum
}

// SetObserver registers a callback invoked on stats / event changes.
func (e *Engine) SetObserver(fn func(EngineStats)) {
	e.observer.Store(fn)
}

// SetupDeployments deploys the full contract suite and caches the
// addresses on the engine. Call once after constructing the engine.
func (e *Engine) SetupDeployments(ctx context.Context) error {
	d, err := Deploy(ctx, e.Pool)
	if err != nil {
		return err
	}
	e.Deploy = d
	e.Log(fmt.Sprintf("deployed ERC20A=%s", short(d.ERC20A)))
	e.Log(fmt.Sprintf("deployed AMM=%s", short(d.AMM)))
	return nil
}

// RegisterDefaultWorkloads wires up the built-in workloads using the
// engine's deployment cache. Returns immediately; workloads remain
// inactive until Registry.Start is called.
func (e *Engine) RegisterDefaultWorkloads(defaultRate int) {
	if e.Deploy != nil {
		e.Reg.Register(NewERC20Workload(e.Pool, e.Reg, e.Deploy.ERC20A, defaultRate))
		e.Reg.Register(NewStorageWorkload(e.Pool, e.Reg, e.Deploy.Storage, defaultRate))
		e.Reg.Register(NewERC721Workload(e.Pool, e.Reg, e.Deploy.ERC721, defaultRate))
		e.Reg.Register(NewWETHWorkload(e.Pool, e.Reg, e.Deploy.WETH, defaultRate))
		e.Reg.Register(NewAMMWorkload(e.Pool, e.Reg, e.Deploy.ERC20A, e.Deploy.ERC20B, e.Deploy.AMM, defaultRate))
		// Multisig uses the first 5 sim users as owners (matches the
		// required=min(3, len(owners)) deploy time choice).
		owners := e.firstNUsersAddrs(5)
		required := 3
		if len(owners) < required {
			required = len(owners)
		}
		if len(owners) > 0 {
			e.Reg.Register(NewMultisigWorkload(e.Pool, e.Reg, e.Deploy.Multisig, required, owners, defaultRate))
		}
	}
	e.Reg.Register(NewTransferWorkload(e.Pool, e.Reg, defaultRate))
}

func (e *Engine) firstNUsersAddrs(n int) []types.Address {
	users := e.Pool.Users()
	if n > len(users) {
		n = len(users)
	}
	out := make([]types.Address, n)
	for i := 0; i < n; i++ {
		out[i] = users[i].Address
	}
	return out
}

// StartNodeMonitor runs a goroutine that polls each node every
// `interval` for health + height + peer count and updates the
// internal stats snapshot.
func (e *Engine) StartNodeMonitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		e.pollNodes(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.pollNodes(ctx)
			}
		}
	}()
}

func (e *Engine) pollNodes(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	clients := e.MC.All()
	new := make([]NodeStats, len(clients))
	for i, c := range clients {
		n := NodeStats{URL: c.URL(), LastPoll: time.Now()}
		bn, err := c.BlockNumber(pctx)
		if err != nil {
			n.Err = err.Error()
			new[i] = n
			continue
		}
		n.BlockNum = bn
		pc, err := c.PeerCount(pctx)
		if err == nil {
			n.PeerCount = pc
		}
		health, _ := c.BsvNetworkHealth(pctx)
		if health != nil {
			if s, ok := health["prove_mode"].(string); ok {
				n.ProveMode = s
			}
			if s, ok := health["prove_state"].(string); ok {
				n.ProveState = s
			}
		}
		n.Healthy = true
		new[i] = n
	}
	e.nodeMu.Lock()
	e.nodeStats = new
	e.nodeMu.Unlock()
}

// NodeStats returns a snapshot of the most recent node poll.
func (e *Engine) NodeStats() []NodeStats {
	e.nodeMu.RLock()
	defer e.nodeMu.RUnlock()
	out := make([]NodeStats, len(e.nodeStats))
	copy(out, e.nodeStats)
	return out
}

// Log appends a line to the event ring.
func (e *Engine) Log(msg string) {
	line := time.Now().Format("15:04:05") + "  " + msg
	e.evMu.Lock()
	e.evBuf = append(e.evBuf, line)
	if len(e.evBuf) > e.evCap {
		e.evBuf = e.evBuf[len(e.evBuf)-e.evCap:]
	}
	e.evMu.Unlock()
}

// Events returns a snapshot of the recent log lines.
func (e *Engine) Events() []string {
	e.evMu.Lock()
	defer e.evMu.Unlock()
	out := make([]string, len(e.evBuf))
	copy(out, e.evBuf)
	return out
}

// EngineStats composes the full snapshot used by the UI / headless tick.
func (e *Engine) EngineStats() EngineStats {
	s := EngineStats{
		ChainID:   e.ChainID,
		Users:     e.Pool.Count(),
		Nodes:     e.NodeStats(),
		Workloads: e.Reg.Snapshot(),
		Events:    e.Events(),
	}
	if t, ok := e.tps.Load().(tpsSnapshot); ok {
		s.TPS5s = t.tps5
		s.TPS30s = t.tps30
	}
	return s
}

// tpsSnapshot holds the most recent rolling-window TPS figures.
type tpsSnapshot struct {
	tps5, tps30 float64
}

// StartTPSTicker samples the global Succeeded counter every second and
// publishes rolling 5s/30s TPS via the observer.
func (e *Engine) StartTPSTicker(ctx context.Context) {
	go func() {
		samples5 := make([]uint64, 5)
		samples30 := make([]uint64, 30)
		prev := e.totalSucceeded()
		idx := 0
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cur := e.totalSucceeded()
			delta := cur - prev
			prev = cur
			samples5[idx%5] = delta
			samples30[idx%30] = delta
			idx++
			e.tps.Store(tpsSnapshot{
				tps5:  avg(samples5, minInt(idx, 5)),
				tps30: avg(samples30, minInt(idx, 30)),
			})
			obs, _ := e.observer.Load().(func(EngineStats))
			if obs != nil {
				obs(e.EngineStats())
			}
		}
	}()
}

func avg(v []uint64, n int) float64 {
	if n == 0 {
		return 0
	}
	var s uint64
	for i := 0; i < n; i++ {
		s += v[i]
	}
	return float64(s) / float64(n)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func short(a types.Address) string {
	h := a.Hex()
	if len(h) < 10 {
		return h
	}
	return h[:6] + ".." + h[len(h)-4:]
}

// AddUser adds a sim user and funds it from the faucet.
func (e *Engine) AddUser(ctx context.Context, fundWei *uint256.Int) (*User, error) {
	u, err := e.Pool.AddUser(ctx, fundWei)
	if err != nil {
		return nil, err
	}
	e.Log(fmt.Sprintf("+user %s=%s", u.Name, short(u.Address)))
	return u, nil
}

// RemoveUser removes a sim user. No dust recovery yet.
func (e *Engine) RemoveUser(id string) bool {
	if e.Pool.RemoveUser(id) {
		e.Log(fmt.Sprintf("-user %s", id))
		return true
	}
	return false
}
