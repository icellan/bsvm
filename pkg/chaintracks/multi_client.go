package chaintracks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"sync"
	"time"
)

// QuorumStrategy selects how MultiClient resolves disagreement between
// child providers. See docs/decisions/header-oracle-quorum.md for the
// rationale behind the default.
type QuorumStrategy string

const (
	// StrategyMOfN requires at least M providers to report the same
	// (height, hash) pair. When fewer than M agree the call returns
	// ErrQuorumUnavailable.
	StrategyMOfN QuorumStrategy = "m_of_n"
	// StrategyHybrid is StrategyMOfN with a cumulative-work tiebreak:
	// if no group reaches M votes the highest-work group wins, provided
	// it passes PoW + checkpoint validation. This is the W6-2 default.
	StrategyHybrid QuorumStrategy = "hybrid"
)

// DisagreementAction selects what MultiClient does when child providers
// return conflicting headers but the configured quorum is still met.
// Cross-checkpoint disagreement always halts regardless of this setting.
type DisagreementAction string

const (
	// ActionLog records the divergence in per-provider stats and serves
	// the quorum-winning group.
	ActionLog DisagreementAction = "log"
	// ActionDrop suspends the deviant providers for cooldown duration.
	ActionDrop DisagreementAction = "drop"
	// ActionHalt refuses to serve any reads until operator intervention.
	ActionHalt DisagreementAction = "halt"
)

// ErrQuorumUnavailable is returned when fewer than M providers
// respond inside ResponseTimeout, or when no group reaches the
// quorum threshold under StrategyMOfN.
var ErrQuorumUnavailable = errors.New("chaintracks: quorum unavailable")

// ErrCheckpointFork is returned when two providers expose chains
// that fork below the deepest pinned checkpoint. Treated as
// an unrecoverable safety violation.
var ErrCheckpointFork = errors.New("chaintracks: providers fork below pinned checkpoint")

// ErrHalted is returned when the MultiClient has been halted by a
// previous safety failure or by ActionHalt.
var ErrHalted = errors.New("chaintracks: client halted")

// Provider wraps a child ChaintracksClient with metadata used by
// MultiClient.
type Provider struct {
	Name    string
	Weight  uint
	Timeout time.Duration
	Client  ChaintracksClient
}

// ProviderHealth exposes per-child health stats.
type ProviderHealth struct {
	Name           string
	Calls          uint64
	Errors         uint64
	Disagreements  uint64
	SuspendedUntil time.Time
	LastRTT        time.Duration
}

// MultiConfig configures a MultiClient.
type MultiConfig struct {
	// Providers is the ordered list of child clients.
	Providers []Provider
	// Strategy selects the quorum policy. Default StrategyHybrid.
	Strategy QuorumStrategy
	// QuorumM is the minimum number of agreeing providers required.
	// Must be >= 1 and <= len(Providers).
	QuorumM int
	// DisagreementAction is invoked when providers disagree but
	// quorum is still reached.
	DisagreementAction DisagreementAction
	// DisagreementCooldown is how long a provider stays suspended
	// after ActionDrop. Default 10 minutes.
	DisagreementCooldown time.Duration
	// ResponseTimeout is the per-call deadline applied when the caller's
	// context has no deadline of its own. Default 5s.
	ResponseTimeout time.Duration
	// StreamSkewWindow is how long stream events are buffered per
	// child before quorum is resolved. Default 750ms.
	StreamSkewWindow time.Duration
	// StreamBufferMax bounds the per-child reorg-event buffer.
	// Default 32.
	StreamBufferMax int
	// Logger is the structured logger. nil falls back to slog.Default().
	Logger *slog.Logger
}

// MultiClient is a ChaintracksClient that fans out to N child clients
// and applies a configurable quorum policy.
type MultiClient struct {
	cfg     MultiConfig
	mu      sync.Mutex
	health  map[string]*ProviderHealth
	halted  bool
	cpStore CheckpointStore

	subsMu sync.Mutex
	subs   []chan *ReorgEvent
	closed bool
}

// CheckpointStore is the read-side hook into W6-9's checkpoint
// validator. Optional; nil disables the cross-checkpoint safety check.
type CheckpointStore interface {
	// DeepestCheckpoint returns the highest-height pinned checkpoint.
	// (0, [32]byte{}) means no checkpoints are pinned.
	DeepestCheckpoint() (height uint64, hash [32]byte)
}

// NewMultiClient builds a MultiClient.
func NewMultiClient(cfg MultiConfig) (*MultiClient, error) {
	if len(cfg.Providers) == 0 {
		return nil, errors.New("chaintracks: at least one provider required")
	}
	if cfg.QuorumM < 1 {
		cfg.QuorumM = 1
	}
	if cfg.QuorumM > len(cfg.Providers) {
		return nil, fmt.Errorf("chaintracks: quorum_m %d > providers %d", cfg.QuorumM, len(cfg.Providers))
	}
	if cfg.Strategy == "" {
		cfg.Strategy = StrategyHybrid
	}
	if cfg.DisagreementAction == "" {
		cfg.DisagreementAction = ActionLog
	}
	if cfg.DisagreementCooldown <= 0 {
		cfg.DisagreementCooldown = 10 * time.Minute
	}
	if cfg.ResponseTimeout <= 0 {
		cfg.ResponseTimeout = 5 * time.Second
	}
	if cfg.StreamSkewWindow <= 0 {
		cfg.StreamSkewWindow = 750 * time.Millisecond
	}
	if cfg.StreamBufferMax <= 0 {
		cfg.StreamBufferMax = 32
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	mc := &MultiClient{
		cfg:    cfg,
		health: make(map[string]*ProviderHealth, len(cfg.Providers)),
	}
	for _, p := range cfg.Providers {
		mc.health[p.Name] = &ProviderHealth{Name: p.Name}
	}
	return mc, nil
}

// SetCheckpointStore wires the W6-9 checkpoint store. Optional.
func (m *MultiClient) SetCheckpointStore(s CheckpointStore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cpStore = s
}

// Health returns a snapshot of per-provider stats.
func (m *MultiClient) Health() []ProviderHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ProviderHealth, 0, len(m.health))
	for _, p := range m.cfg.Providers {
		if h, ok := m.health[p.Name]; ok {
			out = append(out, *h)
		}
	}
	return out
}

// headerResult is one provider's response.
type headerResult struct {
	provider string
	header   *BlockHeader
	err      error
	rtt      time.Duration
}

// fanout invokes fn on every non-suspended provider in parallel and
// collects the results.
func (m *MultiClient) fanout(ctx context.Context, fn func(context.Context, Provider) (*BlockHeader, error)) []headerResult {
	now := time.Now()
	m.mu.Lock()
	active := make([]Provider, 0, len(m.cfg.Providers))
	for _, p := range m.cfg.Providers {
		h := m.health[p.Name]
		if h != nil && !h.SuspendedUntil.IsZero() && now.Before(h.SuspendedUntil) {
			continue
		}
		active = append(active, p)
	}
	m.mu.Unlock()

	if len(active) == 0 {
		return nil
	}

	callCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, m.cfg.ResponseTimeout)
		defer cancel()
	}

	results := make([]headerResult, len(active))
	var wg sync.WaitGroup
	for i, p := range active {
		wg.Add(1)
		go func(i int, p Provider) {
			defer wg.Done()
			callCtx2 := callCtx
			if p.Timeout > 0 {
				var cancel context.CancelFunc
				callCtx2, cancel = context.WithTimeout(callCtx, p.Timeout)
				defer cancel()
			}
			start := time.Now()
			h, err := fn(callCtx2, p)
			rtt := time.Since(start)
			results[i] = headerResult{provider: p.Name, header: h, err: err, rtt: rtt}
		}(i, p)
	}
	wg.Wait()

	m.mu.Lock()
	for _, r := range results {
		st := m.health[r.provider]
		if st == nil {
			continue
		}
		st.Calls++
		st.LastRTT = r.rtt
		if r.err != nil {
			st.Errors++
		}
	}
	m.mu.Unlock()

	return results
}

// quorumGroup is one bucket of providers reporting the same header.
type quorumGroup struct {
	header  *BlockHeader
	voters  []string
	bestRTT time.Duration
}

// resolveQuorum applies the configured quorum policy to a set of
// fanout results.
func (m *MultiClient) resolveQuorum(results []headerResult) (*BlockHeader, []string, error) {
	groups := make(map[[32]byte]*quorumGroup)
	for _, r := range results {
		if r.err != nil || r.header == nil {
			continue
		}
		key := r.header.Hash
		g, ok := groups[key]
		if !ok {
			dup := *r.header
			if r.header.Work != nil {
				dup.Work = new(big.Int).Set(r.header.Work)
			}
			g = &quorumGroup{header: &dup, bestRTT: r.rtt}
			groups[key] = g
		} else if r.rtt < g.bestRTT {
			g.bestRTT = r.rtt
		}
		g.voters = append(g.voters, r.provider)
	}
	if len(groups) == 0 {
		return nil, nil, ErrQuorumUnavailable
	}

	if err := m.checkCrossCheckpoint(groups); err != nil {
		return nil, nil, err
	}

	keys := make([][32]byte, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		gi, gj := groups[keys[i]], groups[keys[j]]
		if len(gi.voters) != len(gj.voters) {
			return len(gi.voters) > len(gj.voters)
		}
		wi, wj := gi.header.Work, gj.header.Work
		if wi == nil {
			wi = new(big.Int)
		}
		if wj == nil {
			wj = new(big.Int)
		}
		if cmp := wi.Cmp(wj); cmp != 0 {
			return cmp > 0
		}
		return gi.bestRTT < gj.bestRTT
	})

	winner := groups[keys[0]]
	dissenters := make([]string, 0)
	for i := 1; i < len(keys); i++ {
		dissenters = append(dissenters, groups[keys[i]].voters...)
	}

	if len(winner.voters) >= m.cfg.QuorumM {
		if len(dissenters) > 0 {
			m.handleDisagreement(winner.voters, dissenters)
		}
		return winner.header, winner.voters, nil
	}

	if m.cfg.Strategy == StrategyMOfN {
		return nil, nil, fmt.Errorf("%w: top group has %d/%d votes", ErrQuorumUnavailable, len(winner.voters), m.cfg.QuorumM)
	}

	// StrategyHybrid: highest-work group wins.
	m.cfg.Logger.Warn("chaintracks quorum tiebreak via highest-work",
		"winner", winner.voters,
		"votes", len(winner.voters),
		"required", m.cfg.QuorumM,
		"groups", len(groups),
	)
	if len(dissenters) > 0 {
		m.handleDisagreement(winner.voters, dissenters)
	}
	return winner.header, winner.voters, nil
}

// checkCrossCheckpoint returns ErrCheckpointFork if any reported
// header at a height >= deepest checkpoint disagrees with the pinned
// checkpoint hash. The W6-9 child validators handle the general
// "fork below depth N" check; here we only catch the special case
// where two providers happened to report a header at the exact
// checkpoint height with mismatching hashes.
func (m *MultiClient) checkCrossCheckpoint(groups map[[32]byte]*quorumGroup) error {
	m.mu.Lock()
	store := m.cpStore
	m.mu.Unlock()
	if store == nil {
		return nil
	}
	cpHeight, cpHash := store.DeepestCheckpoint()
	if cpHeight == 0 {
		return nil
	}
	for _, g := range groups {
		if g.header.Height == cpHeight && g.header.Hash != cpHash {
			m.mu.Lock()
			m.halted = true
			m.mu.Unlock()
			return fmt.Errorf("%w: at height %d voters %v reported %x", ErrCheckpointFork, cpHeight, g.voters, g.header.Hash)
		}
	}
	return nil
}

// handleDisagreement updates per-provider stats and applies the action.
func (m *MultiClient) handleDisagreement(winners, dissenters []string) {
	m.mu.Lock()
	for _, name := range dissenters {
		if h, ok := m.health[name]; ok {
			h.Disagreements++
		}
	}
	switch m.cfg.DisagreementAction {
	case ActionDrop:
		until := time.Now().Add(m.cfg.DisagreementCooldown)
		for _, name := range dissenters {
			if h, ok := m.health[name]; ok {
				h.SuspendedUntil = until
			}
		}
	case ActionHalt:
		m.halted = true
	}
	m.mu.Unlock()
	m.cfg.Logger.Warn("chaintracks providers disagree",
		"winner_voters", winners,
		"dissenters", dissenters,
		"action", string(m.cfg.DisagreementAction),
	)
}

// --- ChaintracksClient implementation -----------------------------

// Tip implements ChaintracksClient.
func (m *MultiClient) Tip(ctx context.Context) (*BlockHeader, error) {
	if m.isHalted() {
		return nil, ErrHalted
	}
	results := m.fanout(ctx, func(c context.Context, p Provider) (*BlockHeader, error) {
		return p.Client.Tip(c)
	})
	h, _, err := m.resolveQuorum(results)
	return h, err
}

// HeaderByHash implements ChaintracksClient.
func (m *MultiClient) HeaderByHash(ctx context.Context, hash [32]byte) (*BlockHeader, error) {
	if m.isHalted() {
		return nil, ErrHalted
	}
	results := m.fanout(ctx, func(c context.Context, p Provider) (*BlockHeader, error) {
		return p.Client.HeaderByHash(c, hash)
	})
	h, _, err := m.resolveQuorum(results)
	return h, err
}

// HeaderByHeight implements ChaintracksClient.
func (m *MultiClient) HeaderByHeight(ctx context.Context, height uint64) (*BlockHeader, error) {
	if m.isHalted() {
		return nil, ErrHalted
	}
	results := m.fanout(ctx, func(c context.Context, p Provider) (*BlockHeader, error) {
		return p.Client.HeaderByHeight(c, height)
	})
	h, _, err := m.resolveQuorum(results)
	return h, err
}

// MerkleRootAtHeight implements ChaintracksClient.
func (m *MultiClient) MerkleRootAtHeight(ctx context.Context, height uint64) ([32]byte, error) {
	h, err := m.HeaderByHeight(ctx, height)
	if err != nil {
		return [32]byte{}, err
	}
	return h.MerkleRoot, nil
}

// Confirmations implements ChaintracksClient.
func (m *MultiClient) Confirmations(ctx context.Context, height uint64, blockHash [32]byte) (int64, error) {
	h, err := m.HeaderByHeight(ctx, height)
	if err != nil {
		if errors.Is(err, ErrUnknownHeader) {
			return 0, nil
		}
		return 0, err
	}
	if h.Hash != blockHash {
		return -1, nil
	}
	tip, err := m.Tip(ctx)
	if err != nil {
		return 0, err
	}
	return int64(tip.Height-h.Height) + 1, nil
}

// SubscribeReorgs implements ChaintracksClient. Subscribes to every
// child and propagates only quorum-decided events. Buffers per-child
// events for cfg.StreamSkewWindow before resolving.
func (m *MultiClient) SubscribeReorgs(ctx context.Context) (<-chan *ReorgEvent, error) {
	if m.isHalted() {
		return nil, ErrHalted
	}
	out := make(chan *ReorgEvent, 8)

	type childSub struct {
		name string
		ch   <-chan *ReorgEvent
	}
	subs := make([]childSub, 0, len(m.cfg.Providers))
	for _, p := range m.cfg.Providers {
		ch, err := p.Client.SubscribeReorgs(ctx)
		if err != nil {
			m.cfg.Logger.Warn("chaintracks child subscribe failed", "provider", p.Name, "err", err)
			continue
		}
		subs = append(subs, childSub{name: p.Name, ch: ch})
	}
	if len(subs) == 0 {
		close(out)
		return out, nil
	}

	m.subsMu.Lock()
	m.subs = append(m.subs, out)
	m.subsMu.Unlock()

	type pending struct {
		provider string
		ev       *ReorgEvent
		recvAt   time.Time
	}
	merged := make(chan pending, m.cfg.StreamBufferMax*len(subs))

	for _, s := range subs {
		go func(s childSub) {
			for ev := range s.ch {
				select {
				case merged <- pending{provider: s.name, ev: ev, recvAt: time.Now()}:
				case <-ctx.Done():
					return
				default:
					// Buffer full — drop and log.
					m.cfg.Logger.Warn("chaintracks stream buffer full, dropping",
						"provider", s.name)
				}
			}
		}(s)
	}

	go func() {
		defer func() {
			m.subsMu.Lock()
			for i, ch := range m.subs {
				if ch == out {
					m.subs = append(m.subs[:i], m.subs[i+1:]...)
					break
				}
			}
			m.subsMu.Unlock()
			close(out)
		}()

		type bucket struct {
			ev     *ReorgEvent
			voters map[string]struct{}
			first  time.Time
		}
		buckets := make(map[[32]byte]*bucket)
		tickInterval := m.cfg.StreamSkewWindow / 4
		if tickInterval <= 0 {
			tickInterval = 100 * time.Millisecond
		}
		ticker := time.NewTicker(tickInterval)
		defer ticker.Stop()
		emit := func(b *bucket) {
			select {
			case out <- b.ev:
			case <-ctx.Done():
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-merged:
				key := p.ev.NewTip
				b, ok := buckets[key]
				if !ok {
					b = &bucket{ev: p.ev, voters: map[string]struct{}{}, first: p.recvAt}
					buckets[key] = b
				}
				b.voters[p.provider] = struct{}{}
				if len(b.voters) >= m.cfg.QuorumM {
					emit(b)
					delete(buckets, key)
				}
			case now := <-ticker.C:
				for k, b := range buckets {
					if now.Sub(b.first) < m.cfg.StreamSkewWindow {
						continue
					}
					if len(b.voters) >= m.cfg.QuorumM {
						emit(b)
					} else if m.cfg.Strategy == StrategyHybrid && len(b.voters) >= 1 {
						m.cfg.Logger.Warn("chaintracks reorg below quorum, hybrid emit",
							"voters", len(b.voters),
							"required", m.cfg.QuorumM,
						)
						emit(b)
					} else {
						m.cfg.Logger.Warn("chaintracks reorg below quorum, dropping",
							"voters", len(b.voters),
							"required", m.cfg.QuorumM,
						)
					}
					delete(buckets, k)
				}
			}
		}
	}()

	return out, nil
}

// Ping implements ChaintracksClient. Returns nil if at least M
// providers respond OK.
func (m *MultiClient) Ping(ctx context.Context) error {
	if m.isHalted() {
		return ErrHalted
	}
	type r struct{ err error }
	results := make(chan r, len(m.cfg.Providers))
	callCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, m.cfg.ResponseTimeout)
		defer cancel()
	}
	for _, p := range m.cfg.Providers {
		go func(p Provider) {
			results <- r{err: p.Client.Ping(callCtx)}
		}(p)
	}
	ok := 0
	for i := 0; i < len(m.cfg.Providers); i++ {
		if (<-results).err == nil {
			ok++
		}
	}
	if ok < m.cfg.QuorumM {
		return fmt.Errorf("%w: ping ok %d/%d", ErrQuorumUnavailable, ok, m.cfg.QuorumM)
	}
	return nil
}

// Close implements ChaintracksClient. Closes every child.
func (m *MultiClient) Close() error {
	m.subsMu.Lock()
	m.closed = true
	m.subsMu.Unlock()
	var firstErr error
	for _, p := range m.cfg.Providers {
		if err := p.Client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiClient) isHalted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.halted
}
