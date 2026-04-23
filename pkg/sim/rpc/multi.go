package rpc

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// MultiClient round-robins read-only calls and sticky-routes per-user
// writes to the same node. If a node fails 3× in a row, it is dropped
// from the rotation for the cooldown.
type MultiClient struct {
	clients []*Client
	rr      atomic.Uint64
	mu      sync.Mutex
	health  []nodeHealth
	cooldwn time.Duration
}

type nodeHealth struct {
	consecutiveFails int
	downUntil        time.Time
}

// NewMultiClient builds a MultiClient from RPC URLs.
func NewMultiClient(urls []string) *MultiClient {
	m := &MultiClient{
		clients: make([]*Client, len(urls)),
		health:  make([]nodeHealth, len(urls)),
		cooldwn: 30 * time.Second,
	}
	for i, u := range urls {
		m.clients[i] = NewClient(u)
	}
	return m
}

func (m *MultiClient) Len() int             { return len(m.clients) }
func (m *MultiClient) All() []*Client       { return m.clients }
func (m *MultiClient) At(i int) *Client     { return m.clients[i] }
func (m *MultiClient) Nth(i int) *Client    { return m.clients[i%len(m.clients)] }

// ForRead picks an up node, round-robin.
func (m *MultiClient) ForRead() *Client {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < len(m.clients); i++ {
		idx := int(m.rr.Add(1)-1) % len(m.clients)
		if idx < 0 {
			idx = -idx
		}
		if m.health[idx].downUntil.Before(now) {
			return m.clients[idx]
		}
	}
	// All nodes cooling down — return any client so caller still attempts.
	return m.clients[0]
}

// ForWrite returns a sticky client for the given key (typically user ID).
// If the assigned client is in cool-down, falls through to the next
// healthy client (deterministic).
func (m *MultiClient) ForWrite(key string) *Client {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	base := int(h.Sum32()) % len(m.clients)
	if base < 0 {
		base = -base
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < len(m.clients); i++ {
		idx := (base + i) % len(m.clients)
		if m.health[idx].downUntil.Before(now) {
			return m.clients[idx]
		}
	}
	return m.clients[base]
}

// RecordResult updates the health record for the given client URL.
func (m *MultiClient) RecordResult(c *Client, err error) {
	idx := -1
	for i, cl := range m.clients {
		if cl == c {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	h := &m.health[idx]
	if err == nil {
		h.consecutiveFails = 0
		h.downUntil = time.Time{}
		return
	}
	h.consecutiveFails++
	if h.consecutiveFails >= 3 {
		h.downUntil = time.Now().Add(m.cooldwn)
	}
}

// IsHealthy reports whether the client at index i is currently serving.
func (m *MultiClient) IsHealthy(i int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.health[i].downUntil.Before(time.Now())
}

// Highest returns the client whose most recent BlockNumber call had
// the highest result. Callers should first invoke BlockNumber on each
// client to keep the data fresh; this method is a convenience wrapper
// that falls back to index 0 if no client has reported a height.
func (m *MultiClient) Highest(heights []uint64) *Client {
	if len(heights) != len(m.clients) {
		return m.clients[0]
	}
	best := 0
	for i := 1; i < len(heights); i++ {
		if heights[i] > heights[best] {
			best = i
		}
	}
	return m.clients[best]
}

// Broadcast fans a read fn across all healthy clients. First non-error
// result wins; errors are collected and returned if every node fails.
func (m *MultiClient) Broadcast(ctx context.Context, fn func(context.Context, *Client) (any, error)) (any, error) {
	var lastErr error
	for i := 0; i < len(m.clients); i++ {
		c := m.clients[i]
		if !m.IsHealthy(i) {
			continue
		}
		v, err := fn(ctx, c)
		m.RecordResult(c, err)
		if err == nil {
			return v, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("all nodes unhealthy")
	}
	return nil, lastErr
}
