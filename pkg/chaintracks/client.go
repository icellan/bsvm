// Package chaintracks is the BSVM client for the BRC-64 Block Headers
// Service. The shard node uses chaintracks as its sole trusted SPV
// anchor: it streams BSV block headers from one or more upstream
// providers, persists them, and serves header lookups to the rest of
// the node.
//
// This package ships scaffolds:
//
//   - The ChaintracksClient interface every provider must satisfy.
//   - An InMemoryClient backed by a sorted map, suitable for unit tests
//     and devnet harnesses that don't need a live header feed.
//   - A RemoteClient that talks BRC-64 HTTP(S) to an external server.
//     The wire format implemented here is a minimal subset sufficient
//     for header lookup; a full live-server integration (subscribe-
//     forward, reorg streaming, multi-upstream quorum) is follow-up.
//
// See spec/17-CHAINTRACKS-BEEF-ARC.md §"Chaintracks: Block Headers
// Service" for the full design.
package chaintracks

import (
	"context"
	"errors"
	"math/big"
	"sync"
)

// ErrUnknownHeader is returned by ChaintracksClient methods when the
// requested header is not present in the local view.
var ErrUnknownHeader = errors.New("chaintracks: unknown header")

// BlockHeader carries the SPV-relevant fields of a BSV block header
// plus cumulative chainwork.
type BlockHeader struct {
	Height     uint64
	Hash       [32]byte
	PrevHash   [32]byte
	MerkleRoot [32]byte
	Timestamp  uint32
	Bits       uint32
	Nonce      uint32
	// Work is the cumulative chainwork up to and including this header.
	// nil is treated as "unknown" by reorg-resolution code.
	Work *big.Int
}

// ReorgEvent is emitted by SubscribeReorgs whenever the client
// switches its best-chain view. Subscribers MUST treat any confirmed
// data above CommonAncestor as invalidated and re-broadcast it.
type ReorgEvent struct {
	CommonAncestor [32]byte
	OldTip         [32]byte
	NewTip         [32]byte
	OldChainLen    uint64
	NewChainLen    uint64
}

// ChaintracksClient is the read-side interface BSVM consumes.
type ChaintracksClient interface {
	// Tip returns the current best-chain tip.
	Tip(ctx context.Context) (*BlockHeader, error)
	// HeaderByHash returns the header whose hash matches.
	HeaderByHash(ctx context.Context, hash [32]byte) (*BlockHeader, error)
	// HeaderByHeight returns the header at the given height.
	HeaderByHeight(ctx context.Context, height uint64) (*BlockHeader, error)
	// MerkleRootAtHeight returns the merkle root of the header at the
	// given height, the value used to verify BRC-74 BUMPs.
	MerkleRootAtHeight(ctx context.Context, height uint64) ([32]byte, error)
	// Confirmations returns the number of confirmations for a tx
	// mined in the given block, or 0 if the block is unknown / not
	// on the best chain. Returns -1 when the block has been reorged
	// off.
	Confirmations(ctx context.Context, height uint64, blockHash [32]byte) (int64, error)
	// SubscribeReorgs returns a channel that receives a ReorgEvent
	// whenever the client switches chains. The channel is closed when
	// ctx is cancelled.
	SubscribeReorgs(ctx context.Context) (<-chan *ReorgEvent, error)
	// Ping reports liveness.
	Ping(ctx context.Context) error
	// Close releases background resources.
	Close() error
}

// InMemoryClient is a Map-backed ChaintracksClient suitable for
// unit tests and devnet harnesses. Mutators (PutHeader, EmitReorg)
// are exposed so tests can drive the client through specific
// scenarios; production wiring uses RemoteClient instead.
type InMemoryClient struct {
	mu       sync.RWMutex
	byHash   map[[32]byte]*BlockHeader
	byHeight map[uint64]*BlockHeader
	tipHash  [32]byte
	subs     []chan *ReorgEvent
	closed   bool
}

// NewInMemoryClient returns an empty InMemoryClient.
func NewInMemoryClient() *InMemoryClient {
	return &InMemoryClient{
		byHash:   make(map[[32]byte]*BlockHeader),
		byHeight: make(map[uint64]*BlockHeader),
	}
}

// PutHeader inserts or replaces a header in the local view and bumps
// the tip if h.Height is at or above the current tip's height. Used by
// tests and by the bootstrap path to seed checkpoints.
func (c *InMemoryClient) PutHeader(h *BlockHeader) {
	if h == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dup := *h
	if dup.Work == nil {
		dup.Work = new(big.Int)
	} else {
		dup.Work = new(big.Int).Set(h.Work)
	}
	c.byHash[h.Hash] = &dup
	c.byHeight[h.Height] = &dup
	if tip, ok := c.byHash[c.tipHash]; !ok || h.Height >= tip.Height {
		c.tipHash = h.Hash
	}
}

// EmitReorg posts a reorg event to every active subscriber.
func (c *InMemoryClient) EmitReorg(ev *ReorgEvent) {
	c.mu.RLock()
	subs := append([]chan *ReorgEvent(nil), c.subs...)
	c.mu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Tip implements ChaintracksClient.
func (c *InMemoryClient) Tip(_ context.Context) (*BlockHeader, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.byHash[c.tipHash]
	if !ok {
		return nil, ErrUnknownHeader
	}
	dup := *h
	return &dup, nil
}

// HeaderByHash implements ChaintracksClient.
func (c *InMemoryClient) HeaderByHash(_ context.Context, hash [32]byte) (*BlockHeader, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.byHash[hash]
	if !ok {
		return nil, ErrUnknownHeader
	}
	dup := *h
	return &dup, nil
}

// HeaderByHeight implements ChaintracksClient.
func (c *InMemoryClient) HeaderByHeight(_ context.Context, height uint64) (*BlockHeader, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.byHeight[height]
	if !ok {
		return nil, ErrUnknownHeader
	}
	dup := *h
	return &dup, nil
}

// MerkleRootAtHeight implements ChaintracksClient.
func (c *InMemoryClient) MerkleRootAtHeight(ctx context.Context, height uint64) ([32]byte, error) {
	h, err := c.HeaderByHeight(ctx, height)
	if err != nil {
		return [32]byte{}, err
	}
	return h.MerkleRoot, nil
}

// Confirmations implements ChaintracksClient.
func (c *InMemoryClient) Confirmations(_ context.Context, height uint64, blockHash [32]byte) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.byHeight[height]
	if !ok {
		return 0, nil
	}
	if h.Hash != blockHash {
		return -1, nil
	}
	tip, ok := c.byHash[c.tipHash]
	if !ok {
		return 0, nil
	}
	return int64(tip.Height-height) + 1, nil
}

// SubscribeReorgs implements ChaintracksClient. The returned channel
// is closed when ctx is cancelled.
func (c *InMemoryClient) SubscribeReorgs(ctx context.Context) (<-chan *ReorgEvent, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("chaintracks: client closed")
	}
	ch := make(chan *ReorgEvent, 8)
	c.subs = append(c.subs, ch)
	c.mu.Unlock()
	go func() {
		<-ctx.Done()
		c.mu.Lock()
		for i, s := range c.subs {
			if s == ch {
				c.subs = append(c.subs[:i], c.subs[i+1:]...)
				break
			}
		}
		c.mu.Unlock()
		close(ch)
	}()
	return ch, nil
}

// Ping implements ChaintracksClient.
func (c *InMemoryClient) Ping(_ context.Context) error { return nil }

// Close implements ChaintracksClient.
func (c *InMemoryClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
