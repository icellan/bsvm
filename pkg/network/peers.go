package network

import (
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// disconnectThreshold is the peer score below which a peer is disconnected.
const disconnectThreshold = -100

// PeerManager tracks connected peers, enforces rate limits, and maintains
// peer scores for DoS protection. Peers that send invalid data receive
// score penalties. A peer whose score drops below -100 is disconnected.
type PeerManager struct {
	host      host.Host
	peers     map[peer.ID]*PeerInfo
	scores    map[peer.ID]int
	mu        sync.RWMutex
	maxPeers  int
	rateLimit int
}

// PeerInfo holds metadata about a connected peer.
type PeerInfo struct {
	// ID is the libp2p peer ID.
	ID peer.ID
	// Addrs contains the peer's known multiaddresses.
	Addrs []ma.Multiaddr
	// ChainTip is the latest L2 block number reported by this peer.
	ChainTip uint64
	// LastSeen is the time the peer was last heard from.
	LastSeen time.Time
	// Score is the peer's reputation score.
	Score int
	// MsgCount tracks the number of messages received in the current
	// rate limit window.
	MsgCount int
	// MsgResetAt is the time when the MsgCount resets.
	MsgResetAt time.Time
}

// NewPeerManager creates a new PeerManager with the given libp2p host,
// maximum peer count, and per-peer rate limit (messages per second).
func NewPeerManager(h host.Host, maxPeers int, rateLimit int) *PeerManager {
	if maxPeers <= 0 {
		maxPeers = 50
	}
	if rateLimit <= 0 {
		rateLimit = 100
	}
	return &PeerManager{
		host:      h,
		peers:     make(map[peer.ID]*PeerInfo),
		scores:    make(map[peer.ID]int),
		maxPeers:  maxPeers,
		rateLimit: rateLimit,
	}
}

// AddPeer registers a new peer with the manager. If the maximum peer count
// has been reached, the peer is rejected. Returns an error if the peer
// cannot be added.
func (pm *PeerManager) AddPeer(id peer.ID, addrs []ma.Multiaddr) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.peers[id]; exists {
		// Update addresses for existing peer.
		pm.peers[id].Addrs = addrs
		pm.peers[id].LastSeen = time.Now()
		return nil
	}

	if len(pm.peers) >= pm.maxPeers {
		return errMaxPeersReached
	}

	pm.peers[id] = &PeerInfo{
		ID:         id,
		Addrs:      addrs,
		LastSeen:   time.Now(),
		MsgResetAt: time.Now().Add(time.Second),
	}
	pm.scores[id] = 0

	slog.Debug("peer added", "peer", id.String())
	return nil
}

// RemovePeer removes a peer from the manager and closes any libp2p
// connections to that peer.
func (pm *PeerManager) RemovePeer(id peer.ID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	delete(pm.peers, id)
	delete(pm.scores, id)

	if pm.host != nil {
		_ = pm.host.Network().ClosePeer(id)
	}

	slog.Debug("peer removed", "peer", id.String())
}

// CheckRateLimit checks whether a peer has exceeded its per-second message
// rate limit. Returns true if the message is allowed, false if rate-limited.
// The rate limit window resets every second.
func (pm *PeerManager) CheckRateLimit(id peer.ID) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	info, exists := pm.peers[id]
	if !exists {
		return false
	}

	now := time.Now()
	if now.After(info.MsgResetAt) {
		info.MsgCount = 0
		info.MsgResetAt = now.Add(time.Second)
	}

	if info.MsgCount >= pm.rateLimit {
		return false
	}

	info.MsgCount++
	info.LastSeen = now
	return true
}

// AdjustScore modifies a peer's reputation score by the given delta.
// If the score drops below the disconnect threshold (-100), the peer
// is removed and disconnected.
func (pm *PeerManager) AdjustScore(id peer.ID, delta int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	score, exists := pm.scores[id]
	if !exists {
		return
	}

	score += delta
	pm.scores[id] = score

	if info, ok := pm.peers[id]; ok {
		info.Score = score
	}

	if score <= disconnectThreshold {
		slog.Warn("peer score below threshold, disconnecting",
			"peer", id.String(),
			"score", score,
		)
		delete(pm.peers, id)
		delete(pm.scores, id)
		if pm.host != nil {
			_ = pm.host.Network().ClosePeer(id)
		}
	}
}

// PeerCount returns the number of currently tracked peers.
func (pm *PeerManager) PeerCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.peers)
}

// BestPeers returns up to n peer IDs sorted by chain tip (highest first).
// Peers with higher chain tips are considered more useful for syncing.
func (pm *PeerManager) BestPeers(n int) []peer.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	type peerTip struct {
		id  peer.ID
		tip uint64
	}
	pts := make([]peerTip, 0, len(pm.peers))
	for _, info := range pm.peers {
		pts = append(pts, peerTip{id: info.ID, tip: info.ChainTip})
	}

	sort.Slice(pts, func(i, j int) bool {
		return pts[i].tip > pts[j].tip
	})

	if n > len(pts) {
		n = len(pts)
	}
	result := make([]peer.ID, n)
	for i := 0; i < n; i++ {
		result[i] = pts[i].id
	}
	return result
}

// UpdateChainTip updates the known chain tip for the given peer.
func (pm *PeerManager) UpdateChainTip(id peer.ID, tip uint64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if info, exists := pm.peers[id]; exists {
		info.ChainTip = tip
		info.LastSeen = time.Now()
	}
}

// GetPeer returns the PeerInfo for the given peer, or nil if unknown.
func (pm *PeerManager) GetPeer(id peer.ID) *PeerInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	info, exists := pm.peers[id]
	if !exists {
		return nil
	}
	// Return a copy to avoid data races.
	cpy := *info
	return &cpy
}

// GetScore returns the current score for the given peer. Returns 0 if
// the peer is unknown.
func (pm *PeerManager) GetScore(id peer.ID) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.scores[id]
}

// AllPeers returns the IDs of all tracked peers.
func (pm *PeerManager) AllPeers() []peer.ID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	ids := make([]peer.ID, 0, len(pm.peers))
	for id := range pm.peers {
		ids = append(ids, id)
	}
	return ids
}

// errMaxPeersReached is returned when AddPeer is called but the maximum
// peer count has already been reached.
type errMaxPeersReachedType struct{}

func (e errMaxPeersReachedType) Error() string {
	return "maximum peer count reached"
}

var errMaxPeersReached = errMaxPeersReachedType{}
