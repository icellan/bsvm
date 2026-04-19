package network

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"

	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
)

// maxStreamReadSize is the maximum number of bytes read from a single
// stream in one read operation. This provides an additional layer of
// protection beyond per-message-type limits.
const maxStreamReadSize = 1024 * 1024 // 1MB

// MessageHandler is a callback function invoked when a message of a
// specific type is received from a peer.
type MessageHandler func(peerID peer.ID, msg *Message) error

// GossipManager manages the P2P gossip protocol. It maintains a libp2p
// host, broadcasts and receives messages, and coordinates with the
// PeerManager for rate limiting and scoring.
type GossipManager struct {
	host       host.Host
	overlay    *overlay.OverlayNode
	config     Config
	peers      *PeerManager
	handlers   map[byte]MessageHandler
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	started    bool
	mdnsCancel context.CancelFunc
}

// NewGossipManager creates a new GossipManager with the given configuration
// and overlay node. It initialises a libp2p host, PeerManager, and message
// handler registry. The gossip manager is not started until Start is called.
func NewGossipManager(config Config, ovl *overlay.OverlayNode) (*GossipManager, error) {
	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = "/ip4/0.0.0.0/tcp/9945"
	}

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	pm := NewPeerManager(h, config.MaxPeers, config.RateLimit)

	gm := &GossipManager{
		host:     h,
		overlay:  ovl,
		config:   config,
		peers:    pm,
		handlers: make(map[byte]MessageHandler),
	}

	return gm, nil
}

// newGossipManagerWithHost creates a GossipManager using an externally
// provided libp2p host. This is used for testing.
func newGossipManagerWithHost(config Config, ovl *overlay.OverlayNode, h host.Host) *GossipManager {
	pm := NewPeerManager(h, config.MaxPeers, config.RateLimit)
	return &GossipManager{
		host:     h,
		overlay:  ovl,
		config:   config,
		peers:    pm,
		handlers: make(map[byte]MessageHandler),
	}
}

// Host returns the underlying libp2p host.
func (g *GossipManager) Host() host.Host {
	return g.host
}

// PeerManager returns the gossip manager's peer manager.
func (g *GossipManager) PeerManager() *PeerManager {
	return g.peers
}

// RegisterHandler registers a callback for a specific message type.
// The handler is invoked when a message of that type is received from
// any connected peer.
func (g *GossipManager) RegisterHandler(msgType byte, handler MessageHandler) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.handlers[msgType] = handler
}

// Start begins listening for incoming connections and messages. It also
// connects to bootstrap peers and starts the heartbeat loop. Start
// blocks until the context is cancelled or Stop is called.
func (g *GossipManager) Start(ctx context.Context) error {
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		return fmt.Errorf("gossip manager already started")
	}
	g.started = true
	g.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	g.cancel = cancel

	// Register the stream handler for our protocol.
	pid := protocol.ID(ProtocolID(g.config.ChainID))
	g.host.SetStreamHandler(pid, g.handleStream)

	slog.Info("gossip manager started",
		"listenAddrs", g.host.Addrs(),
		"peerID", g.host.ID().String(),
		"protocolID", string(pid),
	)

	// Connect to bootstrap peers.
	for _, addr := range g.config.BootstrapPeers {
		addrInfo, err := peer.AddrInfoFromString(addr)
		if err != nil {
			slog.Warn("invalid bootstrap peer address", "addr", addr, "error", err)
			continue
		}
		if err := g.host.Connect(ctx, *addrInfo); err != nil {
			slog.Warn("failed to connect to bootstrap peer", "addr", addr, "error", err)
			continue
		}
		if err := g.peers.AddPeer(addrInfo.ID, addrInfo.Addrs); err != nil {
			slog.Warn("failed to add bootstrap peer", "addr", addr, "error", err)
		}
	}

	// Start mDNS discovery if enabled.
	if g.config.EnableMDNS {
		mdnsCtx, mdnsCancel := context.WithCancel(ctx)
		g.mdnsCancel = mdnsCancel
		g.startMDNS(mdnsCtx)
	}

	// Start the heartbeat loop.
	g.wg.Add(1)
	go g.heartbeatLoop(ctx)

	return nil
}

// Stop gracefully stops the gossip manager, closing all connections and
// cancelling background goroutines.
func (g *GossipManager) Stop() error {
	g.mu.Lock()
	if !g.started {
		g.mu.Unlock()
		return nil
	}
	g.started = false
	g.mu.Unlock()

	if g.mdnsCancel != nil {
		g.mdnsCancel()
	}
	if g.cancel != nil {
		g.cancel()
	}
	g.wg.Wait()

	if err := g.host.Close(); err != nil {
		return fmt.Errorf("failed to close libp2p host: %w", err)
	}

	slog.Info("gossip manager stopped")
	return nil
}

// BroadcastTx broadcasts a single EVM transaction to all connected peers.
func (g *GossipManager) BroadcastTx(tx *types.Transaction) error {
	var buf bytesWriter
	if err := tx.EncodeRLP(&buf); err != nil {
		return fmt.Errorf("failed to RLP-encode transaction: %w", err)
	}

	gossipMsg := &TxGossipMsg{TxRLP: buf.Bytes()}
	msg, err := gossipMsg.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode tx gossip message: %w", err)
	}

	return g.broadcast(msg)
}

// BroadcastBlockAnnounce broadcasts an L2 block announcement to all
// connected peers. The announcement contains the block header summary
// and transaction hashes (not full transactions).
func (g *GossipManager) BroadcastBlockAnnounce(parentHash types.Hash, stateRoot types.Hash, txRoot types.Hash, number uint64, gasUsed uint64, timestamp uint64, txHashes []types.Hash) error {
	announceMsg := &BlockAnnounceMsg{
		ParentHash: parentHash,
		StateRoot:  stateRoot,
		TxRoot:     txRoot,
		Number:     number,
		GasUsed:    gasUsed,
		Timestamp:  timestamp,
		TxHashes:   txHashes,
	}
	msg, err := announceMsg.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode block announce message: %w", err)
	}

	return g.broadcast(msg)
}

// BroadcastProposal gossips a governance proposal (spec 15 / A4).
// Called on both initial announce and signature updates. Receivers
// deduplicate by the content-addressed Proposal.ID and merge
// signature sets. Payload is JSON-marshalled so the governance
// package stays independent of the network layer.
func (g *GossipManager) BroadcastProposal(payload []byte) error {
	msg := &Message{Type: MsgProposal, Payload: payload}
	return g.broadcast(msg)
}

// BroadcastCovenantAdvance broadcasts a covenant advance announcement
// to all connected peers.
func (g *GossipManager) BroadcastCovenantAdvance(bsvTxID types.Hash, l2BlockNum uint64, stateRoot types.Hash) error {
	advanceMsg := &CovenantAdvanceMsg{
		BSVTxID:    bsvTxID,
		L2BlockNum: l2BlockNum,
		StateRoot:  stateRoot,
	}
	msg, err := advanceMsg.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode covenant advance message: %w", err)
	}

	return g.broadcast(msg)
}

// RequestBatch sends a batch request to a specific peer and waits for
// the response. Returns the batch data or an error if the request fails
// or times out.
func (g *GossipManager) RequestBatch(peerID peer.ID, blockNum uint64) ([]byte, error) {
	if g.host == nil {
		return nil, fmt.Errorf("no libp2p host available")
	}

	reqMsg := &BatchRequestMsg{L2BlockNum: blockNum}
	msg, err := reqMsg.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode batch request: %w", err)
	}

	encoded, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode wire message: %w", err)
	}

	pid := protocol.ID(ProtocolID(g.config.ChainID))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := g.host.NewStream(ctx, peerID, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream to peer %s: %w", peerID, err)
	}
	defer stream.Close()

	if _, err := stream.Write(encoded); err != nil {
		return nil, fmt.Errorf("failed to send batch request: %w", err)
	}

	// Read response.
	respData, err := readStreamFull(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read batch response: %w", err)
	}

	respMsg, err := DecodeMessage(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode batch response message: %w", err)
	}

	if respMsg.Type != MsgBatchResponse {
		return nil, fmt.Errorf("unexpected response type: 0x%02x", respMsg.Type)
	}

	batchResp, err := DecodeBatchResponseMsg(respMsg.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode batch response: %w", err)
	}

	return batchResp.BatchData, nil
}

// broadcast sends a message to all connected peers.
func (g *GossipManager) broadcast(msg *Message) error {
	if g.host == nil {
		return nil // No host means no peers to broadcast to.
	}

	encoded, err := msg.Encode()
	if err != nil {
		return err
	}

	pid := protocol.ID(ProtocolID(g.config.ChainID))
	peers := g.peers.AllPeers()

	for _, p := range peers {
		go func(peerID peer.ID) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			stream, err := g.host.NewStream(ctx, peerID, pid)
			if err != nil {
				slog.Debug("failed to open stream to peer",
					"peer", peerID.String(),
					"error", err,
				)
				return
			}
			defer stream.Close()

			if _, err := stream.Write(encoded); err != nil {
				slog.Debug("failed to send message to peer",
					"peer", peerID.String(),
					"error", err,
				)
			}
		}(p)
	}
	return nil
}

// handleStream processes an incoming libp2p stream from a peer.
func (g *GossipManager) handleStream(s network.Stream) {
	defer s.Close()

	remotePeer := s.Conn().RemotePeer()

	// Rate limit check.
	if !g.peers.CheckRateLimit(remotePeer) {
		slog.Debug("rate limited peer", "peer", remotePeer.String())
		g.peers.AdjustScore(remotePeer, -1)
		return
	}

	data, err := readStreamFull(s)
	if err != nil {
		slog.Debug("failed to read stream", "peer", remotePeer, "error", err)
		return
	}

	msg, err := DecodeMessage(data)
	if err != nil {
		slog.Debug("failed to decode message", "peer", remotePeer, "error", err)
		g.peers.AdjustScore(remotePeer, -10)
		return
	}

	g.mu.RLock()
	handler, exists := g.handlers[msg.Type]
	g.mu.RUnlock()

	if exists {
		if err := handler(remotePeer, msg); err != nil {
			slog.Debug("handler error",
				"peer", remotePeer,
				"type", msg.Type,
				"error", err,
			)
			g.peers.AdjustScore(remotePeer, -5)
		}
	}
}

// heartbeatLoop sends periodic heartbeat messages to all connected peers.
func (g *GossipManager) heartbeatLoop(ctx context.Context) {
	defer g.wg.Done()

	interval := g.config.HeartbeatInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.sendHeartbeats()
		}
	}
}

// sendHeartbeats sends a heartbeat message to all connected peers.
func (g *GossipManager) sendHeartbeats() {
	var chainTip uint64
	if g.overlay != nil {
		chainTip = g.overlay.ExecutionTip()
	}

	hb := &HeartbeatMsg{
		PeerID:    g.host.ID().String(),
		ChainTip:  chainTip,
		Timestamp: uint64(time.Now().Unix()),
	}

	msg, err := hb.Encode()
	if err != nil {
		slog.Warn("failed to encode heartbeat", "error", err)
		return
	}

	if err := g.broadcast(msg); err != nil {
		slog.Debug("failed to broadcast heartbeat", "error", err)
	}
}

// startMDNS starts mDNS-based peer discovery for local development.
func (g *GossipManager) startMDNS(ctx context.Context) {
	serviceName := fmt.Sprintf("bsvm-shard-%d", g.config.ChainID)
	notifee := &mdnsNotifee{
		ctx:   ctx,
		host:  g.host,
		peers: g.peers,
	}
	svc := mdns.NewMdnsService(g.host, serviceName, notifee)
	if err := svc.Start(); err != nil {
		slog.Warn("failed to start mDNS", "error", err)
	}
}

// mdnsNotifee implements the mdns.Notifee interface for peer discovery.
type mdnsNotifee struct {
	ctx   context.Context
	host  host.Host
	peers *PeerManager
}

// HandlePeerFound is called when a new peer is discovered via mDNS.
func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.host.ID() {
		return // Ignore ourselves.
	}

	slog.Debug("mDNS discovered peer", "peer", pi.ID.String())
	if err := n.host.Connect(n.ctx, pi); err != nil {
		slog.Debug("failed to connect to mDNS peer", "peer", pi.ID.String(), "error", err)
		return
	}

	if err := n.peers.AddPeer(pi.ID, pi.Addrs); err != nil {
		slog.Debug("failed to add mDNS peer", "peer", pi.ID.String(), "error", err)
	}
}

// readStreamFull reads all data from a stream up to maxStreamReadSize.
// It loops to handle partial reads from large messages.
func readStreamFull(s io.Reader) ([]byte, error) {
	var result []byte
	buf := make([]byte, 32*1024) // 32KB read buffer
	for {
		n, err := s.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
			if len(result) > maxStreamReadSize {
				return nil, fmt.Errorf("stream data exceeds max size %d", maxStreamReadSize)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// bytesWriter is a simple writer that collects bytes for RLP encoding.
type bytesWriter struct {
	buf []byte
}

// Write implements io.Writer.
func (w *bytesWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// Bytes returns the accumulated bytes.
func (w *bytesWriter) Bytes() []byte {
	return w.buf
}
