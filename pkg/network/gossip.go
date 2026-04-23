package network

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"

	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
)

// DerivePeerID returns the libp2p peer ID for a 32-byte identity seed.
// Uses the same ed25519 derivation as NewGossipManager so a compose
// file can bake in known peer IDs for its bootstrap list.
func DerivePeerID(seed []byte) (peer.ID, error) {
	priv, err := privKeyFromSeed(seed)
	if err != nil {
		return "", err
	}
	return peer.IDFromPrivateKey(priv)
}

// privKeyFromSeed derives a libp2p-compatible ed25519 private key from
// a 32-byte seed. Any 32-byte sequence is valid; the caller is
// responsible for choosing a seed with sufficient entropy.
func privKeyFromSeed(seed []byte) (crypto.PrivKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	edPriv := ed25519.NewKeyFromSeed(seed)
	priv, _, err := crypto.KeyPairFromStdKey(&edPriv)
	if err != nil {
		return nil, fmt.Errorf("derive libp2p key: %w", err)
	}
	return priv, nil
}

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

	// genesis caches the raw genesis tx this node is running under,
	// so it can answer GenesisRequest streams from peers that are
	// booting without BSV RPC access. Set via SetLocalGenesis after
	// the boot layer has successfully derived the shard.
	genesis genesisStore
}

// NewGossipManager creates a new GossipManager with the given configuration
// and overlay node. It initialises a libp2p host, PeerManager, and message
// handler registry. The gossip manager is not started until Start is called.
func NewGossipManager(config Config, ovl *overlay.OverlayNode) (*GossipManager, error) {
	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = "/ip4/0.0.0.0/tcp/9945"
	}

	opts := []libp2p.Option{libp2p.ListenAddrStrings(listenAddr)}
	if len(config.IdentitySeed) > 0 {
		priv, err := privKeyFromSeed(config.IdentitySeed)
		if err != nil {
			return nil, fmt.Errorf("gossip manager: %w", err)
		}
		opts = append(opts, libp2p.Identity(priv))
	}

	h, err := libp2p.New(opts...)
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

	// Always-on chain-agnostic genesis-sync handler. Lets a brand-
	// new node ask this one for its raw genesis transaction without
	// needing to know the chain ID (followers that never talk to
	// BSV rely on this to bootstrap).
	g.registerGenesisSyncHandler()

	slog.Info("gossip manager started",
		"listenAddrs", g.host.Addrs(),
		"peerID", g.host.ID().String(),
		"protocolID", string(pid),
	)

	// Connect to bootstrap peers in background with retry so simultaneous
	// startup across a Docker cluster doesn't deadlock on TLS handshake
	// collisions. Each peer gets its own goroutine with backoff.
	for _, addr := range g.config.BootstrapPeers {
		addrInfo, err := peer.AddrInfoFromString(addr)
		if err != nil {
			slog.Warn("invalid bootstrap peer address", "addr", addr, "error", err)
			continue
		}
		g.wg.Add(1)
		go func(ai peer.AddrInfo) {
			defer g.wg.Done()
			backoff := 500 * time.Millisecond
			for attempt := 0; attempt < 10; attempt++ {
				if g.host.Network().Connectedness(ai.ID) == network.Connected {
					g.peers.AddPeer(ai.ID, ai.Addrs)
					return
				}
				dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
				err := g.host.Connect(dialCtx, ai)
				dialCancel()
				if err == nil {
					slog.Info("bootstrap peer connected", "peer", ai.ID.String())
					g.peers.AddPeer(ai.ID, ai.Addrs)
					return
				}
				slog.Debug("bootstrap connect attempt failed",
					"peer", ai.ID.String(),
					"attempt", attempt+1,
					"error", err,
				)
				select {
				case <-time.After(backoff):
					backoff *= 2
					if backoff > 10*time.Second {
						backoff = 10 * time.Second
					}
				case <-ctx.Done():
					return
				}
			}
			slog.Warn("failed to connect to bootstrap peer after retries",
				"peer", ai.ID.String())
		}(*addrInfo)
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

// Peers returns the gossip manager's peer manager.
func (g *GossipManager) Peers() *PeerManager { return g.peers }

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
	// Half-close write side so the receiver's readStreamFull gets EOF
	// and can process the request. The read side stays open for the response.
	if err := stream.CloseWrite(); err != nil {
		return nil, fmt.Errorf("failed to close write side: %w", err)
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

	slog.Info("broadcasting message",
		"type", fmt.Sprintf("0x%02x", msg.Type),
		"peerCount", len(peers),
		"payloadSize", len(msg.Payload),
	)

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
				return
			}
			// Half-close write side so the receiver's readStreamFull gets EOF.
			if err := stream.CloseWrite(); err != nil {
				slog.Debug("failed to close write side",
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
	remotePeer := s.Conn().RemotePeer()

	// Rate limit check.
	if !g.peers.CheckRateLimit(remotePeer) {
		slog.Debug("rate limited peer", "peer", remotePeer.String())
		g.peers.AdjustScore(remotePeer, -1)
		s.Close()
		return
	}

	data, err := readStreamFull(s)
	if err != nil {
		slog.Debug("failed to read stream", "peer", remotePeer, "error", err)
		s.Close()
		return
	}

	msg, err := DecodeMessage(data)
	if err != nil {
		slog.Debug("failed to decode message", "peer", remotePeer, "error", err)
		g.peers.AdjustScore(remotePeer, -10)
		s.Close()
		return
	}

	// Batch requests are request-response: the peer expects a BatchResponse
	// written back on the same stream. Handle them inline before the
	// fire-and-forget handler dispatch.
	if msg.Type == MsgBatchRequest {
		g.handleBatchRequest(s, remotePeer, msg)
		return // stream closed by handleBatchRequest
	}
	s.Close()

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

// handleBatchRequest responds to a MsgBatchRequest by looking up the
// batch data in the overlay's TxCache and writing a MsgBatchResponse
// back on the same stream. The stream is closed before returning.
func (g *GossipManager) handleBatchRequest(s network.Stream, peerID peer.ID, msg *Message) {
	defer s.Close()

	reqMsg, err := DecodeBatchRequestMsg(msg.Payload)
	if err != nil {
		slog.Debug("failed to decode batch request", "peer", peerID, "error", err)
		g.peers.AdjustScore(peerID, -5)
		return
	}

	slog.Debug("batch request received",
		"peer", peerID.String(),
		"block", reqMsg.L2BlockNum,
	)

	var batchData []byte
	if g.overlay != nil {
		if cached := g.overlay.TxCacheRef().GetByL2Block(reqMsg.L2BlockNum); cached != nil {
			batchData = cached.BatchData
		}
	}

	if batchData == nil {
		slog.Debug("batch not found for request",
			"block", reqMsg.L2BlockNum,
			"peer", peerID.String(),
		)
	}

	respMsg := &BatchResponseMsg{
		L2BlockNum: reqMsg.L2BlockNum,
		BatchData:  batchData,
	}
	wireMsg, err := respMsg.Encode()
	if err != nil {
		slog.Debug("failed to encode batch response", "error", err)
		return
	}
	encoded, err := wireMsg.Encode()
	if err != nil {
		slog.Debug("failed to encode wire message", "error", err)
		return
	}

	if _, err := s.Write(encoded); err != nil {
		slog.Debug("failed to write batch response", "peer", peerID, "error", err)
		return
	}

	slog.Debug("batch response sent",
		"peer", peerID.String(),
		"block", reqMsg.L2BlockNum,
		"size", len(batchData),
	)
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

	// Filter out loopback addresses (127.0.0.1, ::1). In Docker, mDNS
	// returns the container's loopback alongside its bridge IP, but the
	// loopback points at the local container, not the remote peer.
	var routable []ma.Multiaddr
	for _, addr := range pi.Addrs {
		s := addr.String()
		if strings.HasPrefix(s, "/ip4/127.") || strings.HasPrefix(s, "/ip6/::1/") {
			continue
		}
		routable = append(routable, addr)
	}
	if len(routable) == 0 {
		return
	}
	pi.Addrs = routable

	// Connect in a goroutine with retry so the mDNS loop isn't blocked
	// and simultaneous-dial TLS collisions are handled gracefully.
	go n.connectWithRetry(pi)
}

// connectWithRetry attempts to connect to a peer up to 3 times with
// exponential backoff. Simultaneous dials (both peers discover each other
// via mDNS at the same time) cause TLS handshake collisions; retrying
// with jitter lets one side back off so the other succeeds.
func (n *mdnsNotifee) connectWithRetry(pi peer.AddrInfo) {
	const maxAttempts = 3
	backoff := 200 * time.Millisecond

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Already connected? Skip.
		if n.host.Network().Connectedness(pi.ID) == network.Connected {
			n.peers.AddPeer(pi.ID, pi.Addrs)
			return
		}

		ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
		err := n.host.Connect(ctx, pi)
		cancel()

		if err == nil {
			slog.Debug("peer connected", "peer", pi.ID.String())
			n.peers.AddPeer(pi.ID, pi.Addrs)
			return
		}

		if attempt < maxAttempts-1 {
			slog.Debug("mDNS connect failed, retrying",
				"peer", pi.ID.String(),
				"attempt", attempt+1,
				"error", err,
			)
			time.Sleep(backoff)
			backoff *= 2
		} else {
			slog.Debug("mDNS connect failed after retries",
				"peer", pi.ID.String(),
				"attempts", maxAttempts,
				"error", err,
			)
		}
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
