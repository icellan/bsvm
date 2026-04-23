// Genesis-tx sync protocol: a narrow, chain-agnostic libp2p protocol
// that lets a booting node request the raw genesis covenant transaction
// from its peers without having BSV RPC access itself. Verification is
// trivial — the txid is double_sha256(rawTx) reversed — so a peer that
// returns the wrong bytes is immediately caught by the requester and
// no signature / per-message MAC is needed.
//
// The protocol runs on a DIFFERENT stream ID from the main shard
// gossip (GenesisSyncProtocolID vs ProtocolID(chainID)) so followers
// can exchange genesis data BEFORE they know the chain ID. Once they
// have the raw tx and have derived the shard, the main gossip on the
// chain-scoped protocol ID takes over for tx / block / advance
// messages.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// GenesisSyncProtocolID is the chain-agnostic libp2p protocol ID used
// for genesis-tx request/response. Every node (prover and follower)
// SHOULD listen on this protocol so a newly booting peer can ask for
// the raw genesis transaction regardless of whether the peer has BSV
// RPC access itself.
const GenesisSyncProtocolID = "/bsvm/genesis/1.0.0"

// GenesisRequest asks a peer to send the raw deploy transaction for
// the shard the peer believes it is running. There is no payload —
// the request is just an open stream and an immediate CloseWrite.
// The peer responds with whatever it has cached; the requester
// verifies by hashing.
type GenesisRequest struct{}

// GenesisResponse carries the raw genesis tx hex the peer is running.
// No signature is required: the requester re-hashes RawTxHex and
// compares to the expected txid it was configured with. If the hash
// mismatches, the response is rejected.
type GenesisResponse struct {
	// TxIDHex is the 64-char lowercase hex txid the peer claims the
	// raw bytes belong to. Informational only — the requester MUST
	// verify by hashing RawTxHex itself.
	TxIDHex string `json:"txidHex"`
	// RawTxHex is the hex-encoded raw genesis covenant transaction.
	RawTxHex string `json:"rawTxHex"`
}

// genesisStore holds the raw-tx hex a node has locally. Nodes with a
// derived shard set this at startup so they can answer GenesisRequest
// messages from peers. Access is guarded by a mutex so the setter can
// be called concurrently with stream handlers.
type genesisStore struct {
	mu       sync.RWMutex
	txIDHex  string
	rawTxHex string
}

// SetLocalGenesis records the raw genesis-tx hex and its txid so this
// node can answer GenesisRequest messages from other peers. Both
// arguments are hex-encoded strings (the caller has typically just
// verified that hash(rawTxHex) == txIDHex, so there is no additional
// validation here). Calling with empty strings clears the cache.
func (g *GossipManager) SetLocalGenesis(txIDHex, rawTxHex string) {
	g.genesis.mu.Lock()
	defer g.genesis.mu.Unlock()
	g.genesis.txIDHex = txIDHex
	g.genesis.rawTxHex = rawTxHex
}

// localGenesis returns the currently cached genesis txid / raw hex,
// or ("", "") if nothing has been registered yet.
func (g *GossipManager) localGenesis() (string, string) {
	g.genesis.mu.RLock()
	defer g.genesis.mu.RUnlock()
	return g.genesis.txIDHex, g.genesis.rawTxHex
}

// registerGenesisSyncHandler installs the stream handler for
// GenesisSyncProtocolID. Called from Start so the handler is only
// active while the gossip manager is live. Safe to call from Start
// alongside the main shard protocol handler.
func (g *GossipManager) registerGenesisSyncHandler() {
	g.host.SetStreamHandler(protocol.ID(GenesisSyncProtocolID), g.handleGenesisStream)
}

// handleGenesisStream serves GenesisRequest by writing back a
// GenesisResponse with whatever the node has cached locally. The
// protocol is deliberately forgiving — an empty-body request is
// also accepted, matching the request type's empty struct.
//
// Rate limiting is applied via the same PeerManager gate as the
// main protocol handler so a misbehaving peer can't flood a
// follower that is already trying to boot.
func (g *GossipManager) handleGenesisStream(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()

	if !g.peers.CheckRateLimit(remotePeer) {
		slog.Debug("genesis-sync: rate limited peer", "peer", remotePeer.String())
		g.peers.AdjustScore(remotePeer, -1)
		return
	}

	// The request is empty-bodied; drain whatever the peer sent
	// (some implementations may close-write without sending; others
	// might send a JSON stub). We ignore the content.
	if _, err := readStreamFull(s); err != nil {
		slog.Debug("genesis-sync: read request failed", "peer", remotePeer, "error", err)
		return
	}

	txIDHex, rawTxHex := g.localGenesis()
	if rawTxHex == "" {
		// No local genesis cached — close without a response. The
		// requester treats an empty-bodied or timeout response as
		// "peer can't help" and moves on to the next peer.
		slog.Debug("genesis-sync: peer asked but we have no cached genesis",
			"peer", remotePeer.String())
		return
	}

	resp := GenesisResponse{
		TxIDHex:  txIDHex,
		RawTxHex: rawTxHex,
	}
	encoded, err := json.Marshal(&resp)
	if err != nil {
		slog.Debug("genesis-sync: marshal response", "error", err)
		return
	}
	if _, err := s.Write(encoded); err != nil {
		slog.Debug("genesis-sync: write response", "peer", remotePeer, "error", err)
		return
	}
	slog.Debug("genesis-sync: responded to peer",
		"peer", remotePeer.String(),
		"txid", txIDHex,
		"rawBytes", len(rawTxHex)/2,
	)
}

// RequestGenesisFromPeers iterates over the currently connected peer
// set and asks each one for its cached genesis transaction. Returns
// the raw-tx hex of the first response whose TxIDHex matches the
// expected txid (lowercase hex, no 0x). Stops early on first hit.
//
// If no peer returns a matching genesis within the given timeout, an
// error is returned. The caller (boot layer) is expected to log the
// failure and either retry later or escalate — there is no silent
// fallback.
//
// The function deliberately does NOT verify the hash itself; it
// returns whatever the peer claimed if the txid label matches, and
// the boot layer re-hashes via VerifyRawTxMatchesTxID before
// trusting the bytes. That split keeps all hash verification in a
// single auditable helper.
func (g *GossipManager) RequestGenesisFromPeers(
	ctx context.Context,
	expectedTxID string,
	timeout time.Duration,
) (string, error) {
	if expectedTxID == "" {
		return "", fmt.Errorf("genesis-sync: expected txid must not be empty")
	}
	if g.host == nil {
		return "", fmt.Errorf("genesis-sync: gossip manager has no libp2p host")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	want := lowerHex(expectedTxID)

	pid := protocol.ID(GenesisSyncProtocolID)
	// One attempt cycle per second until the deadline; each cycle
	// asks every currently-connected peer in parallel. New peers
	// joining mid-wait are picked up on the next cycle.
	var lastErr error
	for time.Now().Before(deadline) {
		peers := g.peers.AllPeers()
		if len(peers) == 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}
		// Parallel fan-out: first valid response wins.
		resultCh := make(chan genesisFetchResult, len(peers))
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 5*time.Second)
		for _, p := range peers {
			go func(peerID peer.ID) {
				resultCh <- fetchOneGenesis(attemptCtx, g.host, peerID, pid, want)
			}(p)
		}
		// Collect until first success or all failed.
		cycleFailed := 0
		for cycleFailed < len(peers) {
			select {
			case r := <-resultCh:
				if r.err == nil && r.raw != "" {
					attemptCancel()
					return r.raw, nil
				}
				if r.err != nil {
					lastErr = r.err
				}
				cycleFailed++
			case <-ctx.Done():
				attemptCancel()
				return "", ctx.Err()
			case <-time.After(time.Until(deadline)):
				attemptCancel()
				if lastErr != nil {
					return "", fmt.Errorf("genesis-sync: timed out waiting for a peer (last error: %w)", lastErr)
				}
				return "", fmt.Errorf("genesis-sync: timed out waiting for a peer with matching txid %s", want)
			}
		}
		attemptCancel()
		// All peers in this cycle failed; pause briefly before retrying.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("genesis-sync: timed out (last error: %w)", lastErr)
	}
	return "", fmt.Errorf("genesis-sync: timed out; no peer returned matching txid %s", want)
}

// genesisFetchResult is the return shape of fetchOneGenesis. Kept as
// a package-private struct so the channel type in
// RequestGenesisFromPeers stays tidy.
type genesisFetchResult struct {
	raw string
	err error
}

// fetchOneGenesis opens a single stream to the given peer on the
// genesis-sync protocol, reads the response, and returns the raw
// tx hex if the response's claimed txid matches `want`. Errors are
// returned as-is; the caller decides whether to retry.
func fetchOneGenesis(ctx context.Context, h host.Host, peerID peer.ID, pid protocol.ID, want string) genesisFetchResult {
	// Open a short-lived stream.
	s, err := h.NewStream(ctx, peerID, pid)
	if err != nil {
		return genesisFetchResult{"", fmt.Errorf("open stream to %s: %w", peerID, err)}
	}
	defer s.Close()
	// Empty request body; half-close write side so the peer's read
	// loop returns EOF and it can send its response.
	if err := s.CloseWrite(); err != nil {
		return genesisFetchResult{"", fmt.Errorf("close write to %s: %w", peerID, err)}
	}
	data, err := readStreamFull(s)
	if err != nil {
		return genesisFetchResult{"", fmt.Errorf("read response from %s: %w", peerID, err)}
	}
	if len(data) == 0 {
		return genesisFetchResult{"", fmt.Errorf("peer %s returned empty genesis response", peerID)}
	}
	var resp GenesisResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return genesisFetchResult{"", fmt.Errorf("decode response from %s: %w", peerID, err)}
	}
	if lowerHex(resp.TxIDHex) != want {
		return genesisFetchResult{"", fmt.Errorf("peer %s returned txid %s, want %s", peerID, resp.TxIDHex, want)}
	}
	return genesisFetchResult{resp.RawTxHex, nil}
}

// NewBootstrapGenesisSyncer creates a minimal libp2p host dedicated
// solely to the chain-agnostic genesis-sync protocol. A follower that
// doesn't yet know the shard's chain ID calls this at startup,
// dials the configured bootstrap peers, requests the raw genesis tx,
// and then tears it down — the main GossipManager (chain-scoped) is
// spun up afterwards with the derived chain ID.
//
// The returned GossipManager does NOT register the shard-scoped
// protocol handler; only GenesisSyncProtocolID is active. The
// overlay node reference is nil (there's nothing to process yet).
// Bootstrap peers are dialed on Start so RequestGenesisFromPeers
// has a live peer set to fan out to.
func NewBootstrapGenesisSyncer(cfg Config) (*GossipManager, error) {
	// Use a fresh/empty listen addr if the caller hasn't overridden:
	// the bootstrap host only needs outbound dials to peers on the
	// GenesisSyncProtocolID; no inbound reachability required.
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "/ip4/0.0.0.0/tcp/0"
	}
	// ChainID is irrelevant for genesis sync but the main protocol
	// handler's listener still gets registered via Start — set a
	// harmless sentinel so ProtocolID(cfg.ChainID) doesn't collide
	// with any real shard's ID. Zero is fine: no real shard uses 0.
	cfg.ChainID = 0
	gm, err := NewGossipManager(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("bootstrap genesis syncer: %w", err)
	}
	return gm, nil
}

// lowerHex lowercases a hex string and strips an optional 0x prefix.
// Kept local so the genesis-sync protocol and the boot layer apply
// identical normalisation (any mismatch would cause false-negatives).
func lowerHex(s string) string {
	// Cheap, allocation-free lowercase + 0x strip — intentionally
	// minimal to keep the helper obvious.
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
