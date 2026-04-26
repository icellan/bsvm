// network.go: BSVNetworkClient — the unified façade composing
// ARCClient + ChaintracksClient + WhatsOnChainClient + BEEFStore per
// spec 17. The legacy RPCProvider in this package is now considered
// DEPRECATED for new broadcast / status / header lookups; it remains
// supported as the BSV-node optional backup path and as the existing
// regtest harness's fast-path. Production wiring SHOULD route new
// broadcast and chain-observation calls through NetworkClient.
package bsvclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/whatsonchain"
)

// NetworkConfig configures a NetworkClient. Each sub-client is
// optional: when nil, the corresponding role is unavailable and
// NetworkClient methods return ErrProviderDisabled. At minimum
// production deployments require ARC + Chaintracks; WoC and the
// BEEFStore are strongly recommended; the legacy BSV-node backup is
// off by default.
type NetworkConfig struct {
	ARC          arc.ARCClient
	Chaintracks  chaintracks.ChaintracksClient
	WhatsOnChain whatsonchain.WhatsOnChainClient
	BEEFStore    beef.Store
}

// NetworkClient is the unified BSV network façade. The rest of BSVM
// imports this and selects sub-clients via the role accessors.
//
// All exported methods are safe for concurrent use.
type NetworkClient struct {
	cfg NetworkConfig

	mu       sync.RWMutex
	healthAt time.Time
	health   NetworkHealth
}

// New constructs a NetworkClient from the given config.
func NewNetworkClient(cfg NetworkConfig) *NetworkClient {
	return &NetworkClient{cfg: cfg}
}

// ARC returns the configured ARC client, or nil.
func (n *NetworkClient) ARC() arc.ARCClient { return n.cfg.ARC }

// Chaintracks returns the configured chaintracks client, or nil.
func (n *NetworkClient) Chaintracks() chaintracks.ChaintracksClient { return n.cfg.Chaintracks }

// WhatsOnChain returns the configured WoC client, or nil if disabled.
func (n *NetworkClient) WhatsOnChain() whatsonchain.WhatsOnChainClient { return n.cfg.WhatsOnChain }

// BEEFStore returns the configured BEEF store, or nil if disabled.
func (n *NetworkClient) BEEFStore() beef.Store { return n.cfg.BEEFStore }

// ErrProviderDisabled is returned when a NetworkClient method is
// called for a provider role that is not configured.
var ErrProviderDisabled = errors.New("bsvclient: provider disabled")

// Broadcast routes to ARC. Returns ErrProviderDisabled if ARC is not
// configured.
func (n *NetworkClient) Broadcast(ctx context.Context, txOrBeef []byte) (*arc.BroadcastResponse, error) {
	if n.cfg.ARC == nil {
		return nil, fmt.Errorf("Broadcast: %w", ErrProviderDisabled)
	}
	return n.cfg.ARC.Broadcast(ctx, txOrBeef)
}

// ChainTip returns the current BSV best-chain tip from chaintracks.
func (n *NetworkClient) ChainTip(ctx context.Context) (uint64, [32]byte, error) {
	if n.cfg.Chaintracks == nil {
		return 0, [32]byte{}, fmt.Errorf("ChainTip: %w", ErrProviderDisabled)
	}
	tip, err := n.cfg.Chaintracks.Tip(ctx)
	if err != nil {
		return 0, [32]byte{}, err
	}
	return tip.Height, tip.Hash, nil
}

// Confirmations returns the BSV confirmation count for a mined tx.
// height is the block at which the tx was mined; blockHash is the
// expected block hash (used to detect reorged-off txs).
func (n *NetworkClient) Confirmations(ctx context.Context, height uint64, blockHash [32]byte) (int64, error) {
	if n.cfg.Chaintracks == nil {
		return 0, fmt.Errorf("Confirmations: %w", ErrProviderDisabled)
	}
	return n.cfg.Chaintracks.Confirmations(ctx, height, blockHash)
}

// FetchAncestor pulls the raw bytes of txid from the cheapest
// available source: BEEFStore → WoC. Returns ErrAncestorNotFound when
// every configured source returns a not-found / disabled response.
//
// SCAFFOLD: production should also try the optional BSV-node backup
// after WoC; that wiring lands when the BSV-node backup interface
// formalises.
func (n *NetworkClient) FetchAncestor(ctx context.Context, txid [32]byte) ([]byte, error) {
	if n.cfg.BEEFStore != nil {
		if env, err := n.cfg.BEEFStore.Get(txid); err == nil && env != nil {
			parsed, perr := beef.ParseBEEF(env.Beef)
			if perr == nil {
				for _, tx := range parsed.Txs {
					if tx.TxID == txid {
						return tx.RawTx, nil
					}
				}
			}
		}
	}
	if n.cfg.WhatsOnChain != nil {
		raw, err := n.cfg.WhatsOnChain.GetTx(ctx, txid)
		if err == nil {
			return raw, nil
		}
		if !errors.Is(err, whatsonchain.ErrNotFound) {
			return nil, err
		}
	}
	return nil, ErrAncestorNotFound
}

// ErrAncestorNotFound is returned when no provider has the requested
// ancestor transaction.
var ErrAncestorNotFound = errors.New("bsvclient: ancestor not found")

// SubscribeReorgs forwards to chaintracks. Subscribers MUST treat any
// confirmed BEEF whose block height is above the reorg's common
// ancestor as invalidated; see spec 17 §"Reorg Handling via Chaintracks".
func (n *NetworkClient) SubscribeReorgs(ctx context.Context) (<-chan *chaintracks.ReorgEvent, error) {
	if n.cfg.Chaintracks == nil {
		return nil, fmt.Errorf("SubscribeReorgs: %w", ErrProviderDisabled)
	}
	return n.cfg.Chaintracks.SubscribeReorgs(ctx)
}

// HealthStatus probes each configured provider's Ping endpoint and
// returns a per-provider reachability snapshot. The returned struct
// is a snapshot — calling repeatedly re-probes.
func (n *NetworkClient) HealthStatus(ctx context.Context) NetworkHealth {
	out := NetworkHealth{Probed: time.Now().UTC()}
	if n.cfg.ARC != nil {
		out.ARC = probe(ctx, "arc", n.cfg.ARC.Ping)
	}
	if n.cfg.Chaintracks != nil {
		out.Chaintracks = probe(ctx, "chaintracks", n.cfg.Chaintracks.Ping)
	}
	if n.cfg.WhatsOnChain != nil {
		out.WhatsOnChain = probe(ctx, "whatsonchain", n.cfg.WhatsOnChain.Ping)
	}
	n.mu.Lock()
	n.health = out
	n.healthAt = out.Probed
	n.mu.Unlock()
	return out
}

// LastHealth returns the most recently probed health snapshot, or
// the zero value if HealthStatus has never been called.
func (n *NetworkClient) LastHealth() NetworkHealth {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.health
}

// NetworkHealth is the per-provider reachability snapshot.
type NetworkHealth struct {
	Probed       time.Time
	ARC          ProviderHealth
	Chaintracks  ProviderHealth
	WhatsOnChain ProviderHealth
}

// ProviderHealth describes a single provider's reachability.
type ProviderHealth struct {
	Name      string
	Reachable bool
	Latency   time.Duration
	LastError string
}

func probe(ctx context.Context, name string, ping func(ctx context.Context) error) ProviderHealth {
	start := time.Now()
	err := ping(ctx)
	out := ProviderHealth{Name: name, Latency: time.Since(start)}
	if err == nil {
		out.Reachable = true
	} else {
		out.LastError = err.Error()
	}
	return out
}
