package network

import "time"

// Config holds the configuration for the P2P network layer.
type Config struct {
	// ListenAddr is the libp2p multiaddr to listen on.
	// Default: "/ip4/0.0.0.0/tcp/9945"
	ListenAddr string

	// BootstrapPeers is a list of libp2p multiaddrs with peer IDs for
	// initial peer discovery. These are used to bootstrap the peer-to-peer
	// network on first startup.
	BootstrapPeers []string

	// MaxPeers is the maximum number of connected peers. Default: 50.
	MaxPeers int

	// ChainID is the L2 shard chain ID, used to construct the protocol ID
	// so that nodes on different shards do not interfere.
	ChainID int64

	// RateLimit is the maximum number of messages per second accepted
	// from a single peer before messages are dropped. Default: 100.
	RateLimit int

	// HeartbeatInterval is the interval at which heartbeat messages are
	// sent to all connected peers. Default: 10s.
	HeartbeatInterval time.Duration

	// MaxConnectionsPerIP is the maximum number of simultaneous connections
	// allowed from a single IP address. Default: 5.
	MaxConnectionsPerIP int

	// EnableMDNS enables mDNS-based peer discovery for local development.
	// Default: true.
	EnableMDNS bool

	// IdentitySeed is a 32-byte seed used to deterministically derive the
	// libp2p host's ed25519 identity key. When non-empty, the resulting
	// peer ID is stable across restarts, so bootstrap lists configured
	// with fixed `/p2p/<peer-id>` suffixes (typical devnet / multinode
	// compose) can reliably dial this node. When empty, libp2p falls
	// back to generating a fresh random identity at each startup.
	IdentitySeed []byte
}

// DefaultConfig returns a Config with sensible defaults for production use.
func DefaultConfig() Config {
	return Config{
		ListenAddr:          "/ip4/0.0.0.0/tcp/9945",
		MaxPeers:            50,
		ChainID:             1,
		RateLimit:           100,
		HeartbeatInterval:   10 * time.Second,
		MaxConnectionsPerIP: 5,
		EnableMDNS:          true,
	}
}
