package shard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ShardInfo describes a discovered shard's basic properties. It contains
// enough information to decide whether to join the shard and how to
// obtain the full configuration.
type ShardInfo struct {
	// ChainID is the EIP-155 chain identifier.
	ChainID int64 `json:"chainId"`
	// ShardID is the globally unique shard identifier (genesis covenant txid).
	ShardID string `json:"shardId"`
	// GenesisCovenantTxID is the BSV transaction that created the covenant.
	GenesisCovenantTxID string `json:"genesisCovenantTxId"`
	// BootstrapPeers lists known peer multiaddrs for this shard.
	BootstrapPeers []string `json:"bootstrapPeers,omitempty"`
	// GovernanceMode is the shard's trust model.
	GovernanceMode string `json:"governanceMode"`
}

// discoveryClient is the HTTP client used for shard discovery requests.
// It has a short timeout to avoid blocking on unresponsive peers.
var discoveryClient = &http.Client{
	Timeout: 10 * time.Second,
}

// DiscoverShards queries bootstrap peers for known shards. Each peer is
// expected to expose a JSON endpoint at /shards that returns a list of
// ShardInfo objects. Results from all reachable peers are merged and
// deduplicated by shard ID.
//
// If no bootstrap peers are provided, the function returns an empty
// slice without error. Unreachable peers are silently skipped.
func DiscoverShards(bootstrapPeers []string) ([]ShardInfo, error) {
	if len(bootstrapPeers) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var result []ShardInfo

	for _, peer := range bootstrapPeers {
		shards, err := queryPeerShards(peer)
		if err != nil {
			// Skip unreachable peers silently. Discovery is best-effort.
			continue
		}
		for _, s := range shards {
			if _, ok := seen[s.ShardID]; ok {
				continue
			}
			seen[s.ShardID] = struct{}{}
			result = append(result, s)
		}
	}

	return result, nil
}

// ResolveShardConfig downloads a shard's full configuration from a
// bootstrap peer. The peer is expected to expose a JSON endpoint at
// /shard/{chainID}/config that returns a ShardConfig object.
func ResolveShardConfig(peerAddr string, chainID int64) (*ShardConfig, error) {
	url := fmt.Sprintf("%s/shard/%d/config", peerAddr, chainID)
	resp, err := discoveryClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("requesting shard config from %s: %w", peerAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer %s returned status %d for chain %d", peerAddr, resp.StatusCode, chainID)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading shard config response: %w", err)
	}

	var cfg ShardConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("parsing shard config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid shard config from peer: %w", err)
	}

	return &cfg, nil
}

// queryPeerShards queries a single peer for its list of known shards.
func queryPeerShards(peerAddr string) ([]ShardInfo, error) {
	url := fmt.Sprintf("%s/shards", peerAddr)
	resp, err := discoveryClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var shards []ShardInfo
	if err := json.Unmarshal(body, &shards); err != nil {
		return nil, err
	}

	return shards, nil
}
