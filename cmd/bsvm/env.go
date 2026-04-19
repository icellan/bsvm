package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ApplyEnvOverrides mutates the provided NodeConfig so that BSVM_* env
// vars overlay the TOML-loaded values. Spec 16 devnet drives every node
// setting from Docker Compose env vars (BSVM_PROVE_MODE, BSVM_CHAIN_ID,
// BSVM_RPC_PORT, BSVM_P2P_PORT, BSVM_PEERS, BSVM_COINBASE, BSVM_ROLE,
// BSVM_BSV_RPC, BSVM_BATCH_SIZE, BSVM_FLUSH_DELAY, BSVM_GAS_PRICE,
// BSVM_LOG_LEVEL, BSVM_DEPOSIT_CONFIRMATIONS). TOML remains the source
// of truth for installs that don't use env; this layer only fills the
// container ergonomic gap.
//
// Only non-empty env values override. Parsing errors are returned so the
// container doesn't silently start with garbage config.
func ApplyEnvOverrides(cfg *NodeConfig) error {
	if cfg == nil {
		return fmt.Errorf("node config must not be nil")
	}

	if v := os.Getenv("BSVM_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("BSVM_CHAIN_ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("BSVM_CHAIN_ID: %w", err)
		}
		cfg.Shard.ChainID = n
	}
	if v := os.Getenv("BSVM_RPC_PORT"); v != "" {
		cfg.RPC.HTTPAddr = "0.0.0.0:" + v
		// The WebSocket server historically runs on RPC_PORT+1. Keep
		// that offset when the operator picks an RPC port via env.
		wsPort, err := strconv.Atoi(v)
		if err == nil {
			cfg.RPC.WSAddr = fmt.Sprintf("0.0.0.0:%d", wsPort+1)
		}
	}
	if v := os.Getenv("BSVM_P2P_PORT"); v != "" {
		cfg.Network.ListenAddr = fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", v)
	}
	if v := os.Getenv("BSVM_PEERS"); v != "" {
		// BSVM_PEERS is a comma-separated list of <host>:<port> pairs
		// (Docker service names). Translate to libp2p multiaddrs so
		// the NetworkConfig bootstrap list can absorb them.
		parts := strings.Split(v, ",")
		peers := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// If the operator already supplied a full multiaddr leave
			// it unchanged; otherwise build one from host:port.
			if strings.HasPrefix(p, "/") {
				peers = append(peers, p)
				continue
			}
			host, port, found := strings.Cut(p, ":")
			if !found {
				return fmt.Errorf("BSVM_PEERS entry %q must be host:port or a multiaddr", p)
			}
			peers = append(peers, fmt.Sprintf("/dns4/%s/tcp/%s", host, port))
		}
		cfg.Network.BootstrapPeers = peers
	}
	if v := os.Getenv("BSVM_COINBASE"); v != "" {
		cfg.Overlay.Coinbase = v
	}
	if v := os.Getenv("BSVM_BSV_RPC"); v != "" {
		cfg.BSV.NodeURL = v
	}
	if v := os.Getenv("BSVM_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("BSVM_BATCH_SIZE: %w", err)
		}
		cfg.Overlay.MaxBatchSize = n
	}
	if v := os.Getenv("BSVM_FLUSH_DELAY"); v != "" {
		cfg.Overlay.MaxBatchFlushDelay = v
	}
	if v := os.Getenv("BSVM_GAS_PRICE"); v != "" {
		// BSVM_GAS_PRICE is expressed in gwei for parity with Ethereum
		// tooling. Convert to wei for the overlay config which expects
		// a base-10 wei string.
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return fmt.Errorf("BSVM_GAS_PRICE: %w", err)
		}
		cfg.Overlay.MinGasPrice = strconv.FormatUint(n*1_000_000_000, 10)
	}
	if v := os.Getenv("BSVM_DEPOSIT_CONFIRMATIONS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("BSVM_DEPOSIT_CONFIRMATIONS: %w", err)
		}
		cfg.Bridge.BSVConfirmations = n
		cfg.BSV.Confirmations = n
	}

	return nil
}

// ProveModeFromEnv returns the spec-16 proving mode set via
// BSVM_PROVE_MODE, or "" if unset. Non-empty values must be mock,
// execute, or prove; anything else is rejected.
func ProveModeFromEnv() (string, error) {
	v := strings.TrimSpace(os.Getenv("BSVM_PROVE_MODE"))
	if v == "" {
		return "", nil
	}
	switch v {
	case "mock", "execute", "prove":
		return v, nil
	default:
		return "", fmt.Errorf("BSVM_PROVE_MODE %q: expected mock, execute, or prove", v)
	}
}

// NodeRoleFromEnv returns BSVM_ROLE (prover or follower) for spec 16
// devnet nodes. Empty if unset.
func NodeRoleFromEnv() string {
	return strings.TrimSpace(os.Getenv("BSVM_ROLE"))
}

// NodeNameFromEnv returns BSVM_NODE_NAME — used for the spec 16
// startup banner (only node1 prints the full banner).
func NodeNameFromEnv() string {
	return strings.TrimSpace(os.Getenv("BSVM_NODE_NAME"))
}
