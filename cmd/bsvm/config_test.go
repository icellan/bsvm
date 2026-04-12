package main

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/prover"
)

func TestDefaultNodeConfig(t *testing.T) {
	cfg := DefaultNodeConfig()

	if cfg.DataDir != "./data" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "./data")
	}
	if cfg.Overlay.BlockGasLimit != 30_000_000 {
		t.Errorf("BlockGasLimit = %d, want %d", cfg.Overlay.BlockGasLimit, 30_000_000)
	}
	if cfg.Overlay.MaxBatchSize != 128 {
		t.Errorf("MaxBatchSize = %d, want %d", cfg.Overlay.MaxBatchSize, 128)
	}
	if cfg.Overlay.MinGasPrice != "1000000000" {
		t.Errorf("MinGasPrice = %q, want %q", cfg.Overlay.MinGasPrice, "1000000000")
	}
	if cfg.Overlay.MaxSpeculativeDepth != 16 {
		t.Errorf("MaxSpeculativeDepth = %d, want %d", cfg.Overlay.MaxSpeculativeDepth, 16)
	}
	if cfg.RPC.HTTPAddr != "0.0.0.0:8545" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.RPC.HTTPAddr, "0.0.0.0:8545")
	}
	if cfg.RPC.WSAddr != "0.0.0.0:8546" {
		t.Errorf("WSAddr = %q, want %q", cfg.RPC.WSAddr, "0.0.0.0:8546")
	}
	if len(cfg.RPC.CORSOrigins) != 1 || cfg.RPC.CORSOrigins[0] != "*" {
		t.Errorf("CORSOrigins = %v, want [*]", cfg.RPC.CORSOrigins)
	}
	if cfg.Prover.Mode != "mock" {
		t.Errorf("Prover.Mode = %q, want %q", cfg.Prover.Mode, "mock")
	}
	if cfg.Prover.Workers != 1 {
		t.Errorf("Prover.Workers = %d, want %d", cfg.Prover.Workers, 1)
	}
	if cfg.Network.ListenAddr != "/ip4/0.0.0.0/tcp/9945" {
		t.Errorf("Network.ListenAddr = %q, want %q", cfg.Network.ListenAddr, "/ip4/0.0.0.0/tcp/9945")
	}
	if cfg.Network.MaxPeers != 50 {
		t.Errorf("Network.MaxPeers = %d, want %d", cfg.Network.MaxPeers, 50)
	}
	if cfg.Bridge.MinDepositSatoshis != 10000 {
		t.Errorf("Bridge.MinDepositSatoshis = %d, want %d", cfg.Bridge.MinDepositSatoshis, 10000)
	}
	if cfg.Bridge.BSVConfirmations != 6 {
		t.Errorf("Bridge.BSVConfirmations = %d, want %d", cfg.Bridge.BSVConfirmations, 6)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "text")
	}

	// Database defaults.
	if cfg.Database.Engine != "leveldb" {
		t.Errorf("Database.Engine = %q, want %q", cfg.Database.Engine, "leveldb")
	}
	if cfg.Database.CacheMB != 256 {
		t.Errorf("Database.CacheMB = %d, want %d", cfg.Database.CacheMB, 256)
	}

	// Governance defaults (zero value = no governance).
	if cfg.Governance.Mode != "" {
		t.Errorf("Governance.Mode = %q, want %q", cfg.Governance.Mode, "")
	}
	if len(cfg.Governance.Keys) != 0 {
		t.Errorf("Governance.Keys = %v, want empty", cfg.Governance.Keys)
	}
	if cfg.Governance.Threshold != 0 {
		t.Errorf("Governance.Threshold = %d, want %d", cfg.Governance.Threshold, 0)
	}

	// BSV defaults.
	if cfg.BSV.Network != "mainnet" {
		t.Errorf("BSV.Network = %q, want %q", cfg.BSV.Network, "mainnet")
	}
	if cfg.BSV.Confirmations != 6 {
		t.Errorf("BSV.Confirmations = %d, want %d", cfg.BSV.Confirmations, 6)
	}
}

func TestLoadNodeConfig(t *testing.T) {
	// Write a TOML config file to a temp directory.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	tomlContent := `
datadir = "/tmp/bsvm-test"
log_level = "debug"
log_format = "json"

[overlay]
coinbase = "0x1234567890abcdef1234567890abcdef12345678"
block_gas_limit = 15000000
batch_size = 64
max_batch_flush_delay = "500ms"
min_gas_price = "2000000000"
max_speculative_depth = 8

[rpc]
http_addr = "127.0.0.1:9545"
ws_addr = "127.0.0.1:9546"
cors_origins = ["http://localhost:3000"]

[prover]
mode = "local"
workers = 4

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9000"
bootstrap_peers = ["/ip4/1.2.3.4/tcp/9000/p2p/QmTest"]
max_peers = 25

[bsv]
node_url = "http://localhost:8332"
arc_url = "https://arc.taal.com"
network = "testnet"
fee_wallet_key = "/path/to/key.wif"
confirmations = 3

[bridge]
min_deposit_satoshis = 20000
min_withdrawal_satoshis = 50000
bsv_confirmations = 3

[database]
engine = "pebble"
cache_mb = 512

[governance]
mode = "multisig"
keys = ["02aaa", "02bbb", "02ccc"]
threshold = 2
`

	if err := os.WriteFile(cfgPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadNodeConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadNodeConfig: %v", err)
	}

	if loaded.DataDir != "/tmp/bsvm-test" {
		t.Errorf("DataDir = %q, want %q", loaded.DataDir, "/tmp/bsvm-test")
	}
	if loaded.Overlay.BlockGasLimit != 15_000_000 {
		t.Errorf("BlockGasLimit = %d, want %d", loaded.Overlay.BlockGasLimit, 15_000_000)
	}
	if loaded.Overlay.MaxBatchSize != 64 {
		t.Errorf("MaxBatchSize = %d, want %d", loaded.Overlay.MaxBatchSize, 64)
	}
	if loaded.Prover.Mode != "local" {
		t.Errorf("Prover.Mode = %q, want %q", loaded.Prover.Mode, "local")
	}
	if loaded.Network.MaxPeers != 25 {
		t.Errorf("Network.MaxPeers = %d, want %d", loaded.Network.MaxPeers, 25)
	}
	if loaded.Bridge.MinDepositSatoshis != 20000 {
		t.Errorf("Bridge.MinDepositSatoshis = %d, want %d", loaded.Bridge.MinDepositSatoshis, 20000)
	}
	if loaded.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", loaded.LogLevel, "debug")
	}
	if loaded.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", loaded.LogFormat, "json")
	}
	if len(loaded.RPC.CORSOrigins) != 1 || loaded.RPC.CORSOrigins[0] != "http://localhost:3000" {
		t.Errorf("CORSOrigins = %v, want [http://localhost:3000]", loaded.RPC.CORSOrigins)
	}
	if loaded.BSV.NodeURL != "http://localhost:8332" {
		t.Errorf("BSV.NodeURL = %q, want %q", loaded.BSV.NodeURL, "http://localhost:8332")
	}
	if loaded.BSV.ARCURL != "https://arc.taal.com" {
		t.Errorf("BSV.ARCURL = %q, want %q", loaded.BSV.ARCURL, "https://arc.taal.com")
	}
	if loaded.BSV.Network != "testnet" {
		t.Errorf("BSV.Network = %q, want %q", loaded.BSV.Network, "testnet")
	}
	if loaded.BSV.FeeWalletKey != "/path/to/key.wif" {
		t.Errorf("BSV.FeeWalletKey = %q, want %q", loaded.BSV.FeeWalletKey, "/path/to/key.wif")
	}
	if loaded.BSV.Confirmations != 3 {
		t.Errorf("BSV.Confirmations = %d, want %d", loaded.BSV.Confirmations, 3)
	}
	if loaded.Database.Engine != "pebble" {
		t.Errorf("Database.Engine = %q, want %q", loaded.Database.Engine, "pebble")
	}
	if loaded.Database.CacheMB != 512 {
		t.Errorf("Database.CacheMB = %d, want %d", loaded.Database.CacheMB, 512)
	}
	if loaded.Governance.Mode != "multisig" {
		t.Errorf("Governance.Mode = %q, want %q", loaded.Governance.Mode, "multisig")
	}
	if len(loaded.Governance.Keys) != 3 {
		t.Errorf("Governance.Keys length = %d, want %d", len(loaded.Governance.Keys), 3)
	}
	if loaded.Governance.Threshold != 2 {
		t.Errorf("Governance.Threshold = %d, want %d", loaded.Governance.Threshold, 2)
	}
}

func TestLoadNodeConfig_FileNotFound(t *testing.T) {
	_, err := LoadNodeConfig("/nonexistent/config.toml")
	if err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}
}

func TestLoadNodeConfig_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(cfgPath, []byte("not [valid toml {{{"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadNodeConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
}

func TestConfigOverride(t *testing.T) {
	// Write a minimal config that overrides only some fields.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "partial.toml")

	partial := `
[overlay]
block_gas_limit = 20000000

[rpc]
http_addr = "0.0.0.0:7545"
`
	if err := os.WriteFile(cfgPath, []byte(partial), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadNodeConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadNodeConfig: %v", err)
	}

	// Overridden value.
	if loaded.Overlay.BlockGasLimit != 20_000_000 {
		t.Errorf("BlockGasLimit = %d, want %d", loaded.Overlay.BlockGasLimit, 20_000_000)
	}
	if loaded.RPC.HTTPAddr != "0.0.0.0:7545" {
		t.Errorf("HTTPAddr = %q, want %q", loaded.RPC.HTTPAddr, "0.0.0.0:7545")
	}

	// Default values should be preserved.
	if loaded.Overlay.MaxBatchSize != 128 {
		t.Errorf("MaxBatchSize = %d, want default %d", loaded.Overlay.MaxBatchSize, 128)
	}
	if loaded.Network.MaxPeers != 50 {
		t.Errorf("Network.MaxPeers = %d, want default %d", loaded.Network.MaxPeers, 50)
	}
}

func TestNodeConfig_ToOverlayConfig(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.Overlay.Coinbase = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.Overlay.BlockGasLimit = 15_000_000
	cfg.Overlay.MaxBatchSize = 64
	cfg.Overlay.MaxBatchFlushDelay = "500ms"
	cfg.Overlay.MinGasPrice = "2000000000"
	cfg.Overlay.MaxSpeculativeDepth = 8

	oc := cfg.ToOverlayConfig(42)

	if oc.ChainID != 42 {
		t.Errorf("ChainID = %d, want %d", oc.ChainID, 42)
	}
	if oc.BlockGasLimit != 15_000_000 {
		t.Errorf("BlockGasLimit = %d, want %d", oc.BlockGasLimit, 15_000_000)
	}
	if oc.MaxBatchSize != 64 {
		t.Errorf("MaxBatchSize = %d, want %d", oc.MaxBatchSize, 64)
	}
	if oc.MaxBatchFlushDelay != 500*time.Millisecond {
		t.Errorf("MaxBatchFlushDelay = %v, want %v", oc.MaxBatchFlushDelay, 500*time.Millisecond)
	}
	if oc.MinGasPrice.Cmp(big.NewInt(2_000_000_000)) != 0 {
		t.Errorf("MinGasPrice = %s, want 2000000000", oc.MinGasPrice)
	}
	if oc.MaxSpeculativeDepth != 8 {
		t.Errorf("MaxSpeculativeDepth = %d, want %d", oc.MaxSpeculativeDepth, 8)
	}
}

func TestNodeConfig_ToRPCConfig(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.RPC.HTTPAddr = "127.0.0.1:9000"
	cfg.RPC.WSAddr = "127.0.0.1:9001"
	cfg.RPC.CORSOrigins = []string{"http://example.com"}

	rc := cfg.ToRPCConfig()

	if rc.HTTPAddr != "127.0.0.1:9000" {
		t.Errorf("HTTPAddr = %q, want %q", rc.HTTPAddr, "127.0.0.1:9000")
	}
	if rc.WSAddr != "127.0.0.1:9001" {
		t.Errorf("WSAddr = %q, want %q", rc.WSAddr, "127.0.0.1:9001")
	}
	if len(rc.CORSOrigins) != 1 || rc.CORSOrigins[0] != "http://example.com" {
		t.Errorf("CORSOrigins = %v, want [http://example.com]", rc.CORSOrigins)
	}
}

func TestNodeConfig_ToProverConfig(t *testing.T) {
	tests := []struct {
		mode string
		want prover.ProverMode
	}{
		{"mock", prover.ProverMock},
		{"local", prover.ProverLocal},
		{"network", prover.ProverNetwork},
		{"MOCK", prover.ProverMock},
		{"Local", prover.ProverLocal},
		{"unknown", prover.ProverMock},
		{"", prover.ProverMock},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg := DefaultNodeConfig()
			cfg.Prover.Mode = tt.mode

			pc := cfg.ToProverConfig()
			if pc.Mode != tt.want {
				t.Errorf("Mode = %v, want %v", pc.Mode, tt.want)
			}
		})
	}
}

func TestNodeConfig_ToNetworkConfig(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.Network.ListenAddr = "/ip4/0.0.0.0/tcp/8000"
	cfg.Network.BootstrapPeers = []string{"/ip4/1.2.3.4/tcp/8000/p2p/QmTest"}
	cfg.Network.MaxPeers = 25

	nc := cfg.ToNetworkConfig(99)

	if nc.ChainID != 99 {
		t.Errorf("ChainID = %d, want %d", nc.ChainID, 99)
	}
	if nc.ListenAddr != "/ip4/0.0.0.0/tcp/8000" {
		t.Errorf("ListenAddr = %q, want %q", nc.ListenAddr, "/ip4/0.0.0.0/tcp/8000")
	}
	if len(nc.BootstrapPeers) != 1 || nc.BootstrapPeers[0] != "/ip4/1.2.3.4/tcp/8000/p2p/QmTest" {
		t.Errorf("BootstrapPeers = %v, want [/ip4/1.2.3.4/tcp/8000/p2p/QmTest]", nc.BootstrapPeers)
	}
	if nc.MaxPeers != 25 {
		t.Errorf("MaxPeers = %d, want %d", nc.MaxPeers, 25)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	// Load the example TOML config file to ensure it parses correctly.
	cfg, err := LoadNodeConfig("bsvm.example.toml")
	if err != nil {
		t.Fatalf("failed to load example config: %v", err)
	}

	if cfg.Overlay.BlockGasLimit != 30_000_000 {
		t.Errorf("example config BlockGasLimit = %d, want %d", cfg.Overlay.BlockGasLimit, 30_000_000)
	}
	if cfg.RPC.HTTPAddr != "0.0.0.0:8545" {
		t.Errorf("example config HTTPAddr = %q, want %q", cfg.RPC.HTTPAddr, "0.0.0.0:8545")
	}
	if cfg.Prover.Mode != "mock" {
		t.Errorf("example config Prover.Mode = %q, want %q", cfg.Prover.Mode, "mock")
	}
	if cfg.Database.Engine != "leveldb" {
		t.Errorf("example config Database.Engine = %q, want %q", cfg.Database.Engine, "leveldb")
	}
	if cfg.Database.CacheMB != 256 {
		t.Errorf("example config Database.CacheMB = %d, want %d", cfg.Database.CacheMB, 256)
	}
	if cfg.Governance.Mode != "none" {
		t.Errorf("example config Governance.Mode = %q, want %q", cfg.Governance.Mode, "none")
	}
	if cfg.BSV.Network != "mainnet" {
		t.Errorf("example config BSV.Network = %q, want %q", cfg.BSV.Network, "mainnet")
	}
}

func TestBSVSection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	content := `
[bsv]
node_url = "http://bsv-node:8332"
arc_url = "https://arc.taal.com"
network = "regtest"
fee_wallet_key = "/tmp/key.wif"
confirmations = 3
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadNodeConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadNodeConfig: %v", err)
	}

	if loaded.BSV.NodeURL != "http://bsv-node:8332" {
		t.Errorf("BSV.NodeURL = %q, want %q", loaded.BSV.NodeURL, "http://bsv-node:8332")
	}
	if loaded.BSV.ARCURL != "https://arc.taal.com" {
		t.Errorf("BSV.ARCURL = %q, want %q", loaded.BSV.ARCURL, "https://arc.taal.com")
	}
	if loaded.BSV.Network != "regtest" {
		t.Errorf("BSV.Network = %q, want %q", loaded.BSV.Network, "regtest")
	}
	if loaded.BSV.FeeWalletKey != "/tmp/key.wif" {
		t.Errorf("BSV.FeeWalletKey = %q, want %q", loaded.BSV.FeeWalletKey, "/tmp/key.wif")
	}
	if loaded.BSV.Confirmations != 3 {
		t.Errorf("BSV.Confirmations = %d, want %d", loaded.BSV.Confirmations, 3)
	}
}
