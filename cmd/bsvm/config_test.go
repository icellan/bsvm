package main

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

	// Metrics defaults — operator runbook gap was "Prometheus not yet
	// wired"; defaults must enable a loopback-only listener.
	if !cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled default = false, want true")
	}
	if cfg.Metrics.ListenAddr != "127.0.0.1:9100" {
		t.Errorf("Metrics.ListenAddr = %q, want %q", cfg.Metrics.ListenAddr, "127.0.0.1:9100")
	}
	if cfg.Metrics.Namespace != "bsvm" {
		t.Errorf("Metrics.Namespace = %q, want %q", cfg.Metrics.Namespace, "bsvm")
	}
}

func TestLoadNodeConfig(t *testing.T) {
	// Write a TOML config file to a temp directory.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	// Stub host bridge + guest ELF so [prover].mode = "local" passes
	// the new on-disk-path validation. The bytes are arbitrary; the
	// validator only checks os.Stat, not the file contents.
	hostBridgePath := filepath.Join(dir, "bsvm-host-bridge")
	if err := os.WriteFile(hostBridgePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("seed host bridge stub: %v", err)
	}
	guestELFPath := filepath.Join(dir, "guest.elf")
	if err := os.WriteFile(guestELFPath, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatalf("seed guest ELF stub: %v", err)
	}

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
host_bridge_binary = "` + hostBridgePath + `"
guest_elf_path = "` + guestELFPath + `"
proof_mode = "groth16-wa"
sp1_proof_mode = "groth16"
timeout = "5m"

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
	if loaded.Prover.HostBridgeBinary != hostBridgePath {
		t.Errorf("Prover.HostBridgeBinary = %q, want %q",
			loaded.Prover.HostBridgeBinary, hostBridgePath)
	}
	if loaded.Prover.GuestELFPath != guestELFPath {
		t.Errorf("Prover.GuestELFPath = %q, want %q",
			loaded.Prover.GuestELFPath, guestELFPath)
	}
	if loaded.Prover.ProofMode != "groth16-wa" {
		t.Errorf("Prover.ProofMode = %q, want %q",
			loaded.Prover.ProofMode, "groth16-wa")
	}
	if loaded.Prover.SP1ProofMode != "groth16" {
		t.Errorf("Prover.SP1ProofMode = %q, want %q",
			loaded.Prover.SP1ProofMode, "groth16")
	}
	if loaded.Prover.Timeout != "5m" {
		t.Errorf("Prover.Timeout = %q, want %q", loaded.Prover.Timeout, "5m")
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

// TestNodeConfig_ToOverlayConfig_PropagatesProverWorkers exercises the
// WW-prover-mode-wiring-workers fix: setting [prover].workers > 1 in
// TOML must lift the overlay's ParallelProver concurrency. The
// overlay then uses ProverWorkers when constructing the
// ParallelProver instead of the previous hard-coded 1.
func TestNodeConfig_ToOverlayConfig_PropagatesProverWorkers(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.Prover.Workers = 4

	oc := cfg.ToOverlayConfig(1)
	if oc.ProverWorkers != 4 {
		t.Errorf("ProverWorkers = %d, want 4", oc.ProverWorkers)
	}

	// 0 / negative falls back to the default (single-prover boot path).
	cfg.Prover.Workers = 0
	oc = cfg.ToOverlayConfig(1)
	if oc.ProverWorkers != 1 {
		t.Errorf("ProverWorkers (workers=0) = %d, want default 1", oc.ProverWorkers)
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
		{"execute", prover.ProverExecute},
		{"MOCK", prover.ProverMock},
		{"Local", prover.ProverLocal},
		{"Execute", prover.ProverExecute},
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

// TestNodeConfig_ToProverConfig_Plumbing exercises the new fields
// introduced for the WW-prover-mode-wiring follow-up: every non-Mode
// knob must round-trip from TOML into the prover.Config the daemon
// actually hands to NewSP1Prover.
func TestNodeConfig_ToProverConfig_Plumbing(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.Prover.Mode = "local"
	cfg.Prover.HostBridgeBinary = "/tmp/host-bridge"
	cfg.Prover.GuestELFPath = "/tmp/guest.elf"
	cfg.Prover.NetworkURL = "https://prover.example/sp1"
	cfg.Prover.Timeout = "5m"
	cfg.Prover.ProofMode = "groth16-wa"
	cfg.Prover.SP1ProofMode = "groth16"

	pc := cfg.ToProverConfig()
	if pc.Mode != prover.ProverLocal {
		t.Errorf("Mode = %v, want ProverLocal", pc.Mode)
	}
	if pc.HostBridgeBinary != "/tmp/host-bridge" {
		t.Errorf("HostBridgeBinary = %q, want %q", pc.HostBridgeBinary, "/tmp/host-bridge")
	}
	if pc.GuestELFPath != "/tmp/guest.elf" {
		t.Errorf("GuestELFPath = %q, want %q", pc.GuestELFPath, "/tmp/guest.elf")
	}
	if pc.NetworkURL != "https://prover.example/sp1" {
		t.Errorf("NetworkURL = %q, want %q", pc.NetworkURL, "https://prover.example/sp1")
	}
	if pc.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", pc.Timeout)
	}
	if pc.ProofMode != prover.ProofModeGroth16WA {
		t.Errorf("ProofMode = %v, want Groth16WA", pc.ProofMode)
	}
	if pc.SP1ProofMode != "groth16" {
		t.Errorf("SP1ProofMode = %q, want %q", pc.SP1ProofMode, "groth16")
	}
}

// TestNodeConfig_ToProverConfig_DefaultsPreserved confirms that
// blank TOML fields fall through to the prover package defaults
// rather than zeroing them — older configs that only set
// [prover].mode + [prover].workers must continue to load with the
// 10-minute Timeout / "compressed" envelope / FRI ProofMode the
// prover package supplies.
func TestNodeConfig_ToProverConfig_DefaultsPreserved(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.Prover.Mode = "mock"

	pc := cfg.ToProverConfig()
	def := prover.DefaultConfig()
	if pc.Timeout != def.Timeout {
		t.Errorf("Timeout = %v, want default %v", pc.Timeout, def.Timeout)
	}
	if pc.SP1ProofMode != def.SP1ProofMode {
		t.Errorf("SP1ProofMode = %q, want default %q", pc.SP1ProofMode, def.SP1ProofMode)
	}
	if pc.ProofMode != def.ProofMode {
		t.Errorf("ProofMode = %v, want default %v", pc.ProofMode, def.ProofMode)
	}
	if pc.HostBridgeBinary != "" {
		t.Errorf("HostBridgeBinary = %q, want empty (mock mode)", pc.HostBridgeBinary)
	}
}

// TestProverSection_Validate covers the ill-formed combinations
// LoadNodeConfig must reject before the daemon boots.
func TestProverSection_Validate(t *testing.T) {
	// Two scratch files used by the local-mode happy-path case.
	dir := t.TempDir()
	hostPath := filepath.Join(dir, "host-bridge")
	elfPath := filepath.Join(dir, "guest.elf")
	if err := os.WriteFile(hostPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("seed host bridge: %v", err)
	}
	if err := os.WriteFile(elfPath, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatalf("seed guest elf: %v", err)
	}

	tests := []struct {
		name    string
		section ProverSection
		wantErr string // empty → expect success
	}{
		{
			name:    "default_mock_ok",
			section: ProverSection{Mode: "mock"},
		},
		{
			name:    "empty_mode_ok",
			section: ProverSection{},
		},
		{
			name:    "unknown_mode_rejected",
			section: ProverSection{Mode: "lcoal"}, // typo
			wantErr: "expected mock, local, network, or execute",
		},
		{
			name: "execute_without_paths_rejected",
			section: ProverSection{
				Mode: "execute",
			},
			wantErr: "host_bridge_binary",
		},
		{
			name: "execute_without_elf_rejected",
			section: ProverSection{
				Mode:             "execute",
				HostBridgeBinary: hostPath,
			},
			wantErr: "guest_elf_path",
		},
		{
			name: "execute_happy_path",
			section: ProverSection{
				Mode:             "execute",
				HostBridgeBinary: hostPath,
				GuestELFPath:     elfPath,
				Workers:          2,
			},
		},
		{
			name: "local_without_paths_rejected",
			section: ProverSection{
				Mode: "local",
			},
			wantErr: "host_bridge_binary",
		},
		{
			name: "local_without_elf_rejected",
			section: ProverSection{
				Mode:             "local",
				HostBridgeBinary: hostPath,
			},
			wantErr: "guest_elf_path",
		},
		{
			name: "local_missing_binary_on_disk",
			section: ProverSection{
				Mode:             "local",
				HostBridgeBinary: filepath.Join(dir, "does-not-exist"),
				GuestELFPath:     elfPath,
			},
			wantErr: "host_bridge_binary",
		},
		{
			name: "local_happy_path",
			section: ProverSection{
				Mode:             "local",
				HostBridgeBinary: hostPath,
				GuestELFPath:     elfPath,
				ProofMode:        "fri",
				SP1ProofMode:     "compressed",
				Timeout:          "30s",
			},
		},
		{
			name: "network_with_url_ok",
			section: ProverSection{
				Mode:       "network",
				NetworkURL: "https://prover.example/sp1",
			},
		},
		{
			name: "network_without_url_ok",
			section: ProverSection{
				Mode: "network",
			},
		},
		{
			name: "network_with_garbage_url_rejected",
			section: ProverSection{
				Mode:       "network",
				NetworkURL: "not a url",
			},
			wantErr: "network_url",
		},
		{
			name: "mock_with_groth16_rejected",
			section: ProverSection{
				Mode:      "mock",
				ProofMode: "groth16",
			},
			wantErr: "contradictory",
		},
		{
			name: "mock_with_groth16_wa_rejected",
			section: ProverSection{
				Mode:      "mock",
				ProofMode: "groth16-wa",
			},
			wantErr: "contradictory",
		},
		{
			name: "mock_with_fri_ok",
			section: ProverSection{
				Mode:      "mock",
				ProofMode: "fri",
			},
		},
		{
			name: "bad_proof_mode_rejected",
			section: ProverSection{
				Mode:      "mock",
				ProofMode: "plonk",
			},
			wantErr: "proof_mode",
		},
		{
			name: "bad_sp1_proof_mode_rejected",
			section: ProverSection{
				Mode:         "mock",
				SP1ProofMode: "starky",
			},
			wantErr: "sp1_proof_mode",
		},
		{
			name: "bad_timeout_rejected",
			section: ProverSection{
				Mode:    "mock",
				Timeout: "five minutes",
			},
			wantErr: "timeout",
		},
		{
			name: "legacy_groth16_witness_alias_ok_with_local",
			section: ProverSection{
				Mode:             "local",
				HostBridgeBinary: hostPath,
				GuestELFPath:     elfPath,
				ProofMode:        "groth16-witness", // legacy alias for groth16-wa
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.section.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestLoadNodeConfig_RejectsBadProverSection confirms that
// LoadNodeConfig surfaces ProverSection.Validate errors so an
// operator who fat-fingers their TOML doesn't silently boot a
// degraded prover.
func TestLoadNodeConfig_RejectsBadProverSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.toml")
	body := `
[prover]
mode = "mock"
proof_mode = "groth16"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadNodeConfig(path); err == nil {
		t.Fatalf("LoadNodeConfig accepted mock + groth16, want rejection")
	} else if !strings.Contains(err.Error(), "contradictory") {
		t.Fatalf("LoadNodeConfig err = %v, want 'contradictory'", err)
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

func TestEVMSection_DefaultsToCancun(t *testing.T) {
	cfg := DefaultNodeConfig()
	if cfg.EVM.Fork != "cancun" {
		t.Errorf("EVM.Fork default = %q, want %q", cfg.EVM.Fork, "cancun")
	}
	if err := cfg.EVM.ValidateFork(); err != nil {
		t.Errorf("ValidateFork on default = %v, want nil", err)
	}
}

func TestEVMSection_ValidateFork(t *testing.T) {
	tests := []struct {
		fork    string
		wantErr bool
	}{
		{"", false},
		{"cancun", false},
		{"CANCUN", false},
		{"Cancun", false},
		{"prague", true},
		{"shanghai", true},
		{"unknown", true},
	}
	for _, tt := range tests {
		t.Run(tt.fork, func(t *testing.T) {
			s := EVMSection{Fork: tt.fork}
			err := s.ValidateFork()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFork(%q) err = %v, wantErr %v", tt.fork, err, tt.wantErr)
			}
		})
	}
}

func TestLoadNodeConfig_RejectsUnsupportedFork(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad-fork.toml")
	content := `
[evm]
fork = "prague"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeConfig(cfgPath); err == nil {
		t.Fatal("expected LoadNodeConfig to reject unsupported [evm].fork, got nil")
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

// TestBSVSection_WoCFanoutDefaults asserts the WoC fan-out + page-
// fetcher defaults match the documented values. These knobs are
// operator-tunable; if defaults shift the example.toml + WoC client
// must be updated in lock-step.
func TestBSVSection_WoCFanoutDefaults(t *testing.T) {
	cfg := DefaultNodeConfig()
	if got, want := cfg.BSV.WoCBlockTxFanoutMax, 1_000_000; got != want {
		t.Errorf("WoCBlockTxFanoutMax default = %d, want %d", got, want)
	}
	if got, want := cfg.BSV.WoCBlockPageFetchWorkers, 4; got != want {
		t.Errorf("WoCBlockPageFetchWorkers default = %d, want %d", got, want)
	}
}

// TestBSVSection_WoCFanoutOverride asserts the operator-supplied TOML
// values reach the loaded config — the cmd-side wiring uses these to
// override the package-level defaults.
func TestBSVSection_WoCFanoutOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	content := `
[bsv]
woc_block_tx_fanout_max = 50000
woc_block_page_fetch_workers = 16
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadNodeConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadNodeConfig: %v", err)
	}
	if loaded.BSV.WoCBlockTxFanoutMax != 50000 {
		t.Errorf("WoCBlockTxFanoutMax = %d, want 50000", loaded.BSV.WoCBlockTxFanoutMax)
	}
	if loaded.BSV.WoCBlockPageFetchWorkers != 16 {
		t.Errorf("WoCBlockPageFetchWorkers = %d, want 16", loaded.BSV.WoCBlockPageFetchWorkers)
	}
}
