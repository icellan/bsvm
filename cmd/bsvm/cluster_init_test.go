package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/holiman/uint256"
	cli "github.com/urfave/cli/v2"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/bsvclient"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/shard"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// newTestCliContext builds a minimal *cli.Context preloaded with the
// given flag values. Supports string and int64 flags, which is all the
// init-cluster / init-local subcommands need.
func newTestCliContext(t *testing.T, values map[string]interface{}) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	for name, v := range values {
		switch x := v.(type) {
		case string:
			set.String(name, x, "")
		case int64:
			set.Int64(name, x, "")
		default:
			t.Fatalf("newTestCliContext: unsupported flag type %T for %q", v, name)
		}
	}
	app := cli.NewApp()
	c := cli.NewContext(app, set, nil)
	c.Context = context.Background()
	// Re-apply values explicitly so set flags are marked as "IsSet"
	// from the cli.Context's perspective.
	for name, v := range values {
		switch x := v.(type) {
		case string:
			_ = set.Set(name, x)
		case int64:
			_ = set.Set(name, fmt.Sprintf("%d", x))
		}
	}
	return c
}

// Reuse mockRPCRequest / mockRPCError from devnet_funding_test.go
// (same package). Build a minimal mockHTTPRPC tailored to this file so
// tests don't cross-contaminate with devnet_funding_test.go.

type clusterMockRPC struct {
	t        *testing.T
	handlers map[string]func(params []interface{}) (interface{}, *mockRPCError)
	callLog  []string
	calls    atomic.Int64
}

func newClusterMockRPC(t *testing.T) *clusterMockRPC {
	return &clusterMockRPC{
		t:        t,
		handlers: make(map[string]func([]interface{}) (interface{}, *mockRPCError)),
	}
}

func (m *clusterMockRPC) on(method string, h func(params []interface{}) (interface{}, *mockRPCError)) {
	m.handlers[method] = h
}

func (m *clusterMockRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.calls.Add(1)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req mockRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.callLog = append(m.callLog, req.Method)
	h, ok := m.handlers[req.Method]
	if !ok {
		m.t.Errorf("cluster mock: unexpected RPC method: %s", req.Method)
		http.Error(w, "unknown method", http.StatusNotFound)
		return
	}
	result, rpcErr := h(req.Params)
	env := struct {
		Result interface{}   `json:"result"`
		Error  *mockRPCError `json:"error"`
		ID     uint64        `json:"id"`
	}{Result: result, Error: rpcErr, ID: req.ID}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
}

// TestCmdInitCluster_AlreadyInitialized confirms that when a shard.json
// with a live covenant tx already exists, the bootstrap is a no-op —
// no deploy, no funding RPCs.
func TestCmdInitCluster_AlreadyInitialized(t *testing.T) {
	dataDir := t.TempDir()
	shardPath := filepath.Join(dataDir, "shard.json")

	// Seed a pre-existing shard.json with a known txid.
	preTxID := "aa11bb22aa11bb22aa11bb22aa11bb22aa11bb22aa11bb22aa11bb22aa11bb22"
	preCfg := &shard.ShardConfig{
		ChainID:             31337,
		ShardID:             preTxID,
		GenesisCovenantTxID: preTxID,
		GenesisCovenantVout: 0,
		CovenantSats:        10000,
		SP1VerifyingKey:     strings.Repeat("00", 32),
		GovernanceMode:      "single_key",
		GovernanceKeys:      []string{strings.Repeat("ab", 33)},
		GovernanceThreshold: 0,
		VerificationMode:    "fri",
		GenesisStateRoot:    strings.Repeat("00", 32),
		HashFunction:        "keccak256",
	}
	if err := preCfg.Save(shardPath); err != nil {
		t.Fatalf("preCfg.Save: %v", err)
	}

	mock := newClusterMockRPC(t)
	mock.on("getrawtransaction", func(params []interface{}) (interface{}, *mockRPCError) {
		// Verify the txid passed matches our seed.
		if got, _ := params[0].(string); got != preTxID {
			t.Errorf("getrawtransaction txid=%v, want %s", params[0], preTxID)
		}
		return map[string]interface{}{
			"hex":           "abcd",
			"confirmations": float64(5),
		}, nil
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	// Drive the command via the public invoker. We build a cli.Context
	// manually because the full app plumbing isn't needed.
	ctx := newTestCliContext(t, map[string]interface{}{
		"datadir":          dataDir,
		"bsv-rpc":          srv.URL + "/",
		"bsv-network":      "regtest",
		"prove-mode":       "execute",
		"chain-id":         int64(31337),
		"prefund-accounts": "hardhat",
	})

	if err := cmdInitCluster(ctx); err != nil {
		t.Fatalf("cmdInitCluster: %v", err)
	}

	// Only one RPC call should have been issued (the idempotency probe).
	if got := mock.calls.Load(); got != 1 {
		t.Errorf("expected 1 RPC call on already-initialized, got %d (methods: %v)",
			got, mock.callLog)
	}

	// The shard.json must not have been rewritten with a different txid.
	got, err := shard.LoadConfig(shardPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got.GenesisCovenantTxID != preTxID {
		t.Errorf("shard txid overwritten: got %s, want %s", got.GenesisCovenantTxID, preTxID)
	}
}

// TestCmdInitCluster_RequiresBSVRPC makes sure we refuse to run without
// an RPC endpoint configured.
func TestCmdInitCluster_RequiresBSVRPC(t *testing.T) {
	dataDir := t.TempDir()
	// Intentionally unset BSVM_BSV_RPC in the current process env.
	t.Setenv("BSVM_BSV_RPC", "")
	ctx := newTestCliContext(t, map[string]interface{}{
		"datadir":          dataDir,
		"bsv-rpc":          "",
		"bsv-network":      "regtest",
		"prove-mode":       "execute",
		"chain-id":         int64(31337),
		"prefund-accounts": "hardhat",
	})
	if err := cmdInitCluster(ctx); err == nil {
		t.Fatalf("expected error when bsv-rpc is missing")
	} else if !strings.Contains(err.Error(), "bsv-rpc") {
		t.Errorf("err does not mention bsv-rpc: %v", err)
	}
}

// TestLoadAndSaveGenesisAlloc round-trips a small alloc through the
// JSON helpers used by init-cluster and init-local.
func TestLoadAndSaveGenesisAlloc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alloc.json")
	addr := types.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bal := uint256.NewInt(1000)
	alloc := map[types.Address]block.GenesisAccount{
		addr: {Balance: bal},
	}
	if err := writeGenesisAlloc(path, alloc); err != nil {
		t.Fatalf("writeGenesisAlloc: %v", err)
	}
	// Confirm file exists and is parseable JSON.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got map[string]block.GenesisAccount
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("round-trip alloc size=%d, want 1", len(got))
	}

	roundTripped, err := loadGenesisAlloc(path)
	if err != nil {
		t.Fatalf("loadGenesisAlloc: %v", err)
	}
	ra, ok := roundTripped[addr]
	if !ok {
		t.Fatalf("addr %s missing after round-trip", addr.Hex())
	}
	if ra.Balance == nil || ra.Balance.Uint64() != 1000 {
		t.Errorf("balance round-trip mismatch: got %v, want 1000", ra.Balance)
	}
}

// TestInitLocal_FromSharedShard validates the init-local flow:
// writing genesis alloc + shard.json to a shared dir, then running
// cmdInitLocal against a fresh per-node datadir must produce a local
// DB whose state root matches the shared config. Uses a zero-alloc
// genesis for simplicity.
func TestInitLocal_FromSharedShard(t *testing.T) {
	sharedDir := t.TempDir()
	nodeDir := t.TempDir()

	// Compute the deterministic genesis state root with empty alloc.
	tmpDB := db.NewMemoryDB()
	hdr, err := block.InitGenesis(tmpDB, &block.Genesis{
		Config:   vm.DefaultL2Config(31337),
		GasLimit: block.DefaultGasLimit,
		Alloc:    map[types.Address]block.GenesisAccount{},
	})
	if err != nil {
		t.Fatalf("temp InitGenesis: %v", err)
	}
	_ = tmpDB.Close()

	// Write shared shard.json and empty alloc.
	shardPath := filepath.Join(sharedDir, "shard.json")
	cfg := &shard.ShardConfig{
		ChainID:             31337,
		ShardID:             strings.Repeat("cd", 32),
		GenesisCovenantTxID: strings.Repeat("cd", 32),
		GenesisCovenantVout: 0,
		CovenantSats:        10000,
		SP1VerifyingKey:     strings.Repeat("00", 32),
		GovernanceMode:      "single_key",
		GovernanceKeys:      []string{strings.Repeat("02", 33)},
		GovernanceThreshold: 0,
		VerificationMode:    "fri",
		GenesisStateRoot:    hdr.StateRoot.Hex(),
		HashFunction:        "keccak256",
	}
	if err := cfg.Save(shardPath); err != nil {
		t.Fatalf("save shard: %v", err)
	}
	if err := writeGenesisAlloc(
		filepath.Join(sharedDir, clusterGenesisAllocFile),
		map[types.Address]block.GenesisAccount{},
	); err != nil {
		t.Fatalf("writeGenesisAlloc: %v", err)
	}

	ctx := newTestCliContext(t, map[string]interface{}{
		"shared-config": shardPath,
		"datadir":       nodeDir,
	})

	if err := cmdInitLocal(ctx); err != nil {
		t.Fatalf("cmdInitLocal: %v", err)
	}

	// The local dir must contain a shard.json and a populated chaindata.
	if _, err := os.Stat(filepath.Join(nodeDir, "shard.json")); err != nil {
		t.Errorf("expected local shard.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nodeDir, "chaindata")); err != nil {
		t.Errorf("expected local chaindata dir: %v", err)
	}

	// Running again must be idempotent.
	if err := cmdInitLocal(ctx); err != nil {
		t.Fatalf("cmdInitLocal (rerun): %v", err)
	}
}

// Sanity compilation check — confirms the RPC provider wiring used in
// cluster_init.go still compiles against bsvclient.RPCProvider.
func TestClusterInit_ProviderCompileCheck(t *testing.T) {
	var _ *bsvclient.RPCProvider = nil
	var _ covenant.VerificationMode = covenant.VerifyFRI
}
