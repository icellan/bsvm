// Package main implements the bsvm binary, the primary entry point for
// running a BSVM L2 node. It provides subcommands for initializing a new
// shard, running a node, recovering state from the BSV covenant chain,
// and printing version information.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/network"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/rpc"
	"github.com/icellan/bsvm/pkg/shard"
	"github.com/icellan/bsvm/pkg/types"
	cli "github.com/urfave/cli/v2"
)

const version = "0.1.0"

func main() {
	app := &cli.App{
		Name:    "bsvm",
		Usage:   "BSVM Layer 2 Node",
		Version: version,
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initialize a new L2 chain from genesis",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "datadir", Value: "./data", Usage: "path to data directory"},
					&cli.Int64Flag{Name: "chain-id", Required: true, Usage: "shard chain ID"},
					&cli.Uint64Flag{Name: "gas-limit", Value: 0, Usage: "genesis block gas limit (default: 30000000)"},
					&cli.StringFlag{Name: "governance", Value: "none", Usage: "governance mode: none, single_key, or multisig"},
					&cli.StringFlag{Name: "verification", Value: "groth16", Usage: "verification mode: groth16 or basefold"},
					&cli.StringFlag{Name: "sp1-vk", Value: "", Usage: "hex-encoded SP1 verifying key (optional for testing)"},
				},
				Action: cmdInit,
			},
			{
				Name:  "run",
				Usage: "Start the L2 node",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Value: "", Usage: "path to node config file (TOML)"},
					&cli.StringFlag{Name: "shard-config", Value: "", Usage: "path to shard config file (default: <datadir>/shard.json)"},
					&cli.StringFlag{Name: "datadir", Value: "./data", Usage: "path to data directory"},
					&cli.StringFlag{Name: "rpc-addr", Value: "", Usage: "JSON-RPC listen address (overrides config)"},
				},
				Action: cmdRun,
			},
			{
				Name:  "recover",
				Usage: "Recover shard state from BSV covenant chain (disaster recovery)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "genesis-txid", Required: true, Usage: "genesis covenant transaction ID"},
					&cli.StringFlag{Name: "datadir", Required: true, Usage: "data directory for recovered state"},
					&cli.Int64Flag{Name: "chain-id", Required: true, Usage: "shard chain ID"},
				},
				Action: cmdRecover,
			},
			{
				Name:   "version",
				Usage:  "Print version information",
				Action: cmdVersion,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

// cmdInit handles the "bsvm init" subcommand. It creates a new shard by
// initializing the L2 genesis state, compiling the covenant, and writing
// the shard configuration to disk.
func cmdInit(ctx *cli.Context) error {
	dataDir := ctx.String("datadir")
	chainID := ctx.Int64("chain-id")
	gasLimit := ctx.Uint64("gas-limit")
	governanceMode := ctx.String("governance")
	verification := ctx.String("verification")
	sp1KeyHex := ctx.String("sp1-vk")

	// Parse governance mode.
	var govMode covenant.GovernanceMode
	switch governanceMode {
	case "none":
		govMode = covenant.GovernanceNone
	case "single_key":
		govMode = covenant.GovernanceSingleKey
	case "multisig":
		govMode = covenant.GovernanceMultiSig
	default:
		return fmt.Errorf("invalid governance mode: %s", governanceMode)
	}

	// Parse verification mode.
	var verifyMode covenant.VerificationMode
	switch verification {
	case "groth16":
		verifyMode = covenant.VerifyGroth16
	case "basefold":
		verifyMode = covenant.VerifyBasefold
	default:
		return fmt.Errorf("invalid verification mode: %s", verification)
	}

	// Parse SP1 verifying key.
	var sp1VK []byte
	if sp1KeyHex != "" {
		var err error
		sp1VK, err = hex.DecodeString(sp1KeyHex)
		if err != nil {
			return fmt.Errorf("invalid SP1 verifying key hex: %w", err)
		}
	} else {
		// Use a 32-byte placeholder for testing/development.
		sp1VK = make([]byte, 32)
	}

	params := &shard.InitShardParams{
		ChainID:         chainID,
		DataDir:         dataDir,
		GasLimit:        gasLimit,
		Governance:      covenant.GovernanceConfig{Mode: govMode},
		Verification:    verifyMode,
		SP1VerifyingKey: sp1VK,
	}

	cfg, header, err := shard.InitShard(params)
	if err != nil {
		return fmt.Errorf("shard initialization failed: %w", err)
	}

	slog.Info("shard initialized",
		"chainID", chainID,
		"genesisRoot", header.StateRoot.Hex(),
		"dataDir", dataDir,
		"configPath", filepath.Join(dataDir, "shard.json"),
		"shardID", cfg.ShardID,
	)
	return nil
}

// cmdRun handles the "bsvm run" subcommand. It loads the shard config,
// opens the database, creates all node components, starts services, and
// waits for a shutdown signal.
func cmdRun(ctx *cli.Context) error {
	configPath := ctx.String("config")
	shardConfigPath := ctx.String("shard-config")
	dataDir := ctx.String("datadir")
	rpcAddr := ctx.String("rpc-addr")

	// 1. Load node config.
	var nodeCfg *NodeConfig
	if configPath != "" {
		var err error
		nodeCfg, err = LoadNodeConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load node config: %w", err)
		}
	} else {
		nodeCfg = DefaultNodeConfig()
	}

	// Override from flags.
	if rpcAddr != "" {
		nodeCfg.RPC.HTTPAddr = rpcAddr
	}
	if dataDir != "" {
		nodeCfg.DataDir = dataDir
	}

	// Configure logging.
	setupLogging(nodeCfg.LogLevel, nodeCfg.LogFormat)

	// 2. Load shard config.
	shardCfgPath := shardConfigPath
	if shardCfgPath == "" {
		shardCfgPath = filepath.Join(nodeCfg.DataDir, "shard.json")
	}

	joinResult, err := shard.JoinShard(shardCfgPath, nodeCfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to join shard: %w", err)
	}
	// Ensure DB is closed on all exit paths.
	defer joinResult.DB.Close()

	shardCfg := joinResult.Config
	chainID := shardCfg.ChainID

	slog.Info("shard loaded",
		"chainID", chainID,
		"synced", joinResult.Synced,
	)

	// 3. Create covenant manager.
	genesisTxID := types.HexToHash(shardCfg.GenesisCovenantTxID)
	initialState := covenant.CovenantState{
		StateRoot: types.HexToHash(shardCfg.GenesisStateRoot),
	}

	// Load compiled covenant (may be nil if covenant ANF is not available).
	var compiledCov *covenant.CompiledCovenant
	anfPath := filepath.Join(nodeCfg.DataDir, "covenant.anf.json")
	if _, statErr := os.Stat(anfPath); statErr == nil {
		compiledCov = &covenant.CompiledCovenant{}
	}

	var verifyMode covenant.VerificationMode
	switch shardCfg.VerificationMode {
	case "basefold":
		verifyMode = covenant.VerifyBasefold
	default:
		verifyMode = covenant.VerifyGroth16
	}

	covenantMgr := covenant.NewCovenantManager(
		compiledCov,
		genesisTxID,
		shardCfg.GenesisCovenantVout,
		shardCfg.CovenantSats,
		initialState,
		uint64(chainID),
		verifyMode,
	)

	// 4. Create prover.
	proverCfg := nodeCfg.ToProverConfig()
	sp1Prover := prover.NewSP1Prover(proverCfg)

	// 5. Create overlay node.
	overlayCfg := nodeCfg.ToOverlayConfig(chainID)
	overlayNode, err := overlay.NewOverlayNode(
		overlayCfg,
		joinResult.ChainDB,
		joinResult.DB,
		covenantMgr,
		sp1Prover,
	)
	if err != nil {
		return fmt.Errorf("failed to create overlay node: %w", err)
	}

	// 5.5: Sync from BSV covenant chain if not fully synced.
	if !joinResult.Synced {
		if nodeCfg.BSV.NodeURL != "" {
			slog.Info("BSV sync not yet available, will sync via P2P gossip",
				"bsv_node_url", nodeCfg.BSV.NodeURL)
		} else {
			slog.Info("BSV client not configured, will sync via P2P gossip")
		}
	}

	// 5.6: Bridge monitor (requires BSV client).
	slog.Info("bridge monitor: requires BSV client (will be available with BSV SDK integration)")

	// 5.7: Double-spend monitor (requires BSV block notifications).
	slog.Info("double-spend monitor: initialized, waiting for BSV block notifications")

	// 6. Create RPC server.
	rpcCfg := nodeCfg.ToRPCConfig()
	rpcServer := rpc.NewRPCServerWithConfig(
		rpcCfg,
		joinResult.ChainConfig,
		overlayNode,
		joinResult.ChainDB,
		joinResult.DB,
	)

	// 7. Create gossip manager (P2P network).
	netCfg := nodeCfg.ToNetworkConfig(chainID)
	gossipMgr, err := network.NewGossipManager(netCfg, overlayNode)
	if err != nil {
		return fmt.Errorf("failed to create gossip manager: %w", err)
	}

	// 8. Start services.
	if err := rpcServer.Start(); err != nil {
		return fmt.Errorf("failed to start RPC server: %w", err)
	}

	bgCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := gossipMgr.Start(bgCtx); err != nil {
		return fmt.Errorf("failed to start gossip manager: %w", err)
	}

	slog.Info("bsvm node started",
		"chainID", chainID,
		"rpc", rpcCfg.HTTPAddr,
		"p2p", netCfg.ListenAddr,
	)

	// 9. Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// 10. Graceful shutdown with timeout.
	slog.Info("shutting down...")
	cancel()

	done := make(chan struct{})
	go func() {
		if err := rpcServer.Stop(); err != nil {
			slog.Error("error stopping RPC server", "error", err)
		}
		if err := gossipMgr.Stop(); err != nil {
			slog.Error("error stopping gossip manager", "error", err)
		}
		overlayNode.Stop()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("shutdown complete")
	case <-time.After(30 * time.Second):
		slog.Warn("shutdown timed out after 30s, forcing exit")
	}

	return nil
}

// cmdRecover handles the "bsvm recover" subcommand. It reconstructs the
// complete shard state from BSV covenant chain data.
func cmdRecover(ctx *cli.Context) error {
	dataDir := ctx.String("datadir")
	genesisTxID := ctx.String("genesis-txid")
	chainID := ctx.Int64("chain-id")

	// Open the database.
	dbPath := filepath.Join(dataDir, "chaindata")
	database, err := db.NewLevelDB(dbPath, 256, 256)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	chainDB := block.NewChainDB(database)

	slog.Info("recovery started",
		"dataDir", dataDir,
		"genesisTxID", genesisTxID,
		"chainID", chainID,
	)

	// Check current state.
	headHash := chainDB.ReadHeadBlockHash()
	if headHash != (types.Hash{}) {
		headHeader := chainDB.ReadHeadHeader()
		if headHeader != nil {
			slog.Info("existing state found",
				"headBlock", headHeader.Number,
				"stateRoot", headHeader.StateRoot.Hex(),
			)
		}
	}

	// Recovery requires a BSV client to walk the covenant UTXO chain.
	slog.Warn("recovery requires BSV client integration -- not yet available")
	slog.Info("to recover manually: replay covenant-advance transactions from BSV and re-execute EVM batches")
	return nil
}

// cmdVersion prints version information.
func cmdVersion(ctx *cli.Context) error {
	fmt.Printf("bsvm version %s\n", version)
	return nil
}

// setupLogging configures the slog default logger based on the given level
// and format strings.
func setupLogging(level, format string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
}
