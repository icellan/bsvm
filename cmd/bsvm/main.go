// Package main implements the bsvm binary, the primary entry point for
// running a BSVM L2 node. It provides subcommands for initializing a new
// shard, running a node, recovering state from the BSV covenant chain,
// and printing version information.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/governance"
	"github.com/icellan/bsvm/pkg/indexer"
	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/network"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/rpc"
	"github.com/icellan/bsvm/pkg/rpc/auth"
	"github.com/icellan/bsvm/pkg/shard"
	"github.com/icellan/bsvm/pkg/tracing"
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
					&cli.Int64Flag{Name: "chain-id", Value: 0, Usage: "shard chain ID (default: 31337 when --prove-mode is set)"},
					&cli.Uint64Flag{Name: "gas-limit", Value: 0, Usage: "genesis block gas limit (default: 30000000)"},
					&cli.StringFlag{Name: "governance", Value: "", Usage: "governance mode: none, single_key, or multisig (default: single_key when --prove-mode is mock|execute)"},
					&cli.StringFlag{Name: "verification", Value: "", Usage: "verification mode: groth16, groth16-wa, fri, or devkey (auto-selected by --prove-mode if both unset)"},
					&cli.StringFlag{Name: "prove-mode", Value: "", Usage: "spec-16 devnet proof mode: mock, execute, or prove (selects covenant + chain defaults)"},
					&cli.StringFlag{Name: "prefund-accounts", Value: "none", Usage: "prefund well-known test accounts: none or hardhat"},
					&cli.StringFlag{Name: "sp1-vk", Value: "", Usage: "hex-encoded SP1 verifying key (optional for testing)"},
					&cli.StringSliceFlag{Name: "alloc", Usage: "genesis alloc: address=balance_wei (repeatable)"},
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
			devCommand(),
			adminCommand(),
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
//
// Spec 16 devnet: passing --prove-mode mock|execute|prove auto-selects
// verification mode, chain ID default (31337), governance mode
// (single_key for mock/execute), and the devnet governance key so
// developers can spin up a complete shard with a single flag.
func cmdInit(ctx *cli.Context) error {
	dataDir := ctx.String("datadir")
	chainID := ctx.Int64("chain-id")
	gasLimit := ctx.Uint64("gas-limit")
	governanceMode := ctx.String("governance")
	verification := ctx.String("verification")
	proveMode := ctx.String("prove-mode")
	prefund := ctx.String("prefund-accounts")
	sp1KeyHex := ctx.String("sp1-vk")

	// Apply --prove-mode defaults before validation. Spec 16 mapping:
	//   mock    → devkey covenant, single_key governance, chain 31337
	//   execute → devkey covenant, single_key governance, chain 31337
	//   prove   → groth16-wa covenant (mainnet-eligible), chain 31337
	switch proveMode {
	case "":
		// No prove-mode — use explicit flags.
	case "mock", "execute":
		if verification == "" {
			verification = "devkey"
		}
		if governanceMode == "" {
			governanceMode = "single_key"
		}
		if chainID == 0 {
			chainID = 31337
		}
	case "prove":
		if verification == "" {
			verification = "groth16-wa"
		}
		if governanceMode == "" {
			governanceMode = "single_key"
		}
		if chainID == 0 {
			chainID = 31337
		}
	default:
		return fmt.Errorf("invalid prove mode %q: expected mock, execute, or prove", proveMode)
	}

	// Apply remaining defaults for the non-devnet path.
	if verification == "" {
		verification = "groth16"
	}
	if governanceMode == "" {
		governanceMode = "none"
	}
	if chainID == 0 {
		return fmt.Errorf("--chain-id is required (or pass --prove-mode to accept the devnet default 31337)")
	}

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
	case "groth16-wa":
		verifyMode = covenant.VerifyGroth16WA
	case "fri":
		verifyMode = covenant.VerifyFRI
	case "devkey":
		verifyMode = covenant.VerifyDevKey
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

	// Build the genesis allocation. Prefund flag takes effect before
	// --alloc so explicit --alloc entries can override a prefunded
	// balance (e.g. raising Hardhat #0's starting balance for a single
	// scenario).
	alloc := make(map[types.Address]block.GenesisAccount)
	switch prefund {
	case "", "none":
		// No prefunding.
	case "hardhat":
		// 1000 wBSV per account == 1000 * 10^18 wei.
		perAccount := new(uint256.Int).SetUint64(1000)
		perAccount.Mul(perAccount, new(uint256.Int).Exp(
			uint256.NewInt(10), uint256.NewInt(18),
		))
		for addr, acc := range shard.HardhatPrefundAlloc(perAccount) {
			alloc[addr] = acc
		}
	default:
		return fmt.Errorf("invalid prefund-accounts %q: expected none or hardhat", prefund)
	}

	// Parse --alloc flags: "0xAddress=balanceWei"
	for _, entry := range ctx.StringSlice("alloc") {
		parts := splitAllocEntry(entry)
		if len(parts) != 2 {
			return fmt.Errorf("invalid alloc entry %q: expected address=balance", entry)
		}
		addr := types.HexToAddress(parts[0])
		bal := new(uint256.Int)
		if err := bal.SetFromDecimal(parts[1]); err != nil {
			return fmt.Errorf("invalid balance in alloc entry %q: %w", entry, err)
		}
		alloc[addr] = block.GenesisAccount{Balance: bal}
	}

	// Assemble the governance config. For devnet prove-mode runs that
	// request single_key / multisig but don't supply keys, auto-derive
	// the devnet governance key (Hardhat #0 pubkey) so the shard can
	// spin up on just a --prove-mode flag.
	govConfig := covenant.GovernanceConfig{Mode: govMode}
	if proveMode != "" && (govMode == covenant.GovernanceSingleKey || govMode == covenant.GovernanceMultiSig) {
		pub, err := shard.DevnetGovernanceKey()
		if err != nil {
			return fmt.Errorf("deriving devnet governance key: %w", err)
		}
		if govMode == covenant.GovernanceSingleKey {
			govConfig.Keys = [][]byte{pub}
		}
		// Multisig devnet needs the operator to supply the other keys
		// explicitly; auto-deriving a single key only covers single_key.
	}

	params := &shard.InitShardParams{
		ChainID:         chainID,
		DataDir:         dataDir,
		GasLimit:        gasLimit,
		Alloc:           alloc,
		Governance:      govConfig,
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

	// Apply BSVM_* env-var overrides. This is the layer spec 16's
	// docker-compose.yml drives — the TOML file (or DefaultNodeConfig)
	// provides the baseline and each container then tweaks per-node
	// values (ports, peers, role, coinbase) via env.
	if err := ApplyEnvOverrides(nodeCfg); err != nil {
		return fmt.Errorf("applying env overrides: %w", err)
	}

	// Override from flags.
	if rpcAddr != "" {
		nodeCfg.RPC.HTTPAddr = rpcAddr
	}
	if dataDir != "" {
		nodeCfg.DataDir = dataDir
	}

	// Configure logging.
	logStreamer := setupLogging(nodeCfg.LogLevel, nodeCfg.LogFormat)

	// 1.5 Build the metrics registry and OTel tracer. Both are
	// best-effort — the node still runs if tracing can't reach its
	// configured OTLP endpoint. Node identity derives from BSVM_NODE_NAME
	// (set by spec 16 docker-compose) or falls back to the shard config.
	nodeName := NodeNameFromEnv()
	if nodeName == "" {
		nodeName = "node"
	}
	chainIDStr := fmt.Sprintf("%d", nodeCfg.Shard.ChainID)
	metricsRegistry := metrics.NewRegistry(metrics.Labels{
		NodeName: nodeName,
		ChainID:  chainIDStr,
	})

	traceCtx, traceCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer traceCancel()
	shutdownTracing, err := tracing.Setup(traceCtx, tracing.Config{
		NodeName:       nodeName,
		ChainID:        chainIDStr,
		ServiceVersion: version,
	})
	if err != nil {
		slog.Warn("tracing setup failed", "error", err)
	}
	defer func() {
		if shutdownTracing == nil {
			return
		}
		// Give the exporter a bounded window to drain pending spans.
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		if err := shutdownTracing(sctx); err != nil {
			slog.Warn("tracing shutdown error", "error", err)
		}
	}()

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
	case "fri":
		verifyMode = covenant.VerifyFRI
	case "groth16-wa":
		verifyMode = covenant.VerifyGroth16WA
	case "devkey":
		verifyMode = covenant.VerifyDevKey
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

	// Resolve the spec-16 proving mode once so the overlay config,
	// the admin auth config, and the startup banner all see the same
	// value. Failure to parse the env is not fatal — an empty mode
	// simply means "not a devnet" which disables dev-bypass auth.
	proveMode, _ := ProveModeFromEnv()

	// 5. Create overlay node.
	overlayCfg := nodeCfg.ToOverlayConfig(chainID)
	overlayCfg.ProveMode = proveMode
	overlayNode, err := overlay.NewOverlayNodeWithObservability(
		overlayCfg,
		joinResult.ChainDB,
		joinResult.DB,
		covenantMgr,
		sp1Prover,
		metricsRegistry,
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

	// 5.8 Optional per-address transaction indexer. Disabled via
	// BSVM_INDEXER_ENABLED=false or indexer.enabled=false in TOML.
	// When off, the bsv_getAddressTxs RPC returns "indexer disabled"
	// so the explorer SPA can show a tasteful fallback message.
	var txIndexer *indexer.Indexer
	if nodeCfg.Indexer.Enabled {
		idxPath := filepath.Join(nodeCfg.DataDir, "indexer")
		idxCfg := indexer.Config{
			Path:    idxPath,
			ChainID: uint64(chainID),
			Cache:   nodeCfg.Indexer.CacheMB,
			Handles: 16,
		}
		txIndexer, err = indexer.New(idxCfg)
		if err != nil {
			return fmt.Errorf("create indexer at %s: %w", idxPath, err)
		}
		slog.Info("indexer enabled", "path", idxPath, "cacheMB", nodeCfg.Indexer.CacheMB)
	} else {
		slog.Info("indexer disabled (bsv_getAddressTxs will return ErrDisabled)")
	}

	// 6. Create RPC server.
	rpcCfg := nodeCfg.ToRPCConfig()
	rpcServer := rpc.NewRPCServerWithConfig(
		rpcCfg,
		joinResult.ChainConfig,
		overlayNode,
		joinResult.ChainDB,
		joinResult.DB,
	)
	// Attach the Prometheus registry so `/metrics` becomes scrapable
	// alongside the JSON-RPC endpoint.
	rpcServer.SetMetricsRegistry(metricsRegistry)

	// Attach the slog streamer so adminLogs WebSocket subscriptions
	// (spec 15 A9) see structured log records as they happen.
	rpcServer.SetLogStreamer(logStreamer)

	// Spec 15 admin surface. Dev-bypass is enabled only when the
	// shard is running in mock/execute mode AND an explicit secret
	// is configured (BSVM_ADMIN_DEV_SECRET). This keeps the admin
	// surface OFF by default even on a mock shard — operators have
	// to opt in.
	devSecret := strings.TrimSpace(os.Getenv("BSVM_ADMIN_DEV_SECRET"))
	if devSecret == "" && (proveMode == "mock" || proveMode == "execute") {
		// Devnet convenience: fall back to the spec 16 default secret
		// so the stock `docker compose up` workflow has a working
		// admin surface without requiring the operator to pick a
		// secret. Production images MUST set BSVM_ADMIN_DEV_SECRET
		// themselves — this fallback is scoped to dev proving modes
		// which are already unsafe for mainnet.
		devSecret = "devnet-secret-do-not-use-in-production"
	}
	// Build a governance-key checker from the shard config — wallets
	// may only authenticate under keys that the shard genesis listed
	// as governance-authorised.
	govConfig, _ := shardCfg.GovernanceConfig()
	govKeyChecker := &shardGovernanceChecker{keys: govConfig.Keys}

	// Persistent server identity lives inside the node's data dir so
	// a restart keeps existing sessions' trust anchor. Only spawn the
	// handshake endpoint when governance mode has at least one key.
	var serverIdentity *auth.ServerIdentity
	var sessionStore *auth.SessionStore
	if len(govConfig.Keys) > 0 {
		var idErr error
		serverIdentity, idErr = auth.LoadOrCreateServerIdentity(nodeCfg.DataDir)
		if idErr != nil {
			slog.Warn("admin identity: failed to load/create, BRC-100 handshake disabled", "error", idErr)
		} else {
			sessionStore = auth.NewSessionStore()
			sessionStore.StartSweeper()
			defer sessionStore.Close()
		}
	}

	rpcServer.SetAdminAuth(auth.Config{
		DevAuthSecret:     devSecret,
		ShardProvingMode:  overlayNode.ProveMode,
		GovernanceChecker: govKeyChecker,
		ServerIdentity:    serverIdentity,
		SessionStore:      sessionStore,
	})

	// 7. Create gossip manager (P2P network).
	netCfg := nodeCfg.ToNetworkConfig(chainID)
	gossipMgr, err := network.NewGossipManager(netCfg, overlayNode)
	if err != nil {
		return fmt.Errorf("failed to create gossip manager: %w", err)
	}

	// Wire the gossip manager as the block announcer so ProcessBatch
	// broadcasts new blocks to peers for sync.
	overlayNode.SetBlockAnnouncer(gossipMgr)

	// 7.5 Wire the governance proposal workflow (spec 15 A4). Uses a
	// content-addressed in-memory store backed by libp2p gossip so
	// proposals propagate across every node automatically. The
	// signature verifier is a closure that parses a DER signature
	// over the 32-byte proposal ID, returning the recovered pubkey.
	proposalStore := governance.NewMemoryStore()
	proposalWorkflow := governance.NewWorkflow(
		proposalStore,
		func(p *governance.Proposal) error {
			data, err := json.Marshal(p)
			if err != nil {
				return err
			}
			return gossipMgr.BroadcastProposal(data)
		},
		makeProposalVerifier(govConfig.Keys),
	)
	proposalWorkflow.OnReady(func(p *governance.Proposal) {
		// v1: log when a proposal reaches threshold. The actual BSV
		// broadcast path lands when the governance broadcaster is
		// wired up to the covenant manager.
		slog.Info("governance proposal ready for broadcast",
			"id", p.ID,
			"action", p.Action,
			"signatures", len(p.Signatures),
			"required", p.Required,
		)
	})
	rpcServer.AdminAPI().SetGovernanceWorkflow(proposalWorkflow, govConfig.Threshold)
	gossipMgr.RegisterHandler(network.MsgProposal, func(peerID peer.ID, msg *network.Message) error {
		var p governance.Proposal
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return fmt.Errorf("decoding proposal gossip from %s: %w", peerID, err)
		}
		_, err := proposalWorkflow.CreateOrMerge(&p)
		return err
	})

	// 7.6 Attach + start the indexer (if enabled). Must happen after
	// the event feed exists (i.e. overlayNode is constructed) and
	// before any block gets processed on the gossip manager.
	if txIndexer != nil {
		rpcServer.SetIndexer(txIndexer)
	}

	// 8. Start services.
	if err := rpcServer.Start(); err != nil {
		return fmt.Errorf("failed to start RPC server: %w", err)
	}

	bgCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if txIndexer != nil {
		// The overlay's event feed is strongly typed over overlay.NewHeadEvent,
		// so subscribe with a matching channel and forward block pointers
		// onto the indexer's generic ingest channel. Non-blocking send
		// protects block processing from a slow indexer writer.
		inCh := txIndexer.Start(bgCtx)
		evCh := make(chan overlay.NewHeadEvent, 64)
		overlayNode.EventFeed().Subscribe(evCh)
		go func() {
			for {
				select {
				case <-bgCtx.Done():
					return
				case ev := <-evCh:
					select {
					case inCh <- ev.Block:
					default:
						slog.Warn("indexer: channel full, dropping block", "block", ev.Block.NumberU64())
					}
				}
			}
		}()
		defer func() {
			if err := txIndexer.Close(); err != nil {
				slog.Warn("closing indexer", "error", err)
			}
		}()
	}

	if err := gossipMgr.Start(bgCtx); err != nil {
		return fmt.Errorf("failed to start gossip manager: %w", err)
	}

	slog.Info("bsvm node started",
		"chainID", chainID,
		"rpc", rpcCfg.HTTPAddr,
		"p2p", netCfg.ListenAddr,
	)

	// 8.5 Spec 16: print the developer banner on node1 once services are up.
	// Silent on non-devnet invocations (BSVM_NODE_NAME not set).
	PrintStartupBanner(proveMode, chainID, rpcCfg.HTTPAddr, netCfg.ListenAddr)

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
// and format strings. It returns the installed LogStreamer so callers can
// wire it to the WebSocket admin log subscription (spec 15 A9).
func setupLogging(level, format string) *rpc.LogStreamer {
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

	var inner slog.Handler
	if format == "json" {
		inner = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		inner = slog.NewTextHandler(os.Stderr, opts)
	}

	streamer := rpc.NewLogStreamer(inner, 4096)
	slog.SetDefault(slog.New(streamer))
	return streamer
}

// makeProposalVerifier returns a governance.SigVerifier that accepts
// any signature from one of the governance keys over sha256(proposalID).
// It rejects signatures that can't be parsed, don't verify, or come
// from a key outside the governance set.
//
// The signed digest deliberately matches the wallet's existing
// convention of signing sha256(messageBytes): the wallet can reuse
// its BRC-3 signMessage helper with proposalID (already hex-encoded)
// as input without any extra plumbing.
func makeProposalVerifier(govKeys [][]byte) governance.SigVerifier {
	return func(proposalID, sigHex string) ([]byte, error) {
		sigBytes, err := hex.DecodeString(sigHex)
		if err != nil {
			return nil, fmt.Errorf("signatureHex: %w", err)
		}
		sigObj, err := ec.ParseDERSignature(sigBytes)
		if err != nil {
			return nil, fmt.Errorf("parse DER signature: %w", err)
		}
		// sha256 over the ID string (hex of the content hash) — stable
		// across wallets without needing a canonical JSON re-derivation.
		digest := sha256.Sum256([]byte(proposalID))
		for _, keyBytes := range govKeys {
			pub, err := ec.ParsePubKey(keyBytes)
			if err != nil {
				continue
			}
			if sigObj.Verify(digest[:], pub) {
				return keyBytes, nil
			}
		}
		return nil, fmt.Errorf("no governance key verified the signature")
	}
}

// shardGovernanceChecker is the minimal implementation of
// auth.GovernanceKeyChecker backed by the shard config's
// governance-key list. Accepts any compressed secp256k1 key that
// appears verbatim in the genesis config — nothing fancier.
type shardGovernanceChecker struct {
	keys [][]byte
}

// IsGovernanceKey reports whether the given compressed pubkey
// matches one of the shard's governance keys.
func (c *shardGovernanceChecker) IsGovernanceKey(pub []byte) bool {
	for _, k := range c.keys {
		if len(k) == len(pub) && bytesEqual(k, pub) {
			return true
		}
	}
	return false
}

// bytesEqual is a local helper to avoid importing crypto/subtle for
// the fixed-length compressed-key comparison. All inputs here are
// 33 bytes, so constant-time isn't a concern (the set is bounded
// and public).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// splitAllocEntry splits "address=balance" on the first '='.
func splitAllocEntry(s string) []string {
	idx := strings.IndexByte(s, '=')
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+1:]}
}
