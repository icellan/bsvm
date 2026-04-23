// Node-local initialization from a shared cluster shard.json.
//
// When a cluster is bootstrapped via `bsvm init-cluster`, the shared
// volume holds a single shard.json + genesis_alloc.json pair. Every
// node must then seed its own local LevelDB with the same genesis
// allocation so that JoinShard's state-root check matches what the
// deployed covenant binds. This file implements that per-node seeding:
//
//  1. Copy (or symlink) the shared shard.json into <datadir>/shard.json
//     so `bsvm run --datadir <datadir>` finds it.
//  2. Open the per-node LevelDB and run block.InitGenesis with the
//     alloc recorded in <shared-dir>/genesis_alloc.json.
//  3. Verify the resulting state root matches the one advertised by the
//     shard config — if not, refuse to continue so operators notice a
//     misconfiguration before broadcasting any covenant advances.
//
// The command is idempotent — if the local DB already contains a
// genesis block with the expected state root, it's a no-op.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/urfave/cli/v2"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/shard"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// cmdInitLocal handles `bsvm init-local`.
func cmdInitLocal(ctx *cli.Context) error {
	sharedConfig := ctx.String("shared-config")
	dataDir := ctx.String("datadir")

	if sharedConfig == "" {
		return fmt.Errorf("init-local: --shared-config is required")
	}
	if dataDir == "" {
		return fmt.Errorf("init-local: --datadir is required")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("init-local: mkdir datadir: %w", err)
	}

	slog.Info("init-local: starting", "sharedConfig", sharedConfig, "datadir", dataDir)

	// 1. Load the shared shard config.
	sharedCfg, err := shard.LoadConfig(sharedConfig)
	if err != nil {
		return fmt.Errorf("init-local: load shared shard config: %w", err)
	}

	// 2. Load the accompanying genesis alloc. Absent file is an
	// operator error — a cluster produced by init-cluster always
	// writes this alongside shard.json.
	sharedDir := filepath.Dir(sharedConfig)
	allocPath := filepath.Join(sharedDir, clusterGenesisAllocFile)
	alloc, err := loadGenesisAlloc(allocPath)
	if err != nil {
		return fmt.Errorf("init-local: load genesis alloc at %s: %w", allocPath, err)
	}
	slog.Info("init-local: loaded genesis alloc", "accounts", len(alloc))

	// 3. Copy the shared shard.json into the per-node datadir so
	// `bsvm run --datadir ...` picks it up by default. We copy rather
	// than symlink so the per-node dir is self-contained.
	localShardPath := filepath.Join(dataDir, "shard.json")
	if err := copyFile(sharedConfig, localShardPath); err != nil {
		return fmt.Errorf("init-local: copy shard.json: %w", err)
	}

	// 3b. Copy covenant.anf.json if present. wireBSVBroadcast checks
	// for its existence to decide whether to pass a CompiledCovenant
	// to the CovenantManager.
	srcANF := filepath.Join(sharedDir, "covenant.anf.json")
	if _, statErr := os.Stat(srcANF); statErr == nil {
		if err := copyFile(srcANF, filepath.Join(dataDir, "covenant.anf.json")); err != nil {
			slog.Warn("init-local: copying covenant.anf.json failed (non-fatal)", "err", err)
		}
	}

	// 4. Open the local DB and run genesis. If the DB already has a
	// head block, check that the state root matches.
	dbPath := filepath.Join(dataDir, "chaindata")
	database, err := db.NewLevelDB(dbPath, 256, 256)
	if err != nil {
		return fmt.Errorf("init-local: open db: %w", err)
	}
	defer database.Close()

	chainDB := block.NewChainDB(database)
	if head := chainDB.ReadHeadBlockHash(); head != (types.Hash{}) {
		headHeader := chainDB.ReadHeadHeader()
		if headHeader == nil {
			return fmt.Errorf("init-local: head block set but header missing")
		}
		got := headHeader.StateRoot.Hex()
		want := sharedCfg.GenesisStateRoot
		if got != want {
			return fmt.Errorf(
				"init-local: local DB genesis state root %s does NOT match cluster config %s — "+
					"operator must wipe %s and retry",
				got, want, dbPath,
			)
		}
		slog.Info("init-local: local DB already initialized with matching genesis", "stateRoot", got)
		return nil
	}

	header, err := block.InitGenesis(database, &block.Genesis{
		Config:    vm.DefaultL2Config(sharedCfg.ChainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     alloc,
	})
	if err != nil {
		return fmt.Errorf("init-local: InitGenesis: %w", err)
	}

	got := header.StateRoot.Hex()
	if got != sharedCfg.GenesisStateRoot {
		return fmt.Errorf(
			"init-local: computed state root %s != cluster config %s — "+
				"genesis alloc out of sync with cluster deploy",
			got, sharedCfg.GenesisStateRoot,
		)
	}
	slog.Info("init-local: DONE", "stateRoot", got, "shardConfig", localShardPath)
	return nil
}

// loadGenesisAlloc reads the JSON file written by writeGenesisAlloc and
// returns the decoded alloc map.
func loadGenesisAlloc(path string) (map[types.Address]block.GenesisAccount, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var serialised map[string]block.GenesisAccount
	if err := json.Unmarshal(raw, &serialised); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	out := make(map[types.Address]block.GenesisAccount, len(serialised))
	for addrStr, acc := range serialised {
		addr := types.HexToAddress(strings.TrimPrefix(addrStr, "0x"))
		out[addr] = acc
	}
	return out, nil
}

// copyFile is a tiny file-copy helper — shard.json is <1 KB so we
// don't bother streaming. We read+write with explicit permissions so
// the destination doesn't inherit the source's 0o600 bootstrap-key
// permissions by accident.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}
