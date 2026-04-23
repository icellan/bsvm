package overlay

import (
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// TestReplayBatchDataDeterministic verifies that a follower node replaying a
// gossiped batch ends up at the same post-execution state root as the
// producer, even when the follower's configured coinbase differs from the
// producer's. This is the regression test for the deterministic-execution
// bug where ReplayBatchData called ProcessBatch and picked up the local
// node's config.Coinbase + locally-computed timestamp, causing every
// follower to diverge from the producer.
func TestReplayBatchDataDeterministic(t *testing.T) {
	// Shared deterministic funding key/address so both genesis allocs
	// are byte-identical (and therefore produce the same genesis state
	// root).
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	addr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	signer := types.LatestSignerForChainID(big.NewInt(testChainID))

	// Deterministic genesis (same timestamp, alloc) → same genesis
	// state root on both nodes.
	mkGenesis := func() *block.Genesis {
		return &block.Genesis{
			Config:    vm.DefaultL2Config(testChainID),
			Timestamp: 1_700_000_000,
			GasLimit:  30_000_000,
			Alloc: map[types.Address]block.GenesisAccount{
				addr: {
					Balance: uint256.NewInt(1_000_000_000_000_000_000),
				},
			},
		}
	}

	mkNode := func(t *testing.T, coinbase types.Address) (*OverlayNode, db.Database, *block.ChainDB, *block.L2Header) {
		t.Helper()
		database := db.NewMemoryDB()
		genesisHeader, err := block.InitGenesis(database, mkGenesis())
		if err != nil {
			t.Fatalf("InitGenesis: %v", err)
		}

		config := DefaultOverlayConfig()
		config.ChainID = testChainID
		config.Coinbase = coinbase
		config.MaxBatchFlushDelay = 100 * time.Millisecond

		sp1Prover := prover.NewSP1Prover(prover.DefaultConfig())

		compiledCovenant := &covenant.CompiledCovenant{}
		initialState := covenant.CovenantState{
			StateRoot:   genesisHeader.StateRoot,
			BlockNumber: 0,
		}
		covenantMgr := covenant.NewCovenantManager(
			compiledCovenant,
			types.Hash{},
			0,
			10000,
			initialState,
			testChainID,
			covenant.VerifyGroth16,
		)

		chainDB := block.NewChainDB(database)

		node, err := NewOverlayNode(config, chainDB, database, covenantMgr, sp1Prover)
		if err != nil {
			t.Fatalf("NewOverlayNode: %v", err)
		}
		return node, database, chainDB, genesisHeader
	}

	coinbaseA := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	coinbaseB := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	nodeA, _, _, genesisA := mkNode(t, coinbaseA)
	defer nodeA.Stop()
	nodeB, _, _, genesisB := mkNode(t, coinbaseB)
	defer nodeB.Stop()

	// Sanity: both nodes share the same genesis state root.
	if genesisA.StateRoot != genesisB.StateRoot {
		t.Fatalf("genesis state roots differ: A=%s B=%s",
			genesisA.StateRoot.Hex(), genesisB.StateRoot.Hex())
	}

	// Producer (node A) builds a batch with a single transfer.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21_000,
		To:       &recipient,
		Value:    uint256.NewInt(1000),
	})

	resultA, err := nodeA.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch on producer: %v", err)
	}
	if resultA.Block.NumberU64() != 1 {
		t.Fatalf("producer block number = %d, want 1", resultA.Block.NumberU64())
	}
	if len(resultA.BatchData) == 0 {
		t.Fatal("producer did not emit encoded batch data")
	}

	// Follower (node B) replays the producer's encoded batch bytes.
	if err := nodeB.ReplayBatchData(resultA.BatchData); err != nil {
		t.Fatalf("ReplayBatchData on follower: %v", err)
	}

	// Producer and follower must agree on the post-execution state root.
	if nodeB.ExecutionTip() != 1 {
		t.Fatalf("follower execution tip = %d, want 1", nodeB.ExecutionTip())
	}

	followerHeader := nodeB.ChainDB().ReadHeaderByNumber(1)
	if followerHeader == nil {
		t.Fatal("follower block 1 header not found")
	}

	if followerHeader.StateRoot != resultA.StateRoot {
		t.Fatalf("state root divergence after replay: producer=%s follower=%s "+
			"(this is the bug ReplayBatch fixes — followers were using their "+
			"local config.Coinbase instead of the producer's coinbase)",
			resultA.StateRoot.Hex(), followerHeader.StateRoot.Hex())
	}

	// Follower's block coinbase should reflect the producer's, not the
	// follower's local config.
	if followerHeader.Coinbase != coinbaseA {
		t.Errorf("follower block coinbase = %s, want producer coinbase %s",
			followerHeader.Coinbase.Hex(), coinbaseA.Hex())
	}

	// Follower's block timestamp should match the producer's too.
	if followerHeader.Timestamp != resultA.Block.Header.Timestamp {
		t.Errorf("follower block timestamp = %d, want producer timestamp %d",
			followerHeader.Timestamp, resultA.Block.Header.Timestamp)
	}
}
