//go:build integration

// Package regtestharness constructs a minimal overlay node bound to a
// real RunarBroadcastClient for end-to-end regtest integration tests. It
// lives in the main bsvm module so it can freely import internal/db and
// other internal packages; the test/integration module (which is a
// separate Go module that cannot reach into internal/) consumes it as a
// public API.
package regtestharness

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Bundle is the fully-wired overlay-and-broadcast system returned by Build.
type Bundle struct {
	Node     *overlay.OverlayNode
	Client   *covenant.RunarBroadcastClient
	Manager  *covenant.CovenantManager
	ChainDB  *block.ChainDB
	Database db.Database

	// TxKey is the deterministic EVM key funded in genesis; tests sign
	// transfer transactions with it.
	TxKey   *ecdsa.PrivateKey
	TxAddr  types.Address
	Signer  types.Signer
	ChainID int64

	// Coinbase is the deterministic L2 block coinbase.
	Coinbase types.Address
}

// Config controls how Build constructs the overlay node and broadcast client.
type Config struct {
	// Contract is the deployed rollup contract the broadcast client will drive.
	Contract *runar.RunarContract
	// Provider is the Rúnar RPC provider.
	Provider runar.Provider
	// Signer is the Rúnar wallet signer for funding inputs.
	Signer runar.Signer
	// ChainID is the L2 chain id AND the rollup contract's embedded chain id.
	// MUST match the chainID used at deploy time.
	ChainID int64
	// TxKeySeed seeds the deterministic EVM test key. The key is funded in
	// genesis so the test can sign transfers without touching the network.
	TxKeySeed byte
	// CoinbaseSeed seeds the deterministic L2 coinbase key.
	CoinbaseSeed byte
	// ProofMode selects which on-chain verification path the overlay's
	// mock prover produces advance proofs for AND which ProofMode the
	// RunarBroadcastClient is bound to. Defaults to ProofModeBasefold so
	// existing tests that only set the three seed fields keep working.
	ProofMode covenant.ProofMode
	// NoBroadcast skips wiring the broadcast client into the covenant
	// manager. ProcessBatch still executes and proves but does not
	// broadcast the advance to BSV. Used by PlanAdvance to extract
	// contract call args without touching the covenant UTXO.
	NoBroadcast bool
}

// Build wires a memory-backed overlay node with a mock prover, initialises
// genesis, and attaches a RunarBroadcastClient to the supplied deployed
// contract. The resulting Bundle is ready for ProcessBatch calls.
func Build(cfg Config) (*Bundle, error) {
	if cfg.Contract == nil {
		return nil, fmt.Errorf("Contract required")
	}
	if cfg.Provider == nil {
		return nil, fmt.Errorf("Provider required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("Signer required")
	}

	txKey, err := deterministicKey(cfg.TxKeySeed)
	if err != nil {
		return nil, fmt.Errorf("tx key: %w", err)
	}
	cbKey, err := deterministicKey(cfg.CoinbaseSeed)
	if err != nil {
		return nil, fmt.Errorf("coinbase key: %w", err)
	}

	txAddr := types.Address(crypto.PubkeyToAddress(txKey.PublicKey))
	coinbase := types.Address(crypto.PubkeyToAddress(cbKey.PublicKey))

	database := db.NewMemoryDB()

	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(cfg.ChainID),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30_000_000,
		Alloc: map[types.Address]block.GenesisAccount{
			txAddr: {
				Balance: uint256.NewInt(1_000_000_000_000_000_000),
			},
		},
	}
	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		return nil, fmt.Errorf("InitGenesis: %w", err)
	}

	overlayCfg := overlay.DefaultOverlayConfig()
	overlayCfg.ChainID = cfg.ChainID
	overlayCfg.Coinbase = coinbase
	overlayCfg.MaxBatchFlushDelay = 100 * time.Millisecond

	proverCfg := prover.DefaultConfig()
	proverCfg.ProofMode = cfg.ProofMode
	sp1Prover := prover.NewSP1Prover(proverCfg)

	cu := cfg.Contract.GetCurrentUtxo()
	if cu == nil {
		return nil, fmt.Errorf("contract.GetCurrentUtxo() == nil after deploy")
	}
	genesisCovTxID, err := ParseHexTxID(cu.Txid)
	if err != nil {
		return nil, fmt.Errorf("parsing deploy txid %q: %w", cu.Txid, err)
	}

	verificationMode := covenant.VerifyBasefold
	switch cfg.ProofMode {
	case covenant.ProofModeBasefold:
		verificationMode = covenant.VerifyBasefold
	case covenant.ProofModeGroth16Generic:
		verificationMode = covenant.VerifyGroth16
	case covenant.ProofModeGroth16Witness:
		verificationMode = covenant.VerifyGroth16WA
	}

	covenantMgr := covenant.NewCovenantManager(
		&covenant.CompiledCovenant{},
		genesisCovTxID,
		uint32(cu.OutputIndex),
		uint64(cu.Satoshis),
		covenant.CovenantState{
			StateRoot:   genesisHeader.StateRoot,
			BlockNumber: 0,
		},
		uint64(cfg.ChainID),
		verificationMode,
	)

	chainDB := block.NewChainDB(database)
	node, err := overlay.NewOverlayNode(overlayCfg, chainDB, database, covenantMgr, sp1Prover)
	if err != nil {
		return nil, fmt.Errorf("NewOverlayNode: %w", err)
	}

	var client *covenant.RunarBroadcastClient
	if !cfg.NoBroadcast {
		client, err = covenant.NewRunarBroadcastClient(covenant.RunarBroadcastClientOpts{
			Contract: cfg.Contract,
			Provider: cfg.Provider,
			Signer:   cfg.Signer,
			ChainID:  cfg.ChainID,
			Mode:     cfg.ProofMode,
		})
		if err != nil {
			return nil, fmt.Errorf("NewRunarBroadcastClient: %w", err)
		}
		covenantMgr.SetBroadcastClient(client)
	}

	return &Bundle{
		Node:     node,
		Client:   client,
		Manager:  covenantMgr,
		ChainDB:  chainDB,
		Database: database,
		TxKey:    txKey,
		TxAddr:   txAddr,
		Signer:   types.LatestSignerForChainID(big.NewInt(cfg.ChainID)),
		ChainID:  cfg.ChainID,
		Coinbase: coinbase,
	}, nil
}

// deterministicKey returns a secp256k1 private key derived from a one-byte seed.
func deterministicKey(seed byte) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 32)
	buf[31] = seed
	return crypto.ToECDSA(buf)
}

// ComputeGenesisStateRoot runs the harness's deterministic genesis
// construction on a throwaway in-memory database and returns the resulting
// state root. Intended for callers that need to deploy a rollup covenant
// whose initial stateRoot field must match the harness's genesis before
// Build is invoked — the subsequent Build call will re-derive the same
// root from the same seeds, so the deployed contract and the in-memory
// overlay agree.
//
// This depends only on cfg.ChainID and cfg.TxKeySeed. The timestamp field
// set inside Build does not influence the state root.
func ComputeGenesisStateRoot(cfg Config) (types.Hash, error) {
	txKey, err := deterministicKey(cfg.TxKeySeed)
	if err != nil {
		return types.Hash{}, fmt.Errorf("tx key: %w", err)
	}
	txAddr := types.Address(crypto.PubkeyToAddress(txKey.PublicKey))

	database := db.NewMemoryDB()
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(cfg.ChainID),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30_000_000,
		Alloc: map[types.Address]block.GenesisAccount{
			txAddr: {
				Balance: uint256.NewInt(1_000_000_000_000_000_000),
			},
		},
	}
	header, err := block.InitGenesis(database, genesis)
	if err != nil {
		return types.Hash{}, fmt.Errorf("InitGenesis: %w", err)
	}
	return header.StateRoot, nil
}

// ParseHexTxID decodes a 64-char (optionally 0x-prefixed) hex string into
// a types.Hash. Intended for turning Rúnar SDK txid strings into values the
// CovenantManager can track.
func ParseHexTxID(s string) (types.Hash, error) {
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return types.Hash{}, err
	}
	if len(b) != 32 {
		return types.Hash{}, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	var h types.Hash
	copy(h[:], b)
	return h, nil
}

// PlannedAdvance holds the contract call arguments that ProcessBatch would
// have broadcast, extracted from a no-broadcast overlay run. Tests use it
// to tamper individual args and verify on-chain rejection.
type PlannedAdvance struct {
	// Result is the full ProcessResult from the overlay run.
	Result *overlay.ProcessResult
	// Proof is the mode-specific AdvanceProof built from the prover output.
	Proof covenant.AdvanceProof
	// Args is the positional argument slice for contract.Call("advanceState", ...).
	Args []interface{}
	// CallOpts holds the Groth16 WA witness bundle (non-nil for Mode 3 only).
	CallOpts *runar.CallOptions
}

// PlanAdvance executes a batch through the overlay (including proving) and
// extracts the contract call args that would have been broadcast, WITHOUT
// actually broadcasting to BSV. The overlay state advances (execution tip
// moves forward, state is committed) but the covenant UTXO is untouched.
//
// Callers must have built the bundle with NoBroadcast: true.
func (b *Bundle) PlanAdvance(txs []*types.Transaction) (*PlannedAdvance, error) {
	result, err := b.Node.ProcessBatch(txs)
	if err != nil {
		return nil, fmt.Errorf("ProcessBatch: %w", err)
	}
	if result.ProveOutput == nil {
		return nil, fmt.Errorf("no proof output — is the mock prover configured?")
	}
	if result.BatchData == nil {
		return nil, fmt.Errorf("no batch data in ProcessResult")
	}

	proof, err := overlay.BuildAdvanceProofForOutput(result.ProveOutput, result.BatchData)
	if err != nil {
		return nil, fmt.Errorf("BuildAdvanceProofForOutput: %w", err)
	}

	req := covenant.BroadcastRequest{
		NewState: covenant.CovenantState{
			StateRoot:   result.StateRoot,
			BlockNumber: result.Block.NumberU64(),
		},
		Proof: proof,
	}
	args, err := proof.ContractCallArgs(req)
	if err != nil {
		return nil, fmt.Errorf("ContractCallArgs: %w", err)
	}

	var callOpts *runar.CallOptions
	if waProof, ok := proof.(*covenant.Groth16WitnessProof); ok && waProof.Witness != nil {
		callOpts = &runar.CallOptions{
			Groth16WAWitness: waProof.Witness,
		}
	}

	return &PlannedAdvance{
		Result:   result,
		Proof:    proof,
		Args:     args,
		CallOpts: callOpts,
	}, nil
}
