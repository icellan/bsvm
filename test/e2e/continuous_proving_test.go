package e2e

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
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
)

const continuousChainID = 1337

type continuousSetup struct {
	node      *overlay.OverlayNode
	fake      *covenant.FakeBroadcastClient
	key       *ecdsa.PrivateKey
	addr      types.Address
	signer    types.Signer
	database  db.Database
	proofMode prover.ProofMode
}

// newContinuousSetup builds an overlay node wired to a mock SP1 prover and
// an in-memory fake broadcast client. proofMode selects which on-chain
// verification path the mock prover targets (Basefold / Groth16-generic /
// Groth16-witness).
func newContinuousSetup(t *testing.T, seed byte, proofMode prover.ProofMode) *continuousSetup {
	t.Helper()

	keyBytes := make([]byte, 32)
	keyBytes[31] = seed
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	addr := types.Address(crypto.PubkeyToAddress(key.PublicKey))

	cbBytes := make([]byte, 32)
	cbBytes[31] = seed + 1
	cbKey, err := crypto.ToECDSA(cbBytes)
	if err != nil {
		t.Fatalf("ToECDSA coinbase: %v", err)
	}
	coinbase := types.Address(crypto.PubkeyToAddress(cbKey.PublicKey))

	database := db.NewMemoryDB()

	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(continuousChainID),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30_000_000,
		Alloc: map[types.Address]block.GenesisAccount{
			addr: {
				Balance: uint256.NewInt(1_000_000_000_000_000_000),
			},
		},
	}

	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}

	cfg := overlay.DefaultOverlayConfig()
	cfg.ChainID = continuousChainID
	cfg.Coinbase = coinbase
	cfg.MaxBatchFlushDelay = 100 * time.Millisecond

	proverCfg := prover.DefaultConfig()
	proverCfg.ProofMode = proofMode
	sp1Prover := prover.NewSP1Prover(proverCfg)

	compiled := &covenant.CompiledCovenant{}
	initialState := covenant.CovenantState{
		StateRoot:   genesisHeader.StateRoot,
		BlockNumber: 0,
	}
	// Non-zero genesis txid so Track/GetConfirmations see distinct keys
	// even though the manager's txid only changes after ApplyAdvance.
	var genesisTxID types.Hash
	genesisTxID[0] = 0xaa
	covenantMgr := covenant.NewCovenantManager(
		compiled,
		genesisTxID,
		0,
		10000,
		initialState,
		continuousChainID,
		covenant.VerifyGroth16,
	)

	chainDB := block.NewChainDB(database)

	node, err := overlay.NewOverlayNode(cfg, chainDB, database, covenantMgr, sp1Prover)
	if err != nil {
		t.Fatalf("NewOverlayNode: %v", err)
	}

	fake := covenant.NewFakeBroadcastClient()
	covenantMgr.SetBroadcastClient(fake)

	return &continuousSetup{
		node:      node,
		fake:      fake,
		key:       key,
		addr:      addr,
		signer:    types.LatestSignerForChainID(big.NewInt(continuousChainID)),
		database:  database,
		proofMode: proofMode,
	}
}

func (cs *continuousSetup) signTransfer(t *testing.T, nonce uint64, to types.Address, value *uint256.Int) *types.Transaction {
	t.Helper()
	tx := types.MustSignNewTx(cs.key, cs.signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &to,
		Value:    value,
	})
	return tx
}

func waitFor(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", desc)
	}
}

// TestContinuousProvingLoop verifies the full produce -> prove -> broadcast
// -> confirm -> finalize pipeline using the in-memory fake broadcast client.
// It runs with the default Basefold proof mode and asserts the broadcast
// carries a non-nil AdvanceProof plus the usual state/confirmation shape.
func TestContinuousProvingLoop(t *testing.T) {
	cs := newContinuousSetup(t, 1, prover.ProofModeFRI)
	defer cs.node.Stop()

	cs.node.StartConfirmationWatcher(cs.fake, 50*time.Millisecond)

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000aa")
	transfer := uint256.NewInt(1000)

	const numBatches = 5
	for i := uint64(0); i < numBatches; i++ {
		tx := cs.signTransfer(t, i, recipient, transfer)
		_, err := cs.node.ProcessBatch([]*types.Transaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch %d: %v", i+1, err)
		}

		if got := cs.node.ProvenTip(); got != i+1 {
			t.Errorf("batch %d: ProvenTip = %d, want %d", i+1, got, i+1)
		}

		broadcasts := cs.fake.Broadcasts()
		if got := uint64(len(broadcasts)); got != i+1 {
			t.Fatalf("batch %d: Broadcasts len = %d, want %d", i+1, got, i+1)
		}
		req := broadcasts[len(broadcasts)-1]
		if req.NewState.BlockNumber != i+1 {
			t.Errorf("batch %d: NewState.BlockNumber = %d, want %d", i+1, req.NewState.BlockNumber, i+1)
		}
		if req.Proof == nil {
			t.Fatalf("batch %d: advance proof must not be nil", i+1)
		}
		if got := req.Proof.Mode(); got != covenant.ProofModeFRI {
			t.Errorf("batch %d: advance proof mode = %s, want basefold", i+1, got)
		}
		if len(req.Proof.ProofBlob()) == 0 {
			t.Errorf("batch %d: proof blob must be non-empty", i+1)
		}
		if len(req.Proof.PublicValues()) == 0 {
			t.Errorf("batch %d: public values must be non-empty", i+1)
		}
		if len(req.Proof.BatchData()) == 0 {
			t.Errorf("batch %d: batch data must be non-empty", i+1)
		}
	}

	if got := cs.node.ConfirmedTip(); got != 0 {
		t.Errorf("ConfirmedTip before any confirmations = %d, want 0", got)
	}
	if got := cs.node.FinalizedTip(); got != 0 {
		t.Errorf("FinalizedTip before any confirmations = %d, want 0", got)
	}

	cs.fake.AdvanceConfirmations(1)
	waitFor(t, time.Second, "ConfirmedTip=5", func() bool {
		return cs.node.ConfirmedTip() >= numBatches
	})
	if got := cs.node.ConfirmedTip(); got != numBatches {
		t.Errorf("ConfirmedTip after 1 conf = %d, want %d", got, numBatches)
	}
	if got := cs.node.FinalizedTip(); got != 0 {
		t.Errorf("FinalizedTip after only 1 conf = %d, want 0", got)
	}

	cs.fake.AdvanceConfirmations(5)
	waitFor(t, time.Second, "FinalizedTip=5", func() bool {
		return cs.node.FinalizedTip() >= numBatches
	})
	if got := cs.node.FinalizedTip(); got != numBatches {
		t.Errorf("FinalizedTip after 6 confs = %d, want %d", got, numBatches)
	}

	waitFor(t, time.Second, "watcher drains outstanding", func() bool {
		return cs.node.ConfirmationWatcherRef().Outstanding() == 0
	})
}

// TestContinuousProvingLoop_BroadcastRejection verifies that a rejected
// broadcast leaves provenTip advanced (block committed locally) but never
// advances confirmedTip or finalizedTip, and that no broadcast is tracked.
func TestContinuousProvingLoop_BroadcastRejection(t *testing.T) {
	cs := newContinuousSetup(t, 3, prover.ProofModeFRI)
	defer cs.node.Stop()

	cs.fake.RejectBroadcast = true
	cs.node.StartConfirmationWatcher(cs.fake, 50*time.Millisecond)

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000bb")
	tx := cs.signTransfer(t, 0, recipient, uint256.NewInt(1000))

	_, err := cs.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	if got := cs.node.ExecutionTip(); got != 1 {
		t.Errorf("ExecutionTip = %d, want 1", got)
	}
	if got := cs.node.ProvenTip(); got != 1 {
		t.Errorf("ProvenTip = %d, want 1 (block locally committed)", got)
	}
	if got := cs.node.ConfirmedTip(); got != 0 {
		t.Errorf("ConfirmedTip = %d, want 0 (no broadcast succeeded)", got)
	}
	if got := cs.node.FinalizedTip(); got != 0 {
		t.Errorf("FinalizedTip = %d, want 0 (no broadcast succeeded)", got)
	}
	if got := len(cs.fake.Broadcasts()); got != 0 {
		t.Errorf("fake.Broadcasts len = %d, want 0 (all rejected)", got)
	}
	if got := cs.fake.Outstanding(); got != 0 {
		t.Errorf("fake.Outstanding = %d, want 0", got)
	}
	if got := cs.node.ConfirmationWatcherRef().Outstanding(); got != 0 {
		t.Errorf("watcher.Outstanding = %d, want 0", got)
	}
}

// TestContinuousProvingLoop_Basefold drives the overlay with the Basefold
// proof mode and asserts that every broadcast carries a FRIProof whose
// ContractCallArgs produces the 5-arg slice expected by
// FRIRollupContract.AdvanceState (newStateRoot, newBlockNumber,
// publicValues, batchData, proofBlob).
func TestContinuousProvingLoop_Basefold(t *testing.T) {
	cs := newContinuousSetup(t, 5, prover.ProofModeFRI)
	defer cs.node.Stop()

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000cc")
	transfer := uint256.NewInt(1000)

	const numBatches = 3
	for i := uint64(0); i < numBatches; i++ {
		tx := cs.signTransfer(t, i, recipient, transfer)
		if _, err := cs.node.ProcessBatch([]*types.Transaction{tx}); err != nil {
			t.Fatalf("ProcessBatch %d: %v", i+1, err)
		}
	}

	broadcasts := cs.fake.Broadcasts()
	if got := len(broadcasts); got != numBatches {
		t.Fatalf("Broadcasts len = %d, want %d", got, numBatches)
	}

	for i, req := range broadcasts {
		if req.Proof == nil {
			t.Fatalf("batch %d: advance proof must not be nil", i+1)
		}
		if got := req.Proof.Mode(); got != covenant.ProofModeFRI {
			t.Errorf("batch %d: mode = %s, want basefold", i+1, got)
		}
		if _, ok := req.Proof.(*covenant.FRIProof); !ok {
			t.Errorf("batch %d: proof concrete type = %T, want *covenant.FRIProof", i+1, req.Proof)
		}
		args, err := req.Proof.ContractCallArgs(req)
		if err != nil {
			t.Fatalf("batch %d: ContractCallArgs: %v", i+1, err)
		}
		if got := len(args); got != 5 {
			t.Errorf("batch %d: ContractCallArgs len = %d, want 5", i+1, got)
		}
	}
}

// TestContinuousProvingLoop_Groth16Generic drives the overlay with the
// Groth16 generic proof mode and asserts that every broadcast carries a
// Groth16GenericProof whose ContractCallArgs produces the 16-arg slice
// expected by Groth16RollupContract.AdvanceState.
func TestContinuousProvingLoop_Groth16Generic(t *testing.T) {
	cs := newContinuousSetup(t, 7, prover.ProofModeGroth16Generic)
	defer cs.node.Stop()

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000dd")
	transfer := uint256.NewInt(1000)

	const numBatches = 3
	for i := uint64(0); i < numBatches; i++ {
		tx := cs.signTransfer(t, i, recipient, transfer)
		if _, err := cs.node.ProcessBatch([]*types.Transaction{tx}); err != nil {
			t.Fatalf("ProcessBatch %d: %v", i+1, err)
		}
	}

	broadcasts := cs.fake.Broadcasts()
	if got := len(broadcasts); got != numBatches {
		t.Fatalf("Broadcasts len = %d, want %d", got, numBatches)
	}

	for i, req := range broadcasts {
		if req.Proof == nil {
			t.Fatalf("batch %d: advance proof must not be nil", i+1)
		}
		if got := req.Proof.Mode(); got != covenant.ProofModeGroth16Generic {
			t.Errorf("batch %d: mode = %s, want groth16-generic", i+1, got)
		}
		if _, ok := req.Proof.(*covenant.Groth16GenericProof); !ok {
			t.Errorf("batch %d: proof concrete type = %T, want *covenant.Groth16GenericProof", i+1, req.Proof)
		}
		args, err := req.Proof.ContractCallArgs(req)
		if err != nil {
			t.Fatalf("batch %d: ContractCallArgs: %v", i+1, err)
		}
		if got := len(args); got != 16 {
			t.Errorf("batch %d: ContractCallArgs len = %d, want 16", i+1, got)
		}
	}
}

// TestContinuousProvingLoop_Groth16Witness drives the overlay with the
// witness-assisted Groth16 proof mode (Mode 3). The mock prover builds a
// Groth16WitnessProof with a real BN254 witness loaded from the embedded
// Gate 0b SP1 fixture, the fake BroadcastClient records it, and the test
// asserts that ContractCallArgs produces the 5-arg slice expected by
// Groth16WARollupContract.AdvanceState (witness is side-channelled via
// CallOptions in the real client and is NOT in the positional args).
func TestContinuousProvingLoop_Groth16Witness(t *testing.T) {
	cs := newContinuousSetup(t, 9, prover.ProofModeGroth16Witness)
	defer cs.node.Stop()

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000ee")
	tx := cs.signTransfer(t, 0, recipient, uint256.NewInt(1000))
	if _, err := cs.node.ProcessBatch([]*types.Transaction{tx}); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	broadcasts := cs.fake.Broadcasts()
	if got := len(broadcasts); got != 1 {
		t.Fatalf("Broadcasts len = %d, want 1", got)
	}
	req := broadcasts[0]
	if req.Proof == nil {
		t.Fatal("advance proof must not be nil")
	}
	if got := req.Proof.Mode(); got != covenant.ProofModeGroth16Witness {
		t.Errorf("mode = %s, want groth16-witness", got)
	}
	waProof, ok := req.Proof.(*covenant.Groth16WitnessProof)
	if !ok {
		t.Fatalf("proof concrete type = %T, want *covenant.Groth16WitnessProof", req.Proof)
	}
	if waProof.Witness == nil {
		t.Error("Groth16WitnessProof.Witness must be non-nil after synthetic proof build")
	}

	args, err := req.Proof.ContractCallArgs(req)
	if err != nil {
		t.Fatalf("ContractCallArgs: %v", err)
	}
	if got := len(args); got != 5 {
		t.Errorf("Groth16WA ContractCallArgs len = %d, want 5", got)
	}
}
