//go:build integration

package integration

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/regtestharness"
	"github.com/icellan/bsvm/pkg/types"

	runar "github.com/icellan/runar/packages/runar-go"
	"runar-integration/helpers"
)

// TestContinuousProvingLoop_Basefold_Regtest is the production smoke test
// for the continuous proving loop end-to-end against a real BSV regtest
// node and a deployed Basefold rollup covenant.
//
// It:
//  1. Computes the deterministic genesis state root that the overlay will
//     initialise from (via regtestharness.ComputeGenesisStateRoot).
//  2. Deploys a BasefoldRollupContract whose initial stateRoot field equals
//     that root (so the first advance's preStateRoot check passes).
//  3. Builds an OverlayNode bound to the deployed contract via a real
//     RunarBroadcastClient configured for ProofModeBasefold.
//  4. Submits 3 transaction batches through the overlay pipeline,
//     verifying that each one lands on-chain and the contract's covenant
//     UTXO advances.
//  5. Mines 1 BSV block and asserts ConfirmedTip reaches numBatches.
//  6. Mines 5 more BSV blocks and asserts FinalizedTip reaches numBatches.
//
// The mock prover is used: it produces synthetic Basefold proof values
// and the contract-compatible public values blob. The overlay's
// synthetic_proofs.go layer rebuilds the public values in the layout the
// Basefold contract expects, so no real SP1 proving is required to drive
// the loop.
func TestContinuousProvingLoop_Basefold_Regtest(t *testing.T) {
	// 1. Compute the deterministic genesis state root the harness will
	//    produce inside Build. We need it BEFORE deploying the contract so
	//    the contract's initial stateRoot matches the overlay's pre-state.
	harnessCfg := regtestharness.Config{
		ChainID:      chainID,
		TxKeySeed:    1,
		CoinbaseSeed: 2,
	}
	genesisStateRoot, err := regtestharness.ComputeGenesisStateRoot(harnessCfg)
	if err != nil {
		t.Fatalf("ComputeGenesisStateRoot: %v", err)
	}
	genesisStateRootHex := hex.EncodeToString(genesisStateRoot[:])
	t.Logf("GENESIS: state root = %s", genesisStateRootHex)

	// 2. Compile and deploy the Basefold rollup contract with the overlay's
	//    genesis state root as its initial stateRoot field.
	contract, provider, signer, _ := deployBasefoldRollupWithStateRoot(t, genesisStateRootHex)
	deployUtxo := contract.GetCurrentUtxo()
	if deployUtxo == nil {
		t.Fatalf("contract.GetCurrentUtxo() == nil after deploy")
	}
	t.Logf("DEPLOY:  txid=%s vout=%d sats=%d", deployUtxo.Txid, deployUtxo.OutputIndex, deployUtxo.Satoshis)

	// Mine the deploy so subsequent advances see a confirmed parent.
	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine deploy: %v", err)
	}

	// 3. Build the overlay bundle. Build will re-derive the same genesis
	//    state root via the same TxKeySeed and seed the CovenantManager
	//    with the deployed contract's UTXO location.
	harnessCfg.Contract = contract
	harnessCfg.Provider = provider
	harnessCfg.Signer = signer
	bundle, err := regtestharness.Build(harnessCfg)
	if err != nil {
		t.Fatalf("regtestharness.Build: %v", err)
	}
	defer bundle.Node.Stop()

	// 4. Start the confirmation watcher.
	bundle.Node.StartConfirmationWatcher(bundle.Client, 500*time.Millisecond)

	// 5. Submit 3 transaction batches through the overlay's full pipeline.
	recipient := types.HexToAddress("0x00000000000000000000000000000000000000aa")
	transfer := uint256.NewInt(1000)
	const numBatches uint64 = 3

	for i := uint64(0); i < numBatches; i++ {
		tx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
			Nonce:    i,
			GasPrice: big.NewInt(1_000_000_000),
			Gas:      21000,
			To:       &recipient,
			Value:    transfer,
		})

		result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch %d: %v", i+1, err)
		}

		if got := bundle.Node.ExecutionTip(); got != i+1 {
			t.Errorf("batch %d: ExecutionTip = %d, want %d", i+1, got, i+1)
		}
		if got := bundle.Node.ProvenTip(); got != i+1 {
			t.Errorf("batch %d: ProvenTip = %d, want %d", i+1, got, i+1)
		}

		cu := contract.GetCurrentUtxo()
		if cu == nil {
			t.Fatalf("batch %d: contract.GetCurrentUtxo() == nil after advance", i+1)
		}

		txids := bundle.Client.TxIDs()
		if uint64(len(txids)) != i+1 {
			t.Fatalf("batch %d: RunarBroadcastClient tracked %d txids, want %d (last error: %v)",
				i+1, len(txids), i+1, bundle.Client.LastError())
		}

		t.Logf("BATCH %d: advance txid=%s covenant_utxo=%s:%d state=%s block=%d",
			i+1, txids[len(txids)-1].Hex(), cu.Txid, cu.OutputIndex,
			result.StateRoot.Hex(), result.Block.NumberU64())
	}

	// 6. Mine enough blocks to reach the finalized depth (>=6 confirmations
	//    per outstanding advance). We mine all 6 in one go to keep the test
	//    resilient against regtest reorgs and concurrent mining processes
	//    that can add chain tips while the test is running.
	if err := helpers.Mine(6); err != nil {
		t.Fatalf("mine +6: %v", err)
	}
	waitForRegtestCond(t, 120*time.Second, "ConfirmedTip>=N", func() bool {
		return bundle.Node.ConfirmedTip() >= numBatches
	})
	if got := bundle.Node.ConfirmedTip(); got < numBatches {
		t.Errorf("ConfirmedTip = %d, want >= %d", got, numBatches)
	}
	waitForRegtestCond(t, 120*time.Second, "FinalizedTip>=N", func() bool {
		return bundle.Node.FinalizedTip() >= numBatches
	})
	if got := bundle.Node.FinalizedTip(); got < numBatches {
		t.Errorf("FinalizedTip = %d, want >= %d", got, numBatches)
	}

	waitForRegtestCond(t, 30*time.Second, "watcher drains outstanding", func() bool {
		return bundle.Node.ConfirmationWatcherRef().Outstanding() == 0
	})

	t.Logf("")
	t.Logf("================================================================")
	t.Logf("END-TO-END CONTINUOUS PROVING LOOP — BASEFOLD ON REAL BSV REGTEST")
	t.Logf("================================================================")
	t.Logf("  Batches processed:   %d", numBatches)
	t.Logf("  BSV txs broadcast:   %d", len(bundle.Client.TxIDs()))
	t.Logf("  ExecutionTip:        %d", bundle.Node.ExecutionTip())
	t.Logf("  ProvenTip:           %d", bundle.Node.ProvenTip())
	t.Logf("  ConfirmedTip:        %d", bundle.Node.ConfirmedTip())
	t.Logf("  FinalizedTip:        %d", bundle.Node.FinalizedTip())
	t.Logf("================================================================")
}

// deployBasefoldRollupWithStateRoot compiles and deploys the Basefold rollup
// covenant with a caller-supplied initial stateRoot hex. This differs from
// deployBasefoldRollupLifecycle (in rollup_basefold_test.go, which is locked)
// only in that it lets the test supply the pre-state root so it can be
// aligned with an external overlay's genesis state root.
//
// Every other constructor argument mirrors deployBasefoldRollupLifecycle
// one-for-one: same merkle-root readonly, same single-key governance, same
// chain ID, same KoalaBear field check.
func deployBasefoldRollupWithStateRoot(t *testing.T, stateRootHex string) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet) {
	t.Helper()

	artifact, err := compileContract(basefoldRollupContractPath)
	if err != nil {
		t.Fatalf("compile Basefold contract: %v", err)
	}
	t.Logf("COMPILE: %s — locking script = %d bytes (%.1f KB)",
		artifact.ContractName, len(artifact.Script)/2, float64(len(artifact.Script)/2)/1024.0)

	wallet := helpers.NewWallet()
	_, _ = helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 5.0); err != nil {
		t.Fatalf("fund wallet: %v", err)
	}
	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	z33 := "000000000000000000000000000000000000000000000000000000000000000000"
	constructorArgs := []interface{}{
		// Mutable state
		stateRootHex,      // stateRoot (caller-supplied)
		int64(0),          // blockNumber
		int64(0),          // frozen
		// Readonly: shared
		fullMerkleRootHex, // sP1VerifyingKeyHash = depth-20 Merkle root
		chainID,           // chainId
		// Readonly: governance
		int64(1),           // governanceMode = 1 (single_key)
		int64(1),           // governanceThreshold = 1
		wallet.PubKeyHex(), // governanceKey
		z33,                // governanceKey2 (unused)
		z33,                // governanceKey3 (unused)
	}

	contract := runar.NewRunarContract(artifact, constructorArgs)

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100_000})
	if err != nil {
		t.Fatalf("deploy Basefold covenant: %v", err)
	}
	t.Logf("DEPLOY:  txid=%s", txid)

	return contract, provider, signer, wallet
}

// TestContinuousProvingLoop_Groth16WA_Regtest is the Mode 3 variant of
// TestContinuousProvingLoop_Basefold_Regtest. It drives the overlay's full
// produce → prove → broadcast loop against a deployed Groth16WA rollup
// covenant whose witness-assisted preamble was baked at compile time with
// the Gate 0b SP1 fixture vk.json. The mock prover's synthetic Mode 3
// proof path (pkg/overlay/synthetic_proofs.go) produces a Groth16WitnessProof
// carrying the cached Gate 0b BN254 witness, which the RunarBroadcastClient
// threads through runar.CallOptions.Groth16WAWitness on every advance.
func TestContinuousProvingLoop_Groth16WA_Regtest(t *testing.T) {
	harnessCfg := regtestharness.Config{
		ChainID:      chainID,
		TxKeySeed:    11,
		CoinbaseSeed: 12,
		ProofMode:    covenant.ProofModeGroth16Witness,
	}
	genesisStateRoot, err := regtestharness.ComputeGenesisStateRoot(harnessCfg)
	if err != nil {
		t.Fatalf("ComputeGenesisStateRoot: %v", err)
	}
	genesisStateRootHex := hex.EncodeToString(genesisStateRoot[:])
	t.Logf("GENESIS: state root = %s", genesisStateRootHex)

	contract, provider, signer, _ := deployGroth16WARollupWithStateRoot(t, genesisStateRootHex)
	deployUtxo := contract.GetCurrentUtxo()
	if deployUtxo == nil {
		t.Fatalf("contract.GetCurrentUtxo() == nil after deploy")
	}
	t.Logf("DEPLOY:  txid=%s vout=%d sats=%d", deployUtxo.Txid, deployUtxo.OutputIndex, deployUtxo.Satoshis)

	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine deploy: %v", err)
	}

	harnessCfg.Contract = contract
	harnessCfg.Provider = provider
	harnessCfg.Signer = signer
	bundle, err := regtestharness.Build(harnessCfg)
	if err != nil {
		t.Fatalf("regtestharness.Build: %v", err)
	}
	defer bundle.Node.Stop()

	bundle.Node.StartConfirmationWatcher(bundle.Client, 500*time.Millisecond)

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000bb")
	transfer := uint256.NewInt(1000)
	const numBatches uint64 = 3

	for i := uint64(0); i < numBatches; i++ {
		tx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
			Nonce:    i,
			GasPrice: big.NewInt(1_000_000_000),
			Gas:      21000,
			To:       &recipient,
			Value:    transfer,
		})

		result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch %d: %v", i+1, err)
		}

		if got := bundle.Node.ExecutionTip(); got != i+1 {
			t.Errorf("batch %d: ExecutionTip = %d, want %d", i+1, got, i+1)
		}
		if got := bundle.Node.ProvenTip(); got != i+1 {
			t.Errorf("batch %d: ProvenTip = %d, want %d", i+1, got, i+1)
		}

		cu := contract.GetCurrentUtxo()
		if cu == nil {
			t.Fatalf("batch %d: contract.GetCurrentUtxo() == nil after advance", i+1)
		}

		txids := bundle.Client.TxIDs()
		if uint64(len(txids)) != i+1 {
			t.Fatalf("batch %d: RunarBroadcastClient tracked %d txids, want %d (last error: %v)",
				i+1, len(txids), i+1, bundle.Client.LastError())
		}

		t.Logf("BATCH %d: advance txid=%s covenant_utxo=%s:%d state=%s block=%d",
			i+1, txids[len(txids)-1].Hex(), cu.Txid, cu.OutputIndex,
			result.StateRoot.Hex(), result.Block.NumberU64())
	}

	// Mine enough blocks to reach the finalized depth (>=6 confirmations
	// per outstanding advance). One mining call to keep the test resilient
	// against regtest reorgs and concurrent mining processes.
	if err := helpers.Mine(6); err != nil {
		t.Fatalf("mine +6: %v", err)
	}
	waitForRegtestCond(t, 120*time.Second, "ConfirmedTip>=N", func() bool {
		return bundle.Node.ConfirmedTip() >= numBatches
	})
	if got := bundle.Node.ConfirmedTip(); got < numBatches {
		t.Errorf("ConfirmedTip = %d, want >= %d", got, numBatches)
	}
	waitForRegtestCond(t, 120*time.Second, "FinalizedTip>=N", func() bool {
		return bundle.Node.FinalizedTip() >= numBatches
	})
	if got := bundle.Node.FinalizedTip(); got < numBatches {
		t.Errorf("FinalizedTip = %d, want >= %d", got, numBatches)
	}

	waitForRegtestCond(t, 30*time.Second, "watcher drains outstanding", func() bool {
		return bundle.Node.ConfirmationWatcherRef().Outstanding() == 0
	})

	t.Logf("")
	t.Logf("================================================================")
	t.Logf("END-TO-END CONTINUOUS PROVING LOOP — GROTH16WA ON REAL BSV REGTEST")
	t.Logf("================================================================")
	t.Logf("  Batches processed:   %d", numBatches)
	t.Logf("  BSV txs broadcast:   %d", len(bundle.Client.TxIDs()))
	t.Logf("  ExecutionTip:        %d", bundle.Node.ExecutionTip())
	t.Logf("  ProvenTip:           %d", bundle.Node.ProvenTip())
	t.Logf("  ConfirmedTip:        %d", bundle.Node.ConfirmedTip())
	t.Logf("  FinalizedTip:        %d", bundle.Node.FinalizedTip())
	t.Logf("================================================================")
}

// deployGroth16WARollupWithStateRoot compiles and deploys the Mode 3
// (witness-assisted Groth16) rollup covenant with a caller-supplied initial
// stateRoot hex. Mirrors deployBasefoldRollupWithStateRoot one-for-one
// except for the compile path (uses compileContractGroth16WA with the
// Gate 0b vk.json baked into the preamble).
func deployGroth16WARollupWithStateRoot(t *testing.T, stateRootHex string) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet) {
	t.Helper()

	vkPath := gate0SP1FixturePath("sp1_groth16_vk.json")
	artifact, err := compileContractGroth16WA(groth16WARollupContractPath, vkPath)
	if err != nil {
		t.Fatalf("compile Groth16WA contract: %v", err)
	}
	t.Logf("COMPILE: %s — locking script = %d bytes (%.1f KB)",
		artifact.ContractName, len(artifact.Script)/2, float64(len(artifact.Script)/2)/1024.0)

	wallet := helpers.NewWallet()
	_, _ = helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 5.0); err != nil {
		t.Fatalf("fund wallet: %v", err)
	}
	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	z33 := "000000000000000000000000000000000000000000000000000000000000000000"
	constructorArgs := []interface{}{
		stateRootHex,      // stateRoot (caller-supplied)
		int64(0),          // blockNumber
		int64(0),          // frozen
		fullMerkleRootHex, // sP1VerifyingKeyHash — bsv-evm tracking hash
		chainID,           // chainId
		int64(1),          // governanceMode = 1 (single_key)
		int64(1),          // governanceThreshold = 1
		wallet.PubKeyHex(), // governanceKey
		z33,                // governanceKey2 (unused)
		z33,                // governanceKey3 (unused)
	}

	contract := runar.NewRunarContract(artifact, constructorArgs)

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 100_000})
	if err != nil {
		t.Fatalf("deploy Groth16WA covenant: %v", err)
	}
	t.Logf("DEPLOY:  txid=%s", txid)

	return contract, provider, signer, wallet
}

// TestContinuousProvingLoop_Groth16Generic_Regtest is the Mode 2 variant of
// TestContinuousProvingLoop_Basefold_Regtest. It drives the overlay's full
// produce → prove → broadcast loop against a deployed Mode 2 Groth16 rollup
// covenant (generic BN254 pairing, no witness-assisted preamble) whose VK is
// baked at compile time with the Gate 0b SP1 fixture. The mock prover's
// synthetic Mode 2 proof path (pkg/overlay/synthetic_proofs.go) produces a
// Groth16GenericProof carrying the Gate 0b fixture's BN254 proof points and
// adjusted public inputs, so the on-chain Bn254MultiPairing4 check passes on
// every advance.
//
// NOTE: Mode 2 advances are significantly slower than Mode 1 or Mode 3
// because the 5.6 MB locking script inlines the full multi-pairing verifier
// and every spend embeds all 19 VK constants plus the 16 per-advance args.
// Per-advance TX size is ~18.5 MB and per-advance time is ~5 seconds, so
// this test uses only 2 batches (vs 3 for Modes 1 / 3) to keep total
// wall-clock under ~25 seconds.
func TestContinuousProvingLoop_Groth16Generic_Regtest(t *testing.T) {
	harnessCfg := regtestharness.Config{
		ChainID:      chainID,
		TxKeySeed:    13,
		CoinbaseSeed: 14,
		ProofMode:    covenant.ProofModeGroth16Generic,
	}
	genesisStateRoot, err := regtestharness.ComputeGenesisStateRoot(harnessCfg)
	if err != nil {
		t.Fatalf("ComputeGenesisStateRoot: %v", err)
	}
	genesisStateRootHex := hex.EncodeToString(genesisStateRoot[:])
	t.Logf("GENESIS: state root = %s", genesisStateRootHex)

	contract, provider, signer, _ := deployGroth16RollupWithStateRoot(t, genesisStateRootHex)
	deployUtxo := contract.GetCurrentUtxo()
	if deployUtxo == nil {
		t.Fatalf("contract.GetCurrentUtxo() == nil after deploy")
	}
	t.Logf("DEPLOY:  txid=%s vout=%d sats=%d", deployUtxo.Txid, deployUtxo.OutputIndex, deployUtxo.Satoshis)

	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine deploy: %v", err)
	}

	harnessCfg.Contract = contract
	harnessCfg.Provider = provider
	harnessCfg.Signer = signer
	bundle, err := regtestharness.Build(harnessCfg)
	if err != nil {
		t.Fatalf("regtestharness.Build: %v", err)
	}
	defer bundle.Node.Stop()

	bundle.Node.StartConfirmationWatcher(bundle.Client, 500*time.Millisecond)

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000cc")
	transfer := uint256.NewInt(1000)
	const numBatches uint64 = 2

	for i := uint64(0); i < numBatches; i++ {
		tx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
			Nonce:    i,
			GasPrice: big.NewInt(1_000_000_000),
			Gas:      21000,
			To:       &recipient,
			Value:    transfer,
		})

		advanceStart := time.Now()
		result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
		advanceDur := time.Since(advanceStart)
		if err != nil {
			t.Fatalf("ProcessBatch %d: %v", i+1, err)
		}

		if got := bundle.Node.ExecutionTip(); got != i+1 {
			t.Errorf("batch %d: ExecutionTip = %d, want %d", i+1, got, i+1)
		}
		if got := bundle.Node.ProvenTip(); got != i+1 {
			t.Errorf("batch %d: ProvenTip = %d, want %d", i+1, got, i+1)
		}

		cu := contract.GetCurrentUtxo()
		if cu == nil {
			t.Fatalf("batch %d: contract.GetCurrentUtxo() == nil after advance", i+1)
		}

		txids := bundle.Client.TxIDs()
		if uint64(len(txids)) != i+1 {
			t.Fatalf("batch %d: RunarBroadcastClient tracked %d txids, want %d (last error: %v)",
				i+1, len(txids), i+1, bundle.Client.LastError())
		}

		t.Logf("BATCH %d: advance txid=%s covenant_utxo=%s:%d state=%s block=%d advance_time=%s",
			i+1, txids[len(txids)-1].Hex(), cu.Txid, cu.OutputIndex,
			result.StateRoot.Hex(), result.Block.NumberU64(), advanceDur)
	}

	// Mine enough blocks to reach the finalized depth (>=6 confirmations
	// per outstanding advance). One mining call to keep the test resilient
	// against regtest reorgs and concurrent mining processes.
	if err := helpers.Mine(6); err != nil {
		t.Fatalf("mine +6: %v", err)
	}
	waitForRegtestCond(t, 120*time.Second, "ConfirmedTip>=N", func() bool {
		return bundle.Node.ConfirmedTip() >= numBatches
	})
	if got := bundle.Node.ConfirmedTip(); got < numBatches {
		t.Errorf("ConfirmedTip = %d, want >= %d", got, numBatches)
	}
	waitForRegtestCond(t, 120*time.Second, "FinalizedTip>=N", func() bool {
		return bundle.Node.FinalizedTip() >= numBatches
	})
	if got := bundle.Node.FinalizedTip(); got < numBatches {
		t.Errorf("FinalizedTip = %d, want >= %d", got, numBatches)
	}

	waitForRegtestCond(t, 30*time.Second, "watcher drains outstanding", func() bool {
		return bundle.Node.ConfirmationWatcherRef().Outstanding() == 0
	})

	t.Logf("")
	t.Logf("================================================================")
	t.Logf("END-TO-END CONTINUOUS PROVING LOOP — GROTH16GENERIC ON REAL BSV REGTEST")
	t.Logf("================================================================")
	t.Logf("  Batches processed:   %d", numBatches)
	t.Logf("  BSV txs broadcast:   %d", len(bundle.Client.TxIDs()))
	t.Logf("  ExecutionTip:        %d", bundle.Node.ExecutionTip())
	t.Logf("  ProvenTip:           %d", bundle.Node.ProvenTip())
	t.Logf("  ConfirmedTip:        %d", bundle.Node.ConfirmedTip())
	t.Logf("  FinalizedTip:        %d", bundle.Node.FinalizedTip())
	t.Logf("================================================================")
}

// deployGroth16RollupWithStateRoot compiles and deploys the Mode 2 (generic
// Groth16) rollup covenant with a caller-supplied initial stateRoot hex.
// Mirrors deployGroth16WARollupWithStateRoot one-for-one except that it
// targets the generic Groth16 contract path (which bakes all 19 VK
// constants into the 29-arg constructor) and uses the Gate 0b SP1 fixture
// VK adjusted by covenant.ApplyZeroInputWorkaround.
//
// The VK conversion from SP1's fixture format (β/γ/δ pre-negated) to Mode
// 2's on-chain convention (β pre-negated, γ/δ positive) and the zero-input
// workaround adjustment (IC0 replaced to compensate for zero public inputs)
// are both applied by loadGate0Groth16Generic, which is defined in
// rollup_groth16_test.go in the same package.
func deployGroth16RollupWithStateRoot(t *testing.T, stateRootHex string) (*runar.RunarContract, runar.Provider, runar.Signer, *helpers.Wallet) {
	t.Helper()

	vk, _, _ := loadGate0Groth16Generic(t)

	artifact, err := compileContract(groth16RollupContractPath)
	if err != nil {
		t.Fatalf("compile Groth16 contract: %v", err)
	}
	t.Logf("COMPILE: %s — locking script = %d bytes (%.2f MB)",
		artifact.ContractName, len(artifact.Script)/2, float64(len(artifact.Script)/2)/(1024.0*1024.0))

	wallet := helpers.NewWallet()
	_, _ = helpers.RPCCall("importaddress", wallet.Address, "", false)
	if _, err := helpers.FundWallet(wallet, 10.0); err != nil {
		t.Fatalf("fund wallet: %v", err)
	}
	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	z33 := "000000000000000000000000000000000000000000000000000000000000000000"

	// Groth16RollupContract declares (in source order):
	//   3 state:       stateRoot, blockNumber, frozen
	//   2 shared:      sP1VerifyingKeyHash, chainId
	//   5 governance:  governanceMode, threshold, key, key2, key3
	//  19 VK:          alphaG1, betaG2X0..Y1 (4), gammaG2X0..Y1 (4),
	//                  deltaG2X0..Y1 (4), iC0..iC5 (6)
	// = 29 constructor args in declaration order. See
	// deployGroth16Rollup in rollup_groth16_test.go for the full comment.
	constructorArgs := []interface{}{
		// Mutable state
		stateRootHex, // stateRoot (caller-supplied)
		int64(0),     // blockNumber
		int64(0),     // frozen
		// Readonly: shared
		fullMerkleRootHex, // sP1VerifyingKeyHash
		chainID,           // chainId
		// Readonly: governance
		int64(1),           // governanceMode = single_key
		int64(1),           // governanceThreshold = 1
		wallet.PubKeyHex(), // governanceKey
		z33,                // governanceKey2
		z33,                // governanceKey3
		// Readonly: Groth16 VK (Gate 0b SP1 fixture, Mode 2 convention,
		// IC0-adjusted for zero-input workaround).
		hex.EncodeToString(vk.AlphaG1),       // alphaG1 (runar.Point → hex)
		new(big.Int).SetBytes(vk.BetaG2[0]),  // betaG2X0 (runar.Bigint → *big.Int)
		new(big.Int).SetBytes(vk.BetaG2[1]),  // betaG2X1
		new(big.Int).SetBytes(vk.BetaG2[2]),  // betaG2Y0
		new(big.Int).SetBytes(vk.BetaG2[3]),  // betaG2Y1
		new(big.Int).SetBytes(vk.GammaG2[0]), // gammaG2X0
		new(big.Int).SetBytes(vk.GammaG2[1]), // gammaG2X1
		new(big.Int).SetBytes(vk.GammaG2[2]), // gammaG2Y0
		new(big.Int).SetBytes(vk.GammaG2[3]), // gammaG2Y1
		new(big.Int).SetBytes(vk.DeltaG2[0]), // deltaG2X0
		new(big.Int).SetBytes(vk.DeltaG2[1]), // deltaG2X1
		new(big.Int).SetBytes(vk.DeltaG2[2]), // deltaG2Y0
		new(big.Int).SetBytes(vk.DeltaG2[3]), // deltaG2Y1
		hex.EncodeToString(vk.IC0),           // iC0 (runar.Point; adjusted)
		hex.EncodeToString(vk.IC1),           // iC1
		hex.EncodeToString(vk.IC2),           // iC2
		hex.EncodeToString(vk.IC3),           // iC3
		hex.EncodeToString(vk.IC4),           // iC4
		hex.EncodeToString(vk.IC5),           // iC5
	}

	contract := runar.NewRunarContract(artifact, constructorArgs)

	txid, _, err := contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 200_000})
	if err != nil {
		t.Fatalf("deploy Groth16 covenant: %v", err)
	}
	t.Logf("DEPLOY:  txid=%s", txid)

	return contract, provider, signer, wallet
}

// waitForRegtestCond polls cond every 50ms until it returns true or the
// timeout elapses. On timeout it calls t.Fatalf with the supplied
// description.
func waitForRegtestCond(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", desc)
	}
}
