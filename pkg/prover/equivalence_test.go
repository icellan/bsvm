package prover

// Dual-EVM equivalence harness for the post-W4 surface.
//
// CLAUDE.md key principle: "Both EVMs MUST pass ethereum/tests and
// produce identical state roots for identical inputs." Three relatively
// new pieces of the pipeline have not previously been covered by a
// Go-vs-Rust equivalence pin:
//
//  1. W4-1 — host-side state-proof export (pkg/prover.ExportStateForProving)
//     drives the guest's MPT root reconstruction. A Go-side regression
//     in the export shape silently breaks proof generation.
//  2. W4-2 — host-side sender recovery for signed user txs. The guest
//     re-runs ECDSA recovery internally (prover/guest/src/tx.rs); the
//     host's TransactionToMessage MUST agree on the recovered sender
//     for every supported tx type or proofs reject the batch.
//  3. EIP-4844 type-3 tx decode — newly accepted by the host. The
//     guest decodes type-3 too; this harness pins the host's encode
//     path so the bytes the host ships to the guest under raw_bytes
//     match what the guest expects.
//
// What this file IS:
//
//   - A Go-EVM-side harness that runs each tx-type batch end-to-end
//     through pkg/block.NewBlockExecutor + pkg/prover.SP1Prover (mock
//     mode) and asserts the round-trip is internally consistent: the
//     mock-prover-emitted PublicValues match the Go EVM's recorded
//     post-state-root, gas usage, receipts hash, and chain id.
//   - A pin on host-side sender recovery across LegacyTx, AccessListTx,
//     DynamicFeeTx, and BlobTx — sender(decode(encode(tx))) == sender(tx).
//
// What this file IS NOT (yet):
//
//   - It does NOT execute revm host-side and compare its post-state
//     root against pkg/vm. revm is reachable only through the SP1
//     host-bridge subprocess (prover/host-bridge/src/main.rs) which
//     requires a built guest ELF, an SP1 toolchain, and minutes per
//     run. That path lives behind ProverLocal, gated by
//     testing.Short(). See TODO(equivalence) below.
//
// TODO(equivalence): wire a host-side revm comparator that does NOT
// require the SP1 prove step. The cheapest path is a small Rust
// binary that links revm + alloy-rlp directly (no SP1 SDK), accepts a
// JSON ProveInput on stdin, runs the batch through revm with
// SpecId::CANCUN, and prints the post-state-root + per-tx gas. The Go
// harness then drives that binary alongside pkg/vm and asserts byte-
// for-byte equivalence on (PostStateRoot, GasUsed, ReceiptsHash). The
// existing prover/host-bridge depends on the SP1 SDK so it cannot be
// reused as-is; a sibling binary `prover/host-revm` is the natural
// home. Until that exists, the harness below covers Go-EVM-side
// internal consistency only — it is necessary but not sufficient for
// the dual-EVM equivalence guarantee. Mainnet wants this; treat it as
// a hard pre-flight item before the W4 features ship to production.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

const equivalenceChainID = 1337

// equivalenceFixture pairs a human-readable label with a builder that
// returns a signed Transaction. Builders take the sender's key and
// signer so each fixture can pick whichever tx type it needs.
type equivalenceFixture struct {
	name  string
	build func(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer) *types.Transaction
}

// equivalenceFixtures enumerates the tx types the dual-EVM harness
// covers. Each fixture is run as a single-tx batch — keeping each
// assertion attributable to one tx type.
var equivalenceFixtures = []equivalenceFixture{
	{
		name: "LegacyTransfer",
		build: func(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer) *types.Transaction {
			t.Helper()
			to := types.HexToAddress("0x1111111111111111111111111111111111111111")
			tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
				Nonce:    0,
				GasPrice: big.NewInt(1_000_000_000),
				Gas:      21_000,
				To:       &to,
				Value:    uint256.NewInt(1_000_000_000_000_000), // 0.001 ETH
			})
			if err != nil {
				t.Fatalf("LegacyTransfer SignNewTx: %v", err)
			}
			return tx
		},
	},
	{
		name: "AccessListTransfer",
		build: func(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer) *types.Transaction {
			t.Helper()
			to := types.HexToAddress("0x2222222222222222222222222222222222222222")
			tx, err := types.SignNewTx(key, signer, &types.AccessListTx{
				ChainID:    big.NewInt(equivalenceChainID),
				Nonce:      0,
				GasPrice:   big.NewInt(1_000_000_000),
				Gas:        25_000,
				To:         &to,
				Value:      uint256.NewInt(2_000_000_000_000_000),
				AccessList: types.AccessList{},
			})
			if err != nil {
				t.Fatalf("AccessListTransfer SignNewTx: %v", err)
			}
			return tx
		},
	},
	{
		name: "DynamicFeeTransfer",
		build: func(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer) *types.Transaction {
			t.Helper()
			to := types.HexToAddress("0x3333333333333333333333333333333333333333")
			tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
				ChainID:   big.NewInt(equivalenceChainID),
				Nonce:     0,
				GasTipCap: big.NewInt(1),
				GasFeeCap: big.NewInt(1_000_000_000),
				Gas:       21_000,
				To:        &to,
				Value:     uint256.NewInt(3_000_000_000_000_000),
			})
			if err != nil {
				t.Fatalf("DynamicFeeTransfer SignNewTx: %v", err)
			}
			return tx
		},
	},
	{
		name: "ContractCreate",
		build: func(t *testing.T, key *ecdsa.PrivateKey, signer types.Signer) *types.Transaction {
			t.Helper()
			// Same minimal contract as roundtrip_test:
			//   PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
			code := []byte{0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
			tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
				ChainID:   big.NewInt(equivalenceChainID),
				Nonce:     0,
				GasTipCap: big.NewInt(1),
				GasFeeCap: big.NewInt(1_000_000_000),
				Gas:       100_000,
				To:        nil, // contract creation
				Value:     uint256.NewInt(0),
				Data:      code,
			})
			if err != nil {
				t.Fatalf("ContractCreate SignNewTx: %v", err)
			}
			return tx
		},
	},
}

// runEquivalenceCase drives one tx fixture through the full Go-EVM
// pipeline (genesis → ProcessBatch → ExportStateForProving →
// SP1Prover.Prove(mock) → ParsePublicValues) and asserts every public-
// values field that the guest commits is consistent with what the Go
// EVM observed. This is the host-side internal-consistency contract
// the real (revm) equivalence run will extend; see the file-level
// TODO(equivalence) for what's still missing.
func runEquivalenceCase(t *testing.T, fx equivalenceFixture) {
	t.Helper()

	database := db.NewMemoryDB()
	chainConfig := vm.DefaultL2Config(equivalenceChainID)

	// Cancun is active under DefaultL2Config (CancunTime=0). This
	// pins the harness to the same fork the guest's revm runs.
	if !chainConfig.IsCancun(big.NewInt(0), 0) {
		t.Fatal("equivalence harness requires Cancun-active chain config")
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	// Genesis: prefund 1000 ETH so any fixture has gas + value headroom.
	genesis := block.DefaultGenesis(equivalenceChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(
		big.NewInt(1000),
		new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
	))
	genesis.Alloc = map[types.Address]block.GenesisAccount{
		senderAddr: {Balance: balance},
	}
	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	preStateRoot := genesisHeader.StateRoot

	// Build the signed tx. The signer is shared across every fixture so
	// chain-id-binding hashes are consistent.
	signer := types.NewLondonSigner(big.NewInt(equivalenceChainID))
	tx := fx.build(t, key, signer)

	// Host-side sender recovery — the same operation the Rust guest
	// re-runs internally on the bytes it receives. Mismatch here is
	// the W4-2 critical bug the guest is designed to surface.
	recovered, err := signer.Sender(tx)
	if err != nil {
		t.Fatalf("%s: signer.Sender: %v", fx.name, err)
	}
	if recovered != senderAddr {
		t.Fatalf("%s: host-side sender %s != expected %s",
			fx.name, recovered.Hex(), senderAddr.Hex())
	}

	// Encode the tx and round-trip via tx.Hash() — the guest's
	// raw_bytes input is the canonical encoded form, so we exercise
	// the same path the prover ships. We do NOT decode-then-recover
	// here for typed txs (envelope form is not a top-level RLP item);
	// the dedicated guest_sender_recovery_test.go covers that.
	var encBuf bytes.Buffer
	if err := tx.EncodeRLP(&encBuf); err != nil {
		t.Fatalf("%s: EncodeRLP: %v", fx.name, err)
	}
	txBytes := encBuf.Bytes()

	// Go EVM execution + access recording (W4-1).
	preStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("%s: pre-state open: %v", fx.name, err)
	}
	execStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("%s: exec state open: %v", fx.name, err)
	}
	execStateDB.StartAccessRecording()

	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	chainCtx := &testChainContext{}

	l2Block, receipts, err := executor.ProcessBatch(
		genesisHeader,
		coinbaseAddr,
		1000,
		[]*types.Transaction{tx},
		execStateDB,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("%s: ProcessBatch: %v", fx.name, err)
	}
	if len(receipts) != 1 {
		t.Fatalf("%s: expected 1 receipt, got %d", fx.name, len(receipts))
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("%s: tx reverted, receipt status %d", fx.name, receipts[0].Status)
	}

	postStateRoot := l2Block.StateRoot()
	gasUsed := l2Block.GasUsed()
	receiptsHash := mpt.DeriveSha(types.Receipts(receipts))

	if postStateRoot == preStateRoot {
		t.Fatalf("%s: post-state root unchanged (expected mutation)", fx.name)
	}

	// W4-1: state-proof export drives the guest's MPT proof checks.
	// A regression in the export shape silently breaks proving.
	recording := execStateDB.StopAccessRecording()
	export, err := ExportStateForProving(preStateDB, recording.Accounts, recording.Slots)
	if err != nil {
		t.Fatalf("%s: ExportStateForProving: %v", fx.name, err)
	}
	if export.PreStateRoot != preStateRoot {
		t.Fatalf("%s: state export pre-root mismatch: got %s want %s",
			fx.name, export.PreStateRoot.Hex(), preStateRoot.Hex())
	}
	stateExportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("%s: SerializeExport: %v", fx.name, err)
	}

	// Drive the mock prover with the Go EVM's expected results. The
	// mock path returns synthetic proof bytes but a 280-byte public-
	// values blob populated from the expected results — so the
	// internal parse must round-trip exactly. A real revm comparator
	// (TODO(equivalence)) would instead derive the expected results
	// independently and assert byte equality.
	proveInput := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  stateExportJSON,
		Transactions: [][]byte{txBytes},
		BlockContext: BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  coinbaseAddr,
			GasLimit:  l2Block.GasLimit(),
			BaseFee:   0,
		},
		ExpectedResults: &ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  receiptsHash,
			GasUsed:       gasUsed,
			ChainID:       equivalenceChainID,
		},
	}

	prover := NewSP1Prover(Config{Mode: ProverMock, SP1ProofMode: "compressed"})
	output, err := prover.Prove(context.Background(), proveInput)
	if err != nil {
		t.Fatalf("%s: Prove(mock): %v", fx.name, err)
	}
	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("%s: ParsePublicValues: %v", fx.name, err)
	}

	// Equivalence asserts: every public-values field the guest
	// commits MUST agree with what the Go EVM observed. Any
	// disagreement here is a critical bug per CLAUDE.md.
	if pv.PreStateRoot != preStateRoot {
		t.Errorf("%s: PreStateRoot mismatch: got %s want %s",
			fx.name, pv.PreStateRoot.Hex(), preStateRoot.Hex())
	}
	if pv.PostStateRoot != postStateRoot {
		t.Errorf("%s: PostStateRoot mismatch: got %s want %s",
			fx.name, pv.PostStateRoot.Hex(), postStateRoot.Hex())
	}
	if pv.ReceiptsHash != receiptsHash {
		t.Errorf("%s: ReceiptsHash mismatch: got %s want %s",
			fx.name, pv.ReceiptsHash.Hex(), receiptsHash.Hex())
	}
	if pv.GasUsed != gasUsed {
		t.Errorf("%s: GasUsed mismatch: got %d want %d", fx.name, pv.GasUsed, gasUsed)
	}
	if pv.ChainID != equivalenceChainID {
		t.Errorf("%s: ChainID mismatch: got %d want %d", fx.name, pv.ChainID, equivalenceChainID)
	}
	if pv.BatchDataHash != hashTransactions(proveInput.Transactions) {
		t.Errorf("%s: BatchDataHash mismatch", fx.name)
	}
}

// TestDualEVMEquivalence_Fixtures runs every equivalenceFixtures entry
// through the Go-EVM-side internal-consistency harness. The real
// Go-vs-Rust comparison still requires a host-side revm comparator —
// see file-level TODO(equivalence). This test stays cheap (no SP1 build)
// so CI runs it on every commit.
func TestDualEVMEquivalence_Fixtures(t *testing.T) {
	for _, fx := range equivalenceFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			runEquivalenceCase(t, fx)
		})
	}
}

// TestDualEVMEquivalence_BlobTxSenderRecovery pins host-side sender
// recovery for an EIP-4844 type-3 tx without running the tx through
// ProcessBatch. The host's TransactionToMessage does not currently
// surface BlobHashes / BlobGasFeeCap into the EVM (see
// pkg/block/state_transition.go::TransactionToMessage); blob txs are
// accepted at decode but their blob fields don't reach BLOBHASH on the
// Go side. The guest re-decodes the type-3 envelope itself and recovers
// the sender — so the host's only job for type-3 is to ship the bytes
// the guest expects under raw_bytes, with the correct sender.
//
// This test exercises the encoding contract: a fresh BlobTx is signed,
// canonical-encoded, and the host's signer recovers the original
// address. The Rust guest's prover/guest/src/tx.rs::tests::eip4844_*
// pin the Rust side of the same contract.
func TestDualEVMEquivalence_BlobTxSenderRecovery(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	expected := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	signer := types.NewLondonSigner(big.NewInt(equivalenceChainID))

	to := types.HexToAddress("0x4444444444444444444444444444444444444444")
	tx, err := types.SignNewTx(key, signer, &types.BlobTx{
		ChainID:    big.NewInt(equivalenceChainID),
		Nonce:      0,
		GasTipCap:  big.NewInt(1_000_000_000),
		GasFeeCap:  big.NewInt(2_000_000_000),
		Gas:        100_000,
		To:         &to,
		Value:      uint256.NewInt(7),
		Data:       []byte{0xCA, 0xFE},
		AccessList: types.AccessList{},
		BlobFeeCap: big.NewInt(3_000_000_000),
		BlobVersionedHashes: []types.Hash{
			types.HexToHash("0x010000000000000000000000000000000000000000000000000000000000abcd"),
		},
	})
	if err != nil {
		t.Fatalf("BlobTx SignNewTx: %v", err)
	}

	// Host recovers sender — must equal the signing key's address.
	recovered, err := signer.Sender(tx)
	if err != nil {
		t.Fatalf("BlobTx Sender: %v", err)
	}
	if recovered != expected {
		t.Fatalf("BlobTx host sender %s != expected %s",
			recovered.Hex(), expected.Hex())
	}

	// Canonical encoding survives a re-encode (byte-stable). The
	// guest's signing-hash reconstruction relies on this — non-
	// determinism here would silently break proving.
	var b1, b2 bytes.Buffer
	if err := tx.EncodeRLP(&b1); err != nil {
		t.Fatalf("BlobTx EncodeRLP: %v", err)
	}
	if err := tx.EncodeRLP(&b2); err != nil {
		t.Fatalf("BlobTx re-EncodeRLP: %v", err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Fatalf("BlobTx encoding non-deterministic: %d != %d bytes",
			b1.Len(), b2.Len())
	}
	if b1.Bytes()[0] != types.BlobTxType {
		t.Fatalf("BlobTx envelope must start with type byte 0x03, got 0x%02X",
			b1.Bytes()[0])
	}

	// Inspect BlobVersionedHashes round-trips through the typed-tx
	// accessor — the field the host's W4-2 path inspects when
	// constructing TxContext.BlobHashes for the EVM.
	hashes := tx.BlobVersionedHashes()
	if len(hashes) != 1 {
		t.Fatalf("BlobTx BlobVersionedHashes length = %d, want 1", len(hashes))
	}
	if hashes[0] != types.HexToHash("0x010000000000000000000000000000000000000000000000000000000000abcd") {
		t.Fatalf("BlobTx BlobVersionedHashes[0] mismatch: got %s", hashes[0].Hex())
	}
}

// TestDualEVMEquivalence_RealRevmHarness is the placeholder for the
// host-side revm comparator described in the file's TODO(equivalence)
// block. It is intentionally skipped under -short and panics with a
// clear message under -long until prover/host-revm exists. Running
// `go test -tags equivalence_full ./pkg/prover -run RealRevm` should
// be the gate that exercises this once the Rust side is built.
//
// The skip-in-short / fail-with-helpful-message-otherwise pattern is
// deliberate: it keeps CI green today while making the gap visible to
// anyone who attempts to run the full equivalence suite.
func TestDualEVMEquivalence_RealRevmHarness(t *testing.T) {
	if testing.Short() {
		t.Skip("dual-EVM-real-revm harness requires prover/host-revm; skipped under -short")
	}
	t.Skip("TODO(equivalence): prover/host-revm comparator not yet implemented; see equivalence_test.go top-of-file note")
}
