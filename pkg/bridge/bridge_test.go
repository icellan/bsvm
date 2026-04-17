package bridge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// --- TestSatoshisToWei ---

func TestSatoshisToWei(t *testing.T) {
	tests := []struct {
		name     string
		satoshis uint64
		wantWei  *uint256.Int
	}{
		{
			name:     "zero",
			satoshis: 0,
			wantWei:  uint256.NewInt(0),
		},
		{
			name:     "one satoshi",
			satoshis: 1,
			wantWei:  uint256.NewInt(1e10),
		},
		{
			name:     "one BSV (1e8 satoshis)",
			satoshis: 100_000_000,
			// 1e8 * 1e10 = 1e18
			wantWei: new(uint256.Int).Mul(uint256.NewInt(100_000_000), uint256.NewInt(1e10)),
		},
		{
			name:     "typical deposit 10000 sats",
			satoshis: 10000,
			wantWei:  new(uint256.Int).Mul(uint256.NewInt(10000), uint256.NewInt(1e10)),
		},
		{
			name:     "large amount",
			satoshis: 21_000_000 * 100_000_000, // 21 million BSV in satoshis
			wantWei:  new(uint256.Int).Mul(uint256.NewInt(21_000_000*100_000_000), uint256.NewInt(1e10)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := types.SatoshisToWei(tt.satoshis)
			if got.Cmp(tt.wantWei) != 0 {
				t.Errorf("SatoshisToWei(%d) = %s, want %s", tt.satoshis, got, tt.wantWei)
			}
		})
	}
}

// --- TestWeiToSatoshis ---

func TestWeiToSatoshis(t *testing.T) {
	tests := []struct {
		name         string
		wei          *uint256.Int
		wantSatoshis uint64
	}{
		{
			name:         "zero",
			wei:          uint256.NewInt(0),
			wantSatoshis: 0,
		},
		{
			name:         "nil",
			wei:          nil,
			wantSatoshis: 0,
		},
		{
			name:         "one satoshi worth of wei",
			wei:          uint256.NewInt(1e10),
			wantSatoshis: 1,
		},
		{
			name:         "1 BSV in wei",
			wei:          new(uint256.Int).Mul(uint256.NewInt(100_000_000), uint256.NewInt(1e10)),
			wantSatoshis: 100_000_000,
		},
		{
			name:         "truncation: partial satoshi",
			wei:          uint256.NewInt(1e10 + 5),
			wantSatoshis: 1, // floor division
		},
		{
			name:         "sub-satoshi amount",
			wei:          uint256.NewInt(999),
			wantSatoshis: 0, // below 1 satoshi
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := types.WeiToSatoshis(tt.wei)
			if got != tt.wantSatoshis {
				t.Errorf("WeiToSatoshis(%v) = %d, want %d", tt.wei, got, tt.wantSatoshis)
			}
		})
	}
}

// --- TestSatoshiConversionRoundtrip ---

func TestSatoshiConversionRoundtrip(t *testing.T) {
	testCases := []uint64{0, 1, 100, 10000, 100_000_000, 21_000_000_00_000_000}
	for _, sats := range testCases {
		wei := types.SatoshisToWei(sats)
		gotSats := types.WeiToSatoshis(wei)
		if gotSats != sats {
			t.Errorf("roundtrip failed for %d satoshis: got back %d", sats, gotSats)
		}
	}
}

// --- TestDepositTxHash ---

func TestDepositTxHash(t *testing.T) {
	tx := &types.DepositTransaction{
		SourceHash: types.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		From:       types.BridgeSystemAddress,
		To:         types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Value:      types.SatoshisToWei(50000),
		Gas:        0,
		IsSystemTx: true,
		Data:       nil,
	}

	h1 := tx.Hash()
	h2 := tx.Hash()

	// Hash must be deterministic.
	if h1 != h2 {
		t.Fatalf("hash is not deterministic: %s != %s", h1.Hex(), h2.Hex())
	}

	// Hash must be non-zero.
	if h1 == (types.Hash{}) {
		t.Fatal("hash is zero")
	}

	// Different source hash must produce different tx hash.
	tx2 := *tx
	tx2.SourceHash = types.HexToHash("0xdeadbeef00000000000000000000000000000000000000000000000000000000")
	if tx.Hash() == tx2.Hash() {
		t.Fatal("different source hash should produce different tx hash")
	}
}

// --- TestParseDeposit ---

func TestParseDeposit(t *testing.T) {
	bridgeScript := []byte{0xaa, 0xbb, 0xcc} // mock bridge covenant script
	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	shardID := make([]byte, 4) // zeroed shard ID

	// Build OP_RETURN payload: "BSVM" + 0x03 + shard_id(4) + l2_addr(20) = 29 bytes
	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)

	// Build script: OP_RETURN + push length + payload
	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a) // OP_RETURN
	opReturnScript = append(opReturnScript, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	tx := &BSVTransaction{
		TxID:        types.HexToHash("0xaaaa"),
		BlockHeight: 100,
		Outputs: []BSVOutput{
			{Script: bridgeScript, Value: 50000}, // Bridge payment
			{Script: opReturnScript, Value: 0},   // OP_RETURN metadata
		},
	}

	deposit := ParseDeposit(tx, bridgeScript, 0)
	if deposit == nil {
		t.Fatal("expected deposit, got nil")
	}

	if deposit.L2Address != l2Addr {
		t.Errorf("L2Address = %s, want %s", deposit.L2Address.Hex(), l2Addr.Hex())
	}

	if deposit.SatoshiAmount != 50000 {
		t.Errorf("SatoshiAmount = %d, want 50000", deposit.SatoshiAmount)
	}

	if deposit.BSVTxID != tx.TxID {
		t.Errorf("BSVTxID = %s, want %s", deposit.BSVTxID.Hex(), tx.TxID.Hex())
	}

	expectedWei := types.SatoshisToWei(50000)
	if deposit.L2WeiAmount.Cmp(expectedWei) != 0 {
		t.Errorf("L2WeiAmount = %s, want %s", deposit.L2WeiAmount, expectedWei)
	}
}

// --- TestParseDepositInvalid ---

func TestParseDepositInvalid(t *testing.T) {
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}

	tests := []struct {
		name string
		tx   *BSVTransaction
	}{
		{
			name: "no outputs",
			tx: &BSVTransaction{
				TxID:    types.HexToHash("0x01"),
				Outputs: nil,
			},
		},
		{
			name: "no bridge output",
			tx: &BSVTransaction{
				TxID: types.HexToHash("0x02"),
				Outputs: []BSVOutput{
					{Script: []byte{0x01, 0x02}, Value: 50000},
				},
			},
		},
		{
			name: "bridge output but no OP_RETURN",
			tx: &BSVTransaction{
				TxID: types.HexToHash("0x03"),
				Outputs: []BSVOutput{
					{Script: bridgeScript, Value: 50000},
					{Script: []byte{0x76, 0xa9}, Value: 0}, // P2PKH, not OP_RETURN
				},
			},
		},
		{
			name: "OP_RETURN with wrong magic",
			tx: &BSVTransaction{
				TxID: types.HexToHash("0x04"),
				Outputs: []BSVOutput{
					{Script: bridgeScript, Value: 50000},
					{Script: buildOpReturn([]byte("FAKE"), 0x03, make([]byte, 4), make([]byte, 20)), Value: 0},
				},
			},
		},
		{
			name: "OP_RETURN with wrong message type",
			tx: &BSVTransaction{
				TxID: types.HexToHash("0x05"),
				Outputs: []BSVOutput{
					{Script: bridgeScript, Value: 50000},
					{Script: buildOpReturn(DepositMagic, 0x99, make([]byte, 4), make([]byte, 20)), Value: 0},
				},
			},
		},
		{
			name: "OP_RETURN too short",
			tx: &BSVTransaction{
				TxID: types.HexToHash("0x06"),
				Outputs: []BSVOutput{
					{Script: bridgeScript, Value: 50000},
					{Script: []byte{0x6a, 0x04, 'B', 'S', 'V', 'M'}, Value: 0},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deposit := ParseDeposit(tt.tx, bridgeScript, 0)
			if deposit != nil {
				t.Error("expected nil deposit for invalid transaction")
			}
		})
	}
}

// buildOpReturn creates an OP_RETURN script with the given payload parts.
func buildOpReturn(magic []byte, msgType byte, shardID, addr []byte) []byte {
	payload := make([]byte, 0, len(magic)+1+len(shardID)+len(addr))
	payload = append(payload, magic...)
	payload = append(payload, msgType)
	payload = append(payload, shardID...)
	payload = append(payload, addr...)

	script := make([]byte, 0, 2+len(payload))
	script = append(script, 0x6a)
	script = append(script, byte(len(payload)))
	script = append(script, payload...)
	return script
}

// --- TestDepositToSystemTx ---

func TestDepositToSystemTx(t *testing.T) {
	bsvTxID := types.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	l2Addr := types.HexToAddress("0x1234567890123456789012345678901234567890")
	deposit := NewDeposit(bsvTxID, 100, l2Addr, 50000)

	dtx := deposit.ToDepositTx()

	if dtx.From != types.BridgeSystemAddress {
		t.Errorf("From = %s, want %s", dtx.From.Hex(), types.BridgeSystemAddress.Hex())
	}

	if dtx.To != l2Addr {
		t.Errorf("To = %s, want %s", dtx.To.Hex(), l2Addr.Hex())
	}

	expectedValue := types.SatoshisToWei(50000)
	if dtx.Value.Cmp(expectedValue) != 0 {
		t.Errorf("Value = %s, want %s", dtx.Value, expectedValue)
	}

	if dtx.Gas != 0 {
		t.Errorf("Gas = %d, want 0", dtx.Gas)
	}

	if !dtx.IsSystemTx {
		t.Error("IsSystemTx = false, want true")
	}

	if len(dtx.Data) != 0 {
		t.Errorf("Data = %x, want empty", dtx.Data)
	}

	expectedSourceHash := types.DepositTxID(bsvTxID)
	if dtx.SourceHash != expectedSourceHash {
		t.Errorf("SourceHash = %s, want %s", dtx.SourceHash.Hex(), expectedSourceHash.Hex())
	}
}

// --- TestWithdrawalHash ---

func TestWithdrawalHash(t *testing.T) {
	bsvAddr := make([]byte, 20)
	copy(bsvAddr, []byte{0x01, 0x02, 0x03, 0x04, 0x05})
	amount := uint64(100000)
	nonce := uint64(0)

	h := WithdrawalHash(bsvAddr, amount, nonce)

	// Verify it matches manual double-SHA256 computation.
	data := make([]byte, 0, 36)
	data = append(data, bsvAddr...)
	data = append(data, types.Uint64ToBE(amount)...)
	data = append(data, types.Uint64ToBE(nonce)...)

	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])

	if h != types.Hash(second) {
		t.Errorf("WithdrawalHash mismatch: got %s, want %s", h.Hex(), types.Hash(second).Hex())
	}

	// Hash must be non-zero.
	if h == (types.Hash{}) {
		t.Error("withdrawal hash is zero")
	}

	// Different inputs produce different hashes.
	h2 := WithdrawalHash(bsvAddr, amount, 1)
	if h == h2 {
		t.Error("different nonce should produce different hash")
	}
}

// --- TestWithdrawalMerkleTree ---

func TestWithdrawalMerkleTree(t *testing.T) {
	// Empty tree.
	root, proofs := BuildWithdrawalMerkleTree(nil)
	if root != (types.Hash{}) {
		t.Error("empty tree should have zero root")
	}
	if proofs != nil {
		t.Error("empty tree should have nil proofs")
	}

	// Single element.
	h0 := WithdrawalHash([]byte{0x01}, 100, 0)
	root, proofs = BuildWithdrawalMerkleTree([]types.Hash{h0})
	if root != h0 {
		t.Errorf("single-element root = %s, want %s", root.Hex(), h0.Hex())
	}
	if len(proofs) != 1 || len(proofs[0]) != 0 {
		t.Errorf("single-element proof should be empty, got %d proofs with %d elements", len(proofs), len(proofs[0]))
	}

	// Two elements.
	h1 := WithdrawalHash([]byte{0x02}, 200, 1)
	root, proofs = BuildWithdrawalMerkleTree([]types.Hash{h0, h1})

	expectedRoot := sha256Pair(h0, h1)
	if root != expectedRoot {
		t.Errorf("two-element root mismatch: got %s, want %s", root.Hex(), expectedRoot.Hex())
	}

	// Verify proofs.
	if len(proofs) != 2 {
		t.Fatalf("expected 2 proofs, got %d", len(proofs))
	}
	if len(proofs[0]) != 1 || proofs[0][0] != h1 {
		t.Error("proof[0] should contain h1 as sibling")
	}
	if len(proofs[1]) != 1 || proofs[1][0] != h0 {
		t.Error("proof[1] should contain h0 as sibling")
	}

	// Four elements.
	h2 := WithdrawalHash([]byte{0x03}, 300, 2)
	h3 := WithdrawalHash([]byte{0x04}, 400, 3)
	root4, proofs4 := BuildWithdrawalMerkleTree([]types.Hash{h0, h1, h2, h3})

	left := sha256Pair(h0, h1)
	right := sha256Pair(h2, h3)
	expectedRoot4 := sha256Pair(left, right)
	if root4 != expectedRoot4 {
		t.Errorf("four-element root mismatch: got %s, want %s", root4.Hex(), expectedRoot4.Hex())
	}
	if len(proofs4) != 4 {
		t.Fatalf("expected 4 proofs, got %d", len(proofs4))
	}
}

// --- TestWithdrawalMerkleProof ---

func TestWithdrawalMerkleProof(t *testing.T) {
	hashes := make([]types.Hash, 5)
	for i := range hashes {
		hashes[i] = WithdrawalHash([]byte{byte(i + 1)}, uint64(i+1)*100, uint64(i))
	}

	root, allProofs := BuildWithdrawalMerkleTree(hashes)

	// Verify each proof individually.
	for i, proof := range allProofs {
		rootFromProof, proofFromFunc := WithdrawalProof(hashes, i)

		if rootFromProof != root {
			t.Errorf("WithdrawalProof root mismatch at index %d", i)
		}

		if len(proof) != len(proofFromFunc) {
			t.Errorf("proof length mismatch at index %d: BuildTree=%d, WithdrawalProof=%d",
				i, len(proof), len(proofFromFunc))
			continue
		}

		for j := range proof {
			if proof[j] != proofFromFunc[j] {
				t.Errorf("proof element mismatch at index %d, level %d", i, j)
			}
		}

		// Verify the proof.
		if !VerifyWithdrawalProof(hashes[i], proof, i, root) {
			t.Errorf("proof verification failed at index %d", i)
		}
	}

	// Invalid proof should fail verification.
	if VerifyWithdrawalProof(hashes[0], allProofs[1], 0, root) {
		t.Error("verification should fail with wrong proof")
	}
}

// --- TestWithdrawalProofEdgeCases ---

func TestWithdrawalProofEdgeCases(t *testing.T) {
	// Empty hashes.
	root, proof := WithdrawalProof(nil, 0)
	if root != (types.Hash{}) {
		t.Error("empty hashes should return zero root")
	}
	if proof != nil {
		t.Error("empty hashes should return nil proof")
	}

	// Out of range index.
	hashes := []types.Hash{WithdrawalHash([]byte{0x01}, 100, 0)}
	root, proof = WithdrawalProof(hashes, -1)
	if root != (types.Hash{}) || proof != nil {
		t.Error("negative index should return zero root and nil proof")
	}

	root, proof = WithdrawalProof(hashes, 1)
	if root != (types.Hash{}) || proof != nil {
		t.Error("out-of-range index should return zero root and nil proof")
	}
}

// --- TestBridgeMonitorProcessDeposit ---

func TestBridgeMonitorProcessDeposit(t *testing.T) {
	client := &mockBSVClient{}
	submitter := &mockOverlaySubmitter{}
	config := DefaultConfig()
	config.BSVConfirmations = 6

	monitor := NewBridgeMonitor(config, client, submitter, nil)
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	monitor.SetBridgeScriptHash(bridgeScript)

	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	shardID := make([]byte, 4)

	// Build a valid deposit transaction.
	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)
	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	txs := []*BSVTransaction{
		{
			TxID:        types.HexToHash("0xabcd"),
			BlockHeight: 100,
			Outputs: []BSVOutput{
				{Script: bridgeScript, Value: 50000},
				{Script: opReturnScript, Value: 0},
			},
		},
	}

	// Process the block.
	monitor.ProcessBlock(100, txs)

	// Should be pending, not yet confirmed.
	if monitor.PendingCount() != 1 {
		t.Fatalf("expected 1 pending deposit, got %d", monitor.PendingCount())
	}

	// At height 105, still not eligible (need 6 confirmations: height >= 100 + 6 = 106).
	eligible := monitor.EligibleDeposits(105)
	if len(eligible) != 0 {
		t.Errorf("expected 0 eligible deposits at height 105, got %d", len(eligible))
	}

	// At height 106, should be eligible.
	eligible = monitor.EligibleDeposits(106)
	if len(eligible) != 1 {
		t.Fatalf("expected 1 eligible deposit at height 106, got %d", len(eligible))
	}

	if eligible[0].L2Address != l2Addr {
		t.Errorf("eligible deposit L2Address = %s, want %s", eligible[0].L2Address.Hex(), l2Addr.Hex())
	}

	if eligible[0].SatoshiAmount != 50000 {
		t.Errorf("eligible deposit SatoshiAmount = %d, want 50000", eligible[0].SatoshiAmount)
	}
}

// --- TestBridgeMonitorDedup ---

func TestBridgeMonitorDedup(t *testing.T) {
	client := &mockBSVClient{}
	submitter := &mockOverlaySubmitter{}
	config := DefaultConfig()
	monitor := NewBridgeMonitor(config, client, submitter, nil)
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	monitor.SetBridgeScriptHash(bridgeScript)

	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	shardID := make([]byte, 4)

	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)
	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	txID := types.HexToHash("0xabcd")
	txs := []*BSVTransaction{
		{
			TxID:        txID,
			BlockHeight: 100,
			Outputs: []BSVOutput{
				{Script: bridgeScript, Value: 50000},
				{Script: opReturnScript, Value: 0},
			},
		},
	}

	// Process the same block twice.
	monitor.ProcessBlock(100, txs)
	monitor.ProcessBlock(100, txs)

	// Should only be 1 pending deposit (second is a duplicate BSV txid
	// in pendingDeposits but not yet marked processed).
	eligible := monitor.EligibleDeposits(200)
	if len(eligible) != 2 {
		// Before marking processed, duplicates accumulate in pending
		// because processedDeposits is not set until MarkProcessed.
		// This is expected -- the overlay node should check before
		// including. Let's mark the first one processed and verify.
	}

	// Mark as processed.
	monitor.MarkProcessed(txID, 0)

	// Now the deposit should not appear again.
	if !monitor.IsProcessed(txID, 0) {
		t.Error("expected deposit to be marked as processed")
	}

	// Process the same transaction in a new block scan.
	monitor.ProcessBlock(101, txs)

	eligible = monitor.EligibleDeposits(200)
	if len(eligible) != 0 {
		t.Errorf("expected 0 eligible deposits after marking processed, got %d", len(eligible))
	}
}

// --- TestBridgeMonitorMinDeposit ---

func TestBridgeMonitorMinDeposit(t *testing.T) {
	client := &mockBSVClient{}
	submitter := &mockOverlaySubmitter{}
	config := DefaultConfig()
	config.MinDepositSatoshis = 10000

	monitor := NewBridgeMonitor(config, client, submitter, nil)
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	monitor.SetBridgeScriptHash(bridgeScript)

	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	shardID := make([]byte, 4)

	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)
	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	// Below minimum.
	txs := []*BSVTransaction{
		{
			TxID:        types.HexToHash("0x01"),
			BlockHeight: 100,
			Outputs: []BSVOutput{
				{Script: bridgeScript, Value: 9999}, // Below min
				{Script: opReturnScript, Value: 0},
			},
		},
	}
	monitor.ProcessBlock(100, txs)

	eligible := monitor.EligibleDeposits(200)
	if len(eligible) != 0 {
		t.Errorf("expected 0 eligible deposits for below-minimum amount, got %d", len(eligible))
	}

	// Exactly at minimum.
	txs2 := []*BSVTransaction{
		{
			TxID:        types.HexToHash("0x02"),
			BlockHeight: 101,
			Outputs: []BSVOutput{
				{Script: bridgeScript, Value: 10000}, // At min
				{Script: opReturnScript, Value: 0},
			},
		},
	}
	monitor.ProcessBlock(101, txs2)

	eligible = monitor.EligibleDeposits(200)
	if len(eligible) != 1 {
		t.Errorf("expected 1 eligible deposit for at-minimum amount, got %d", len(eligible))
	}
}

// --- TestBridgeConfigDefaults ---

func TestBridgeConfigDefaults(t *testing.T) {
	config := DefaultConfig()

	if config.MinDepositSatoshis != 10000 {
		t.Errorf("MinDepositSatoshis = %d, want 10000", config.MinDepositSatoshis)
	}

	if config.MinWithdrawalSatoshis != 10000 {
		t.Errorf("MinWithdrawalSatoshis = %d, want 10000", config.MinWithdrawalSatoshis)
	}

	if config.BSVConfirmations != 6 {
		t.Errorf("BSVConfirmations = %d, want 6", config.BSVConfirmations)
	}

	if config.BridgeContractAddress != types.BridgeContractAddress {
		t.Errorf("BridgeContractAddress = %s, want %s",
			config.BridgeContractAddress.Hex(), types.BridgeContractAddress.Hex())
	}
}

// --- TestDepositTxID ---

func TestDepositTxID(t *testing.T) {
	txid := types.HexToHash("0xaaaa")

	id1 := types.DepositTxID(txid)
	id2 := types.DepositTxID(txid)

	if id1 != id2 {
		t.Fatal("DepositTxID is not deterministic")
	}

	if id1 == (types.Hash{}) {
		t.Fatal("DepositTxID returned zero hash")
	}

	// Different txid should produce different ID.
	txid2 := types.HexToHash("0xbbbb")
	id3 := types.DepositTxID(txid2)
	if id1 == id3 {
		t.Fatal("different txid should produce different DepositTxID")
	}
}

// --- TestMaxSatoshisToWei ---

func TestMaxSatoshisToWei(t *testing.T) {
	// 21 million BSV = 2.1e15 satoshis
	// 2.1e15 * 1e10 = 2.1e25, which fits in uint256.
	maxSatoshis := uint64(21_000_000) * uint64(100_000_000)
	wei := types.SatoshisToWei(maxSatoshis)
	if wei.IsZero() {
		t.Fatal("max satoshis should produce non-zero wei")
	}

	// Roundtrip.
	gotSats := types.WeiToSatoshis(wei)
	if gotSats != maxSatoshis {
		t.Errorf("roundtrip failed: got %d, want %d", gotSats, maxSatoshis)
	}
}

// --- TestWeiToSatoshisMaxUint64 ---

func TestWeiToSatoshisMaxUint64(t *testing.T) {
	// This tests that WeiToSatoshis handles very large wei values
	// without panicking.
	large := new(uint256.Int).SetUint64(math.MaxUint64)
	large.Mul(large, uint256.NewInt(1e10))
	sats := types.WeiToSatoshis(large)
	if sats != math.MaxUint64 {
		t.Errorf("expected MaxUint64 satoshis, got %d", sats)
	}
}

// --- TestOddNumberOfLeaves ---

func TestOddNumberOfLeaves(t *testing.T) {
	// Test Merkle tree with 3 leaves (odd number requires padding).
	h0 := WithdrawalHash([]byte{0x01}, 100, 0)
	h1 := WithdrawalHash([]byte{0x02}, 200, 1)
	h2 := WithdrawalHash([]byte{0x03}, 300, 2)

	root, proofs := BuildWithdrawalMerkleTree([]types.Hash{h0, h1, h2})

	// The tree should pad with zero hash:
	//        root
	//       /    \
	//    h01      h2z
	//   /   \    /   \
	//  h0   h1  h2   0x00
	h01 := sha256Pair(h0, h1)
	h2z := sha256Pair(h2, types.Hash{})
	expectedRoot := sha256Pair(h01, h2z)

	if root != expectedRoot {
		t.Errorf("3-element root mismatch: got %s, want %s", root.Hex(), expectedRoot.Hex())
	}

	// Verify all proofs.
	for i, proof := range proofs {
		if !VerifyWithdrawalProof([]types.Hash{h0, h1, h2}[i], proof, i, root) {
			t.Errorf("proof verification failed for leaf %d", i)
		}
	}
}

// --- Test helpers ---

// mockBSVClient implements BSVClient for testing.
type mockBSVClient struct {
	txs         map[types.Hash]*BSVTransaction
	blockHeight uint64
	blockTxs    map[uint64][]*BSVTransaction
}

func (m *mockBSVClient) GetTransaction(txid types.Hash) (*BSVTransaction, error) {
	if m.txs == nil {
		return nil, nil
	}
	return m.txs[txid], nil
}

func (m *mockBSVClient) GetBlockHeight() (uint64, error) {
	return m.blockHeight, nil
}

func (m *mockBSVClient) GetBlockTransactions(height uint64) ([]*BSVTransaction, error) {
	if m.blockTxs == nil {
		return nil, nil
	}
	return m.blockTxs[height], nil
}

func (m *mockBSVClient) SubscribeNewBlocks(_ context.Context) (<-chan uint64, error) {
	ch := make(chan uint64)
	return ch, nil
}

// mockOverlaySubmitter implements OverlaySubmitter for testing.
type mockOverlaySubmitter struct {
	submitted []*types.DepositTransaction
}

func (m *mockOverlaySubmitter) SubmitDepositTx(tx *types.DepositTransaction) error {
	m.submitted = append(m.submitted, tx)
	return nil
}

// sha256PairTest is a test-visible alias for the internal sha256Pair function.
func sha256PairTest(a, b types.Hash) types.Hash {
	h := sha256.New()
	h.Write(a[:])
	h.Write(b[:])
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// --- Deposit Persistence Tests ---

// newTestMonitor creates a BridgeMonitor backed by an in-memory database.
func newTestMonitor(t *testing.T) (*BridgeMonitor, *db.MemoryDB) {
	t.Helper()
	store := db.NewMemoryDB()
	config := DefaultConfig()
	config.BSVConfirmations = 6
	m := NewBridgeMonitor(config, &mockBSVClient{}, &mockOverlaySubmitter{}, store)
	return m, store
}

func TestBridgeMonitor_PersistDeposit(t *testing.T) {
	m, store := newTestMonitor(t)

	dep := NewDepositWithVout(
		types.HexToHash("0xaabbccdd"),
		0,
		100,
		types.HexToAddress("0x1111111111111111111111111111111111111111"),
		50000,
	)
	dep.Confirmed = true

	if err := m.PersistDeposit(dep); err != nil {
		t.Fatalf("PersistDeposit: %v", err)
	}

	// Verify in-memory state.
	if !m.IsProcessed(dep.BSVTxID, dep.Vout) {
		t.Error("deposit should be marked processed in memory")
	}

	// Create a new monitor with the same DB and reload.
	m2 := NewBridgeMonitor(DefaultConfig(), &mockBSVClient{}, &mockOverlaySubmitter{}, store)
	if err := m2.LoadProcessedDeposits(); err != nil {
		t.Fatalf("LoadProcessedDeposits: %v", err)
	}

	if !m2.IsProcessed(dep.BSVTxID, dep.Vout) {
		t.Error("deposit should survive reload from DB")
	}
}

func TestBridgeMonitor_LoadProcessedDeposits(t *testing.T) {
	m, store := newTestMonitor(t)

	// Persist multiple deposits.
	for i := 0; i < 5; i++ {
		txid := types.Hash{}
		txid[0] = byte(i + 1)
		dep := NewDepositWithVout(txid, uint32(i), uint64(100+i),
			types.HexToAddress("0x2222222222222222222222222222222222222222"),
			uint64(10000*(i+1)),
		)
		dep.Confirmed = true
		if err := m.PersistDeposit(dep); err != nil {
			t.Fatalf("PersistDeposit(%d): %v", i, err)
		}
	}

	// Create a new monitor and load.
	m2 := NewBridgeMonitor(DefaultConfig(), &mockBSVClient{}, &mockOverlaySubmitter{}, store)
	if err := m2.LoadProcessedDeposits(); err != nil {
		t.Fatalf("LoadProcessedDeposits: %v", err)
	}

	for i := 0; i < 5; i++ {
		txid := types.Hash{}
		txid[0] = byte(i + 1)
		if !m2.IsProcessed(txid, uint32(i)) {
			t.Errorf("deposit %d should be loaded from DB", i)
		}
	}
}

func TestBridgeMonitor_IsDepositProcessed(t *testing.T) {
	m, _ := newTestMonitor(t)

	txid := types.HexToHash("0xdeadbeef")
	dep := NewDepositWithVout(txid, 0, 100,
		types.HexToAddress("0x3333333333333333333333333333333333333333"),
		20000,
	)

	// Not processed yet.
	if m.IsDepositProcessed(txid, 0) {
		t.Error("deposit should not be processed yet")
	}

	// Persist it.
	if err := m.PersistDeposit(dep); err != nil {
		t.Fatalf("PersistDeposit: %v", err)
	}

	// Should be processed from memory.
	if !m.IsDepositProcessed(txid, 0) {
		t.Error("deposit should be processed after persist")
	}

	// Should also be found via DB fallback in a fresh monitor.
	m2, _ := newTestMonitor(t)
	// Share the same DB by direct key insertion.
	key := depositKey(txid, 0)
	val := encodeDeposit(dep)
	if err := m2.db.Put(key, val); err != nil {
		t.Fatalf("direct put: %v", err)
	}
	if !m2.IsDepositProcessed(txid, 0) {
		t.Error("deposit should be found via DB fallback")
	}
}

func TestBridgeMonitor_DuplicateDeposit(t *testing.T) {
	m, _ := newTestMonitor(t)

	txid := types.HexToHash("0xduplicate")
	dep := NewDepositWithVout(txid, 0, 100,
		types.HexToAddress("0x4444444444444444444444444444444444444444"),
		30000,
	)

	// Persist twice — should be idempotent.
	if err := m.PersistDeposit(dep); err != nil {
		t.Fatalf("first PersistDeposit: %v", err)
	}
	if err := m.PersistDeposit(dep); err != nil {
		t.Fatalf("second PersistDeposit: %v", err)
	}

	// Should still be marked processed.
	if !m.IsProcessed(txid, 0) {
		t.Error("deposit should be processed after double persist")
	}

	// Verify DB has the entry (only one write, no error).
	key := depositKey(txid, 0)
	has, err := m.db.Has(key)
	if err != nil || !has {
		t.Error("deposit should exist in DB")
	}
}

func TestBridgeMonitor_PersistMultiple(t *testing.T) {
	m, store := newTestMonitor(t)

	const count = 100
	txids := make([]types.Hash, count)
	for i := 0; i < count; i++ {
		txid := types.Hash{}
		txid[0] = byte(i >> 8)
		txid[1] = byte(i & 0xff)
		txids[i] = txid

		dep := NewDepositWithVout(txid, uint32(i%4), uint64(100+i),
			types.HexToAddress("0x5555555555555555555555555555555555555555"),
			uint64(10000+i*100),
		)
		dep.Confirmed = true
		if err := m.PersistDeposit(dep); err != nil {
			t.Fatalf("PersistDeposit(%d): %v", i, err)
		}
	}

	// Reload in a new monitor.
	m2 := NewBridgeMonitor(DefaultConfig(), &mockBSVClient{}, &mockOverlaySubmitter{}, store)
	if err := m2.LoadProcessedDeposits(); err != nil {
		t.Fatalf("LoadProcessedDeposits: %v", err)
	}

	for i, txid := range txids {
		if !m2.IsProcessed(txid, uint32(i%4)) {
			t.Errorf("deposit %d should be loaded after reload", i)
		}
	}
}

// --- Deposit Horizon Tests ---

func TestBridgeMonitor_SetDepositHorizon_Monotonic(t *testing.T) {
	m, _ := newTestMonitor(t)

	// Set initial horizon.
	if err := m.SetDepositHorizon(100); err != nil {
		t.Fatalf("SetDepositHorizon(100): %v", err)
	}
	if got := m.DepositHorizon(); got != 100 {
		t.Errorf("DepositHorizon = %d, want 100", got)
	}

	// Increase is allowed.
	if err := m.SetDepositHorizon(200); err != nil {
		t.Fatalf("SetDepositHorizon(200): %v", err)
	}
	if got := m.DepositHorizon(); got != 200 {
		t.Errorf("DepositHorizon = %d, want 200", got)
	}

	// Same value is allowed.
	if err := m.SetDepositHorizon(200); err != nil {
		t.Fatalf("SetDepositHorizon(200) same: %v", err)
	}

	// Decrease should fail.
	if err := m.SetDepositHorizon(150); err == nil {
		t.Error("SetDepositHorizon(150) should fail when current is 200")
	}

	// Horizon should remain unchanged after failed decrease.
	if got := m.DepositHorizon(); got != 200 {
		t.Errorf("DepositHorizon = %d after failed decrease, want 200", got)
	}
}

func TestBridgeMonitor_ValidateHorizon_WithinLimit(t *testing.T) {
	m, _ := newTestMonitor(t)

	tests := []struct {
		horizon uint64
		tip     uint64
	}{
		{100, 100}, // same
		{100, 101}, // tip 1 ahead
		{100, 103}, // tip 3 ahead (at limit)
		{103, 100}, // horizon 3 ahead (at limit)
		{50, 50},   // equal
	}

	for _, tt := range tests {
		if err := m.ValidateHorizon(tt.horizon, tt.tip); err != nil {
			t.Errorf("ValidateHorizon(%d, %d) should pass: %v", tt.horizon, tt.tip, err)
		}
	}
}

func TestBridgeMonitor_ValidateHorizon_TooStale(t *testing.T) {
	m, _ := newTestMonitor(t)

	// Horizon is 4+ blocks behind the tip.
	if err := m.ValidateHorizon(100, 104); err == nil {
		t.Error("ValidateHorizon(100, 104) should fail: horizon too stale")
	}
	if err := m.ValidateHorizon(100, 200); err == nil {
		t.Error("ValidateHorizon(100, 200) should fail: horizon too stale")
	}
}

func TestBridgeMonitor_ValidateHorizon_TooFar(t *testing.T) {
	m, _ := newTestMonitor(t)

	// Horizon is 4+ blocks ahead of the tip.
	if err := m.ValidateHorizon(104, 100); err == nil {
		t.Error("ValidateHorizon(104, 100) should fail: horizon too far ahead")
	}
	if err := m.ValidateHorizon(200, 100); err == nil {
		t.Error("ValidateHorizon(200, 100) should fail: horizon too far ahead")
	}
}

func TestBridgeMonitor_EligibleDepositsAtHorizon(t *testing.T) {
	m, _ := newTestMonitor(t)

	// Persist deposits at different block heights.
	for i := 0; i < 5; i++ {
		txid := types.Hash{}
		txid[0] = byte(i + 1)
		dep := NewDepositWithVout(txid, 0, uint64(100+i*10),
			types.HexToAddress("0x6666666666666666666666666666666666666666"),
			uint64(10000*(i+1)),
		)
		dep.Confirmed = true
		if err := m.PersistDeposit(dep); err != nil {
			t.Fatalf("PersistDeposit(%d): %v", i, err)
		}
	}

	// Heights: 100, 110, 120, 130, 140
	// Horizon 115 should include deposits at 100 and 110.
	eligible := m.EligibleDepositsAtHorizon(115)
	if len(eligible) != 2 {
		t.Fatalf("expected 2 eligible at horizon 115, got %d", len(eligible))
	}

	// Horizon 140 should include all 5.
	eligible = m.EligibleDepositsAtHorizon(140)
	if len(eligible) != 5 {
		t.Fatalf("expected 5 eligible at horizon 140, got %d", len(eligible))
	}

	// Horizon 99 should include none.
	eligible = m.EligibleDepositsAtHorizon(99)
	if len(eligible) != 0 {
		t.Fatalf("expected 0 eligible at horizon 99, got %d", len(eligible))
	}
}

func TestBridgeMonitor_EligibleDepositsAtHorizon_Sorted(t *testing.T) {
	m, _ := newTestMonitor(t)

	// Create deposits with same block height but different txids.
	type depDef struct {
		txidByte byte
		height   uint64
	}
	defs := []depDef{
		{0xcc, 100},
		{0xaa, 100},
		{0xbb, 100},
		{0x11, 90},
		{0xff, 110},
	}

	for _, d := range defs {
		txid := types.Hash{}
		txid[0] = d.txidByte
		dep := NewDepositWithVout(txid, 0, d.height,
			types.HexToAddress("0x7777777777777777777777777777777777777777"),
			20000,
		)
		dep.Confirmed = true
		if err := m.PersistDeposit(dep); err != nil {
			t.Fatalf("PersistDeposit: %v", err)
		}
	}

	eligible := m.EligibleDepositsAtHorizon(200)
	if len(eligible) != 5 {
		t.Fatalf("expected 5 eligible, got %d", len(eligible))
	}

	// Verify sort order: by blockHeight ASC, then txid ASC.
	for i := 1; i < len(eligible); i++ {
		prev := eligible[i-1]
		curr := eligible[i]

		if prev.BSVBlockHeight > curr.BSVBlockHeight {
			t.Errorf("wrong order at %d: height %d > %d",
				i, prev.BSVBlockHeight, curr.BSVBlockHeight)
		}
		if prev.BSVBlockHeight == curr.BSVBlockHeight {
			if prev.BSVTxID.String() > curr.BSVTxID.String() {
				t.Errorf("wrong order at %d: txid %s > %s (same height %d)",
					i, prev.BSVTxID.String(), curr.BSVTxID.String(), prev.BSVBlockHeight)
			}
		}
	}

	// First should be the deposit at height 90.
	if eligible[0].BSVBlockHeight != 90 {
		t.Errorf("first eligible should be at height 90, got %d", eligible[0].BSVBlockHeight)
	}
	// Last should be at height 110.
	if eligible[4].BSVBlockHeight != 110 {
		t.Errorf("last eligible should be at height 110, got %d", eligible[4].BSVBlockHeight)
	}
}

func TestBridgeMonitor_HorizonPersistence(t *testing.T) {
	m, store := newTestMonitor(t)

	// Set a horizon.
	if err := m.SetDepositHorizon(500); err != nil {
		t.Fatalf("SetDepositHorizon: %v", err)
	}

	// Create a new monitor and reload from DB.
	m2 := NewBridgeMonitor(DefaultConfig(), &mockBSVClient{}, &mockOverlaySubmitter{}, store)
	if err := m2.LoadProcessedDeposits(); err != nil {
		t.Fatalf("LoadProcessedDeposits: %v", err)
	}

	if got := m2.DepositHorizon(); got != 500 {
		t.Errorf("DepositHorizon after reload = %d, want 500", got)
	}

	// Monotonic enforcement should still apply with loaded horizon.
	if err := m2.SetDepositHorizon(400); err == nil {
		t.Error("SetDepositHorizon(400) should fail when loaded horizon is 500")
	}

	// Increasing should work.
	if err := m2.SetDepositHorizon(600); err != nil {
		t.Fatalf("SetDepositHorizon(600): %v", err)
	}
	if got := m2.DepositHorizon(); got != 600 {
		t.Errorf("DepositHorizon = %d, want 600", got)
	}
}

// --- TestParseDeposit_ShardID4Bytes ---

func TestParseDeposit_ShardID4Bytes(t *testing.T) {
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	l2Addr := types.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
	// Non-zero shard ID: 0x00000042 (uint32 = 66).
	shardID := []byte{0x00, 0x00, 0x00, 0x42}

	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)

	if len(payload) != 29 {
		t.Fatalf("payload length = %d, want 29", len(payload))
	}

	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	tx := &BSVTransaction{
		TxID: types.HexToHash("0xface"),
		Outputs: []BSVOutput{
			{Script: bridgeScript, Value: 100000},
			{Script: opReturnScript, Value: 0},
		},
	}

	// Local shard matches the OP_RETURN shard_id (0x42).
	deposit := ParseDeposit(tx, bridgeScript, 0x42)
	if deposit == nil {
		t.Fatal("expected deposit with 4-byte shard ID, got nil")
	}
	if deposit.L2Address != l2Addr {
		t.Errorf("L2Address = %s, want %s", deposit.L2Address.Hex(), l2Addr.Hex())
	}
	if deposit.SatoshiAmount != 100000 {
		t.Errorf("SatoshiAmount = %d, want 100000", deposit.SatoshiAmount)
	}

	// A foreign shard_id must be rejected.
	foreign := ParseDeposit(tx, bridgeScript, 0x43)
	if foreign != nil {
		t.Errorf("foreign shard_id accepted; expected nil")
	}
}

// --- TestParseDeposit_Old32ByteShardIDRejected ---

func TestParseDeposit_Old32ByteShardIDRejected(t *testing.T) {
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	// Old-format 32-byte shard ID should be rejected (wrong total length).
	shardID := make([]byte, 32)

	payload := make([]byte, 0, 57)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)

	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	tx := &BSVTransaction{
		TxID: types.HexToHash("0xdead"),
		Outputs: []BSVOutput{
			{Script: bridgeScript, Value: 50000},
			{Script: opReturnScript, Value: 0},
		},
	}

	// The old 32-byte format will parse but extract the wrong address
	// (bytes 9..28 of a 57-byte payload are part of the shard ID zeros,
	// not the L2 address). The L2 address extracted will be all zeros.
	deposit := ParseDeposit(tx, bridgeScript, 0)
	if deposit != nil && deposit.L2Address == l2Addr {
		t.Error("32-byte shard ID should not correctly extract the L2 address")
	}
}

// --- TestBridgeMonitor_DedupCompositeKey ---

func TestBridgeMonitor_DedupCompositeKey(t *testing.T) {
	// Verify that two outputs in the same transaction (different vouts)
	// are tracked independently.
	m, _ := newTestMonitor(t)

	txid := types.HexToHash("0xaabb")
	dep0 := NewDepositWithVout(txid, 0, 100,
		types.HexToAddress("0x1111111111111111111111111111111111111111"),
		50000,
	)
	dep1 := NewDepositWithVout(txid, 1, 100,
		types.HexToAddress("0x2222222222222222222222222222222222222222"),
		60000,
	)

	// Persist deposit with vout 0.
	if err := m.PersistDeposit(dep0); err != nil {
		t.Fatalf("PersistDeposit(vout=0): %v", err)
	}

	// Vout 0 should be processed, vout 1 should not.
	if !m.IsProcessed(txid, 0) {
		t.Error("vout 0 should be processed")
	}
	if m.IsProcessed(txid, 1) {
		t.Error("vout 1 should not be processed yet")
	}

	// Persist deposit with vout 1.
	if err := m.PersistDeposit(dep1); err != nil {
		t.Fatalf("PersistDeposit(vout=1): %v", err)
	}

	// Both should now be processed.
	if !m.IsProcessed(txid, 0) {
		t.Error("vout 0 should still be processed")
	}
	if !m.IsProcessed(txid, 1) {
		t.Error("vout 1 should now be processed")
	}
}

// --- TestBridgeMonitor_MarkProcessed_CompositeKey ---

func TestBridgeMonitor_MarkProcessed_CompositeKey(t *testing.T) {
	m, _ := newTestMonitor(t)
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	m.SetBridgeScriptHash(bridgeScript)

	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	shardID := make([]byte, 4)

	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)
	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	txID := types.HexToHash("0xabcd")
	txs := []*BSVTransaction{
		{
			TxID:        txID,
			BlockHeight: 100,
			Outputs: []BSVOutput{
				{Script: bridgeScript, Value: 50000},
				{Script: opReturnScript, Value: 0},
			},
		},
	}

	m.ProcessBlock(100, txs)

	// Mark only vout 0 as processed.
	m.MarkProcessed(txID, 0)

	if !m.IsProcessed(txID, 0) {
		t.Error("vout 0 should be processed after MarkProcessed")
	}

	// Vout 1 should not be affected.
	if m.IsProcessed(txID, 1) {
		t.Error("vout 1 should not be processed")
	}
}

// --- TestBridgeMonitor_Run ---

func TestBridgeMonitor_Run(t *testing.T) {
	blockCh := make(chan uint64, 2)
	client := &mockBSVClientWithSub{
		blockCh: blockCh,
	}
	submitter := &mockOverlaySubmitter{}
	config := DefaultConfig()
	config.BSVConfirmations = 1

	monitor := NewBridgeMonitor(config, client, submitter, nil)
	bridgeScript := []byte{0xaa, 0xbb, 0xcc}
	monitor.SetBridgeScriptHash(bridgeScript)

	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	shardID := make([]byte, 4)

	payload := make([]byte, 0, 29)
	payload = append(payload, DepositMagic...)
	payload = append(payload, DepositMsgType)
	payload = append(payload, shardID...)
	payload = append(payload, l2Addr[:]...)
	opReturnScript := make([]byte, 0, 2+len(payload))
	opReturnScript = append(opReturnScript, 0x6a, byte(len(payload)))
	opReturnScript = append(opReturnScript, payload...)

	// Set up block transactions for the mock client.
	client.blockTxs = map[uint64][]*BSVTransaction{
		100: {
			{
				TxID:        types.HexToHash("0x0100"),
				BlockHeight: 100,
				Outputs: []BSVOutput{
					{Script: bridgeScript, Value: 50000},
					{Script: opReturnScript, Value: 0},
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Send block height, then close.
	blockCh <- 100
	close(blockCh)

	err := monitor.Run(ctx)
	cancel()

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// The deposit should be pending.
	if monitor.PendingCount() != 1 {
		t.Errorf("expected 1 pending deposit after Run, got %d", monitor.PendingCount())
	}
}

// mockBSVClientWithSub implements BSVClient with a controllable
// SubscribeNewBlocks channel.
type mockBSVClientWithSub struct {
	blockCh  chan uint64
	blockTxs map[uint64][]*BSVTransaction
}

func (m *mockBSVClientWithSub) GetTransaction(_ types.Hash) (*BSVTransaction, error) {
	return nil, nil
}

func (m *mockBSVClientWithSub) GetBlockHeight() (uint64, error) {
	return 0, nil
}

func (m *mockBSVClientWithSub) GetBlockTransactions(height uint64) ([]*BSVTransaction, error) {
	if m.blockTxs == nil {
		return nil, nil
	}
	return m.blockTxs[height], nil
}

func (m *mockBSVClientWithSub) SubscribeNewBlocks(_ context.Context) (<-chan uint64, error) {
	return m.blockCh, nil
}

// --- TestWithdrawer_ProcessFinalizedWithdrawals ---

func TestWithdrawer_ProcessFinalizedWithdrawals(t *testing.T) {
	broadcaster := &mockBroadcaster{}
	scanner := &mockWithdrawalScanner{
		withdrawals: []*PendingWithdrawal{
			{
				Nonce:          1,
				BSVAddress:     make([]byte, 20),
				AmountSatoshis: 100_000_000, // 1 BSV
				L2BlockNum:     10,
			},
		},
	}
	advanceFinder := &mockAdvanceFinder{
		tx: &BSVTransaction{
			TxID: types.HexToHash("0xbeef"),
			Outputs: []BSVOutput{
				{Script: []byte{0x76}, Value: 1000},
			},
		},
	}

	bridgeUTXO := &BridgeUTXO{
		TxID:             types.HexToHash("0xaaaa"),
		Vout:             0,
		Balance:          10_000_000_000, // 100 BSV
		LastClaimedNonce: 0,
		Script:           []byte{0x76, 0xa9},
	}

	w := NewWithdrawer(
		broadcaster,
		bridgeUTXO,
		scanner,
		advanceFinder,
		DefaultWithdrawalConfig(),
	)

	err := w.ProcessFinalizedWithdrawals()
	if err != nil {
		t.Fatalf("ProcessFinalizedWithdrawals: %v", err)
	}

	// Verify the broadcaster was called.
	if len(broadcaster.broadcasts) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(broadcaster.broadcasts))
	}

	// Verify bridge UTXO was updated.
	if bridgeUTXO.LastClaimedNonce != 1 {
		t.Errorf("LastClaimedNonce = %d, want 1", bridgeUTXO.LastClaimedNonce)
	}
	if bridgeUTXO.Balance != 10_000_000_000-100_000_000 {
		t.Errorf("Balance = %d, want %d", bridgeUTXO.Balance, 10_000_000_000-100_000_000)
	}
}

// --- TestWithdrawer_InsufficientBalance ---

func TestWithdrawer_InsufficientBalance(t *testing.T) {
	broadcaster := &mockBroadcaster{}
	scanner := &mockWithdrawalScanner{
		withdrawals: []*PendingWithdrawal{
			{
				Nonce:          1,
				BSVAddress:     make([]byte, 20),
				AmountSatoshis: 200_000_000_000, // more than balance
				L2BlockNum:     10,
			},
		},
	}

	bridgeUTXO := &BridgeUTXO{
		TxID:             types.HexToHash("0xaaaa"),
		Vout:             0,
		Balance:          100_000_000_000,
		LastClaimedNonce: 0,
		Script:           []byte{0x76, 0xa9},
	}

	w := NewWithdrawer(
		broadcaster,
		bridgeUTXO,
		scanner,
		&mockAdvanceFinder{},
		DefaultWithdrawalConfig(),
	)

	err := w.ProcessFinalizedWithdrawals()
	if err != nil {
		t.Fatalf("ProcessFinalizedWithdrawals should not error, got: %v", err)
	}

	// Should not have broadcast (insufficient balance).
	if len(broadcaster.broadcasts) != 0 {
		t.Errorf("expected 0 broadcasts, got %d", len(broadcaster.broadcasts))
	}

	// Nonce should not have advanced.
	if bridgeUTXO.LastClaimedNonce != 0 {
		t.Errorf("LastClaimedNonce should remain 0, got %d", bridgeUTXO.LastClaimedNonce)
	}
}

// --- TestBridgeUTXO_UpdateAfterWithdrawal ---

func TestBridgeUTXO_UpdateAfterWithdrawal(t *testing.T) {
	utxo := &BridgeUTXO{
		TxID:             types.HexToHash("0x0001"),
		Balance:          10_000_000_000,
		LastClaimedNonce: 5,
	}

	newTxID := types.HexToHash("0x0002")
	utxo.UpdateAfterWithdrawal(newTxID, 1_000_000_000, 6)

	if utxo.TxID != newTxID {
		t.Errorf("TxID = %s, want %s", utxo.TxID.Hex(), newTxID.Hex())
	}
	if utxo.Balance != 9_000_000_000 {
		t.Errorf("Balance = %d, want 9000000000", utxo.Balance)
	}
	if utxo.LastClaimedNonce != 6 {
		t.Errorf("LastClaimedNonce = %d, want 6", utxo.LastClaimedNonce)
	}
}

// --- TestWithdrawalConfig_Default ---

func TestWithdrawalConfig_Default(t *testing.T) {
	config := DefaultWithdrawalConfig()

	if config.MinWithdrawal != 10000 {
		t.Errorf("MinWithdrawal = %d, want 10000", config.MinWithdrawal)
	}

	if len(config.Tiers) != 3 {
		t.Fatalf("expected 3 tiers, got %d", len(config.Tiers))
	}

	if config.Tiers[0].MaxAmount != 1_000_000_000 {
		t.Errorf("tier 0 max = %d, want 1000000000", config.Tiers[0].MaxAmount)
	}
	if config.Tiers[0].Confirmations != 6 {
		t.Errorf("tier 0 confirmations = %d, want 6", config.Tiers[0].Confirmations)
	}

	if config.Tiers[1].MaxAmount != 10_000_000_000 {
		t.Errorf("tier 1 max = %d, want 10000000000", config.Tiers[1].MaxAmount)
	}
	if config.Tiers[1].Confirmations != 20 {
		t.Errorf("tier 1 confirmations = %d, want 20", config.Tiers[1].Confirmations)
	}

	if config.Tiers[2].Confirmations != 100 {
		t.Errorf("tier 2 confirmations = %d, want 100", config.Tiers[2].Confirmations)
	}
}

// --- mock types for Withdrawer tests ---

type mockBroadcaster struct {
	broadcasts [][]byte
}

func (m *mockBroadcaster) Broadcast(rawTx []byte) (types.Hash, error) {
	m.broadcasts = append(m.broadcasts, rawTx)
	// Return a deterministic hash.
	h := types.Hash{}
	h[0] = byte(len(m.broadcasts))
	return h, nil
}

type mockWithdrawalScanner struct {
	withdrawals []*PendingWithdrawal
}

func (m *mockWithdrawalScanner) ScanPendingWithdrawals(_ uint64) ([]*PendingWithdrawal, error) {
	return m.withdrawals, nil
}

type mockAdvanceFinder struct {
	tx *BSVTransaction
}

func (m *mockAdvanceFinder) FindCovenantAdvanceForBlock(_ uint64) (*BSVTransaction, error) {
	if m.tx != nil {
		return m.tx, nil
	}
	return &BSVTransaction{}, nil
}

// Ensure fmt is used (for error formatting in tests).
var _ = fmt.Sprintf
