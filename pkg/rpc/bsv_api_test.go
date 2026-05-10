package rpc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/types"
)

type bridgeSnapshotProviderStub struct {
	totalLockedSats uint64
	subCovenants    int
	deposits        []*bridge.Deposit
	withdrawals     []WithdrawalSummary
}

func (s *bridgeSnapshotProviderStub) TotalLockedSatoshis() uint64 {
	return s.totalLockedSats
}

func (s *bridgeSnapshotProviderStub) SubCovenantCount() int {
	return s.subCovenants
}

func (s *bridgeSnapshotProviderStub) Deposits(_, _ uint64) []*bridge.Deposit {
	return s.deposits
}

func (s *bridgeSnapshotProviderStub) Withdrawals(_, _ uint64) []WithdrawalSummary {
	return s.withdrawals
}

func TestBsvAPI_Spec15BridgeAliases(t *testing.T) {
	txid := strings.Repeat("12", 32)
	l2Addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	deposit := bridge.NewDepositWithVout(types.BSVHashFromHex(txid), 2, 123, l2Addr, 50_000)
	deposit.Confirmed = true

	api := &BsvAPI{}
	api.SetBridgeProvider(&bridgeSnapshotProviderStub{
		totalLockedSats: 87_000,
		subCovenants:    3,
		deposits:        []*bridge.Deposit{deposit},
		withdrawals: []WithdrawalSummary{{
			Nonce:        7,
			AmountWei:    "420000000000000",
			BsvAddress:   "76a914001122334455667788990011223344556677889988ac",
			L2TxHash:     "0xabc",
			Claimed:      true,
			ClaimBsvTxid: strings.Repeat("34", 32),
			CsvRemaining: 12,
		}},
	})

	status := api.BridgeStatus()
	if got, want := status["totalLocked"], "870000000000000"; got != want {
		t.Errorf("totalLocked = %v, want %v", got, want)
	}
	if got := status["totalLockedWei"]; got != status["totalLocked"] {
		t.Errorf("totalLockedWei = %v, want alias totalLocked %v", got, status["totalLocked"])
	}
	if got, want := status["totalSupply"], "870000000000000"; got != want {
		t.Errorf("totalSupply = %v, want %v", got, want)
	}
	for _, key := range []string{"rateLimitPeriod", "currentPeriodWithdrawals", "maxPerPeriod"} {
		if _, ok := status[key]; !ok {
			t.Errorf("BridgeStatus missing spec-15 alias %q", key)
		}
	}

	deposits := api.GetDeposits(0, 0)
	if len(deposits) != 1 {
		t.Fatalf("GetDeposits len = %d, want 1", len(deposits))
	}
	gotDep := deposits[0]
	if gotDep["bsvTxId"] != txid || gotDep["bsvTxid"] != txid {
		t.Errorf("deposit txid aliases = %v/%v, want %s", gotDep["bsvTxId"], gotDep["bsvTxid"], txid)
	}
	if gotDep["amount"] != gotDep["l2WeiAmount"] {
		t.Errorf("deposit amount alias = %v, want l2WeiAmount %v", gotDep["amount"], gotDep["l2WeiAmount"])
	}
	if gotDep["credited"] != true {
		t.Errorf("deposit credited = %v, want true", gotDep["credited"])
	}
	for _, key := range []string{"bsvConfirmations", "l2BlockNumber"} {
		if _, ok := gotDep[key]; !ok {
			t.Errorf("deposit missing spec-15 alias %q", key)
		}
	}

	withdrawals := api.GetWithdrawals(0, 0)
	if len(withdrawals) != 1 {
		t.Fatalf("GetWithdrawals len = %d, want 1", len(withdrawals))
	}
	gotWithdrawal := withdrawals[0]
	if gotWithdrawal["amount"] != gotWithdrawal["amountWei"] {
		t.Errorf("withdrawal amount alias = %v, want amountWei %v", gotWithdrawal["amount"], gotWithdrawal["amountWei"])
	}
	if gotWithdrawal["csvBlocksRemaining"] != gotWithdrawal["csvRemaining"] {
		t.Errorf("csvBlocksRemaining = %v, want csvRemaining %v",
			gotWithdrawal["csvBlocksRemaining"], gotWithdrawal["csvRemaining"])
	}
}

// mockWithdrawalStore implements WithdrawalStore for testing.
type mockWithdrawalStore struct {
	proofs map[uint64]*WithdrawalProofData
}

func newMockWithdrawalStore() *mockWithdrawalStore {
	return &mockWithdrawalStore{
		proofs: make(map[uint64]*WithdrawalProofData),
	}
}

func (m *mockWithdrawalStore) GetWithdrawalProof(nonce uint64) (*WithdrawalProofData, error) {
	proof, ok := m.proofs[nonce]
	if !ok {
		return nil, nil
	}
	return proof, nil
}

func TestBuildWithdrawalClaim_PendingProof(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// No withdrawal store set -- should return pending_proof.
	result, err := ts.server.BsvAPI().BuildWithdrawalClaim(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		100000,
		1,
	)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaim failed: %v", err)
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map[string]interface{}", result)
	}

	if m["status"] != "pending_proof" {
		t.Errorf("status = %v, want pending_proof", m["status"])
	}
	if m["withdrawalHash"] == nil || m["withdrawalHash"] == "" {
		t.Error("withdrawalHash should be set")
	}
	if m["unsignedTx"] != nil {
		t.Errorf("unsignedTx should be nil for pending_proof, got %v", m["unsignedTx"])
	}
	if m["merkleProof"] != nil {
		t.Errorf("merkleProof should be nil for pending_proof, got %v", m["merkleProof"])
	}
	if m["withdrawalRoot"] != nil {
		t.Errorf("withdrawalRoot should be nil for pending_proof, got %v", m["withdrawalRoot"])
	}

	// Also test with a store that returns no proof for the given nonce.
	store := newMockWithdrawalStore()
	ts.server.BsvAPI().SetWithdrawalStore(store)

	result, err = ts.server.BsvAPI().BuildWithdrawalClaim(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		100000,
		42,
	)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaim failed: %v", err)
	}

	m = result.(map[string]interface{})
	if m["status"] != "pending_proof" {
		t.Errorf("status = %v, want pending_proof (store has no proof for nonce 42)", m["status"])
	}
}

func TestBuildWithdrawalClaim_WithProof(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	store := newMockWithdrawalStore()
	var root [32]byte
	root[0] = 0xab
	root[31] = 0xcd
	store.proofs[1] = &WithdrawalProofData{
		Root:        root,
		Proof:       [][]byte{{0x01, 0x02}, {0x03, 0x04}},
		LeafIndex:   0,
		BlockNumber: 5,
	}
	ts.server.BsvAPI().SetWithdrawalStore(store)

	result, err := ts.server.BsvAPI().BuildWithdrawalClaim(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		100000,
		1,
	)
	if err != nil {
		t.Fatalf("BuildWithdrawalClaim failed: %v", err)
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map[string]interface{}", result)
	}

	if m["status"] != "proven" {
		t.Errorf("status = %v, want proven", m["status"])
	}
	if m["withdrawalHash"] == nil || m["withdrawalHash"] == "" {
		t.Error("withdrawalHash should be set")
	}
	if m["withdrawalRoot"] == nil {
		t.Error("withdrawalRoot should be set for proven withdrawal")
	}
	if m["blockNumber"] != EncodeUint64(5) {
		t.Errorf("blockNumber = %v, want %s", m["blockNumber"], EncodeUint64(5))
	}
	if m["leafIndex"] != EncodeUint64(0) {
		t.Errorf("leafIndex = %v, want %s", m["leafIndex"], EncodeUint64(0))
	}

	// Check Merkle proof.
	proof, ok := m["merkleProof"].([]string)
	if !ok {
		t.Fatalf("merkleProof type = %T, want []string", m["merkleProof"])
	}
	if len(proof) != 2 {
		t.Fatalf("merkleProof length = %d, want 2", len(proof))
	}
	if proof[0] != "0x0102" {
		t.Errorf("merkleProof[0] = %s, want 0x0102", proof[0])
	}
	if proof[1] != "0x0304" {
		t.Errorf("merkleProof[1] = %s, want 0x0304", proof[1])
	}

	// Check unsigned tx template.
	unsignedTx, ok := m["unsignedTx"].(map[string]interface{})
	if !ok {
		t.Fatalf("unsignedTx type = %T, want map[string]interface{}", m["unsignedTx"])
	}
	if unsignedTx["version"] != 1 {
		t.Errorf("unsignedTx version = %v, want 1", unsignedTx["version"])
	}
	if unsignedTx["satoshis"] != EncodeUint64(100000) {
		t.Errorf("unsignedTx satoshis = %v, want %s", unsignedTx["satoshis"], EncodeUint64(100000))
	}
}

func TestBuildWithdrawalClaim_InvalidAddress(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	tests := []struct {
		name    string
		address string
		wantErr string
	}{
		{
			name:    "not hex",
			address: "not-hex-at-all",
			wantErr: "invalid bsv address hex",
		},
		{
			name:    "too short",
			address: "0xaabb",
			wantErr: "bsv address must be 20 bytes",
		},
		{
			name:    "too long",
			address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb",
			wantErr: "bsv address must be 20 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ts.server.BsvAPI().BuildWithdrawalClaim(tc.address, 100000, 1)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if got := fmt.Sprint(err); !containsSubstring(got, tc.wantErr) {
				t.Errorf("error = %q, want containing %q", got, tc.wantErr)
			}
		})
	}
}

func TestBuildWithdrawalClaim_ZeroAmount(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	_, err := ts.server.BsvAPI().BuildWithdrawalClaim(
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		0,
		1,
	)
	if err == nil {
		t.Fatal("expected error for zero amount, got nil")
	}
	if got := fmt.Sprint(err); !containsSubstring(got, "satoshi amount must be greater than zero") {
		t.Errorf("error = %q, want containing 'satoshi amount must be greater than zero'", got)
	}
}

// containsSubstring reports whether s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
