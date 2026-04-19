package shard

import (
	"encoding/hex"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

func TestHardhatDefaultAccounts_Count(t *testing.T) {
	got := HardhatDefaultAccounts()
	if len(got) != 10 {
		t.Fatalf("HardhatDefaultAccounts: expected 10 entries, got %d", len(got))
	}
}

func TestHardhatDefaultAccounts_WellKnownAddresses(t *testing.T) {
	accounts := HardhatDefaultAccounts()
	wantFirst := types.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	if accounts[0].Address != wantFirst {
		t.Errorf("account #0: expected %s, got %s", wantFirst.Hex(), accounts[0].Address.Hex())
	}

	wantSecond := types.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	if accounts[1].Address != wantSecond {
		t.Errorf("account #1: expected %s, got %s", wantSecond.Hex(), accounts[1].Address.Hex())
	}

	// Account #0's private key is the well-known Hardhat #0 secret that
	// every Solidity developer has memorised. Any drift here breaks
	// every existing Hardhat / Foundry test suite pointed at our
	// devnet.
	wantPriv := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	if accounts[0].PrivateKey != wantPriv {
		t.Errorf("account #0 private key mismatch:\n  want %s\n  got  %s",
			wantPriv, accounts[0].PrivateKey)
	}
}

func TestHardhatPrefundAlloc_AllAccountsFunded(t *testing.T) {
	oneThousandWBSV := new(uint256.Int).Mul(
		uint256.NewInt(1000),
		new(uint256.Int).Exp(uint256.NewInt(10), uint256.NewInt(18)),
	)

	alloc := HardhatPrefundAlloc(oneThousandWBSV)
	if len(alloc) != 10 {
		t.Fatalf("expected 10 allocations, got %d", len(alloc))
	}

	for _, a := range HardhatDefaultAccounts() {
		entry, ok := alloc[a.Address]
		if !ok {
			t.Errorf("account %s not in alloc", a.Address.Hex())
			continue
		}
		if entry.Balance.Cmp(oneThousandWBSV) != 0 {
			t.Errorf("account %s: expected balance %s, got %s",
				a.Address.Hex(), oneThousandWBSV, entry.Balance)
		}
	}
}

func TestHardhatPrefundAlloc_BalancesAreDistinct(t *testing.T) {
	// Regression: early versions of HardhatPrefundAlloc shared the same
	// *uint256.Int pointer across every entry, so bumping one account's
	// balance at runtime would silently change every other account too.
	// Each entry must hold its own pointer.
	base := new(uint256.Int).SetUint64(100)
	alloc := HardhatPrefundAlloc(base)

	accounts := HardhatDefaultAccounts()
	firstAddr := accounts[0].Address
	secondAddr := accounts[1].Address

	alloc[firstAddr].Balance.SetUint64(999)
	if alloc[secondAddr].Balance.Uint64() != 100 {
		t.Errorf("balance pointers aliased: second account leaked first account's mutation")
	}
}

func TestDevnetGovernanceKey_CompressedPubKey(t *testing.T) {
	pub, err := DevnetGovernanceKey()
	if err != nil {
		t.Fatalf("DevnetGovernanceKey: unexpected error: %v", err)
	}
	if len(pub) != 33 {
		t.Fatalf("expected 33-byte compressed pubkey, got %d bytes", len(pub))
	}
	if pub[0] != 0x02 && pub[0] != 0x03 {
		t.Errorf("expected compressed pubkey prefix 0x02 or 0x03, got 0x%02x", pub[0])
	}
}

func TestDevnetGovernanceKey_DeterministicAcrossCalls(t *testing.T) {
	// Every node in the devnet must derive the same pubkey. Rerunning
	// the function should give byte-identical output.
	first, err := DevnetGovernanceKey()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := DevnetGovernanceKey()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if hex.EncodeToString(first) != hex.EncodeToString(second) {
		t.Errorf("non-deterministic pubkey: first=%x second=%x", first, second)
	}
}
