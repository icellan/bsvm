package shard

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// sampleManifest returns a fully-populated manifest for round-trip tests.
// Uses deterministic, non-trivial values so encoder/decoder bugs that
// drop or confuse fields show up as visible diffs.
func sampleManifest() *GenesisManifest {
	return &GenesisManifest{
		Version:          GenesisManifestVersion,
		ChainID:          31337,
		GasLimit:         30_000_000,
		VerificationMode: "fri",
		SP1VerifyingKey:  hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32)),
		Governance: GenesisGovernance{
			Mode:      "single_key",
			Threshold: 0,
			Keys:      []string{hex.EncodeToString(append([]byte{0x02}, bytes.Repeat([]byte{0xcd}, 32)...))},
		},
		Alloc: map[string]GenesisAllocEntry{
			"f39fd6e51aad88f6f4ce6ab8827279cfffb92266": {
				BalanceWei: "1000000000000000000000",
				Nonce:      0,
			},
			"1111111111111111111111111111111111111111": {
				BalanceWei: "42",
				Nonce:      7,
				Code:       "600160005260206000f3",
				Storage: map[string]string{
					"0000000000000000000000000000000000000000000000000000000000000001": "000000000000000000000000000000000000000000000000000000000000002a",
				},
			},
		},
		CovenantSats: 10000,
		Timestamp:    1_700_000_000,
	}
}

func TestEncodeDecodeManifest_RoundTrip(t *testing.T) {
	orig := sampleManifest()
	data, err := EncodeManifest(orig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Magic must be first 5 bytes.
	if string(data[:5]) != GenesisManifestMagic {
		t.Fatalf("magic prefix mismatch: got %q", data[:5])
	}

	got, err := DecodeManifest(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.ChainID != orig.ChainID {
		t.Errorf("ChainID mismatch: got %d, want %d", got.ChainID, orig.ChainID)
	}
	if got.GasLimit != orig.GasLimit {
		t.Errorf("GasLimit mismatch: got %d, want %d", got.GasLimit, orig.GasLimit)
	}
	if got.VerificationMode != orig.VerificationMode {
		t.Errorf("VerificationMode mismatch: got %q, want %q", got.VerificationMode, orig.VerificationMode)
	}
	if got.SP1VerifyingKey != orig.SP1VerifyingKey {
		t.Errorf("SP1VerifyingKey mismatch: got %q, want %q", got.SP1VerifyingKey, orig.SP1VerifyingKey)
	}
	if got.Governance.Mode != orig.Governance.Mode {
		t.Errorf("Governance.Mode mismatch")
	}
	if len(got.Alloc) != len(orig.Alloc) {
		t.Errorf("Alloc length mismatch: got %d, want %d", len(got.Alloc), len(orig.Alloc))
	}
	for addr, origEntry := range orig.Alloc {
		gotEntry, ok := got.Alloc[addr]
		if !ok {
			t.Errorf("alloc missing %s", addr)
			continue
		}
		if gotEntry.BalanceWei != origEntry.BalanceWei {
			t.Errorf("alloc %s balance mismatch: got %q, want %q", addr, gotEntry.BalanceWei, origEntry.BalanceWei)
		}
		if gotEntry.Nonce != origEntry.Nonce {
			t.Errorf("alloc %s nonce mismatch", addr)
		}
		if gotEntry.Code != origEntry.Code {
			t.Errorf("alloc %s code mismatch", addr)
		}
		if len(gotEntry.Storage) != len(origEntry.Storage) {
			t.Errorf("alloc %s storage length mismatch", addr)
		}
	}
}

func TestDecodeManifest_MissingMagic(t *testing.T) {
	// 40 bytes of garbage, no magic.
	bogus := bytes.Repeat([]byte{0xff}, 40)
	if _, err := DecodeManifest(bogus); err == nil {
		t.Fatal("expected magic mismatch error, got nil")
	}
}

func TestDecodeManifest_TooShort(t *testing.T) {
	if _, err := DecodeManifest([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected too-short error, got nil")
	}
}

func TestDecodeManifest_TruncatedPayload(t *testing.T) {
	// Valid magic + length claiming 100 bytes but only 5 bytes of payload.
	bad := make([]byte, 0)
	bad = append(bad, []byte(GenesisManifestMagic)...)
	bad = append(bad, 0x00, 0x00, 0x00, 0x64) // length = 100
	bad = append(bad, 0x01, 0x02, 0x03, 0x04, 0x05)
	if _, err := DecodeManifest(bad); err == nil {
		t.Fatal("expected truncated-payload error, got nil")
	}
}

func TestDecodeManifest_MalformedJSON(t *testing.T) {
	bad := make([]byte, 0)
	bad = append(bad, []byte(GenesisManifestMagic)...)
	bad = append(bad, 0x00, 0x00, 0x00, 0x04)
	bad = append(bad, 'n', 'u', 'l', '?')
	if _, err := DecodeManifest(bad); err == nil {
		t.Fatal("expected JSON parse error, got nil")
	}
}

func TestBuildAlloc(t *testing.T) {
	m := &GenesisManifest{
		Alloc: map[string]GenesisAllocEntry{
			"1111111111111111111111111111111111111111": {
				BalanceWei: "1000000000000000000000",
				Nonce:      5,
			},
			"2222222222222222222222222222222222222222": {
				BalanceWei: "0",
			},
		},
	}
	got, err := m.BuildAlloc()
	if err != nil {
		t.Fatalf("BuildAlloc: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(got))
	}
	addr1 := types.HexToAddress("0x1111111111111111111111111111111111111111")
	acc1, ok := got[addr1]
	if !ok {
		t.Fatal("missing addr1")
	}
	expectBal := new(uint256.Int)
	if err := expectBal.SetFromDecimal("1000000000000000000000"); err != nil {
		t.Fatal(err)
	}
	if acc1.Balance == nil || acc1.Balance.Cmp(expectBal) != 0 {
		t.Errorf("addr1 balance mismatch: got %v, want %v", acc1.Balance, expectBal)
	}
	if acc1.Nonce != 5 {
		t.Errorf("addr1 nonce = %d, want 5", acc1.Nonce)
	}
}

func TestBuildAlloc_InvalidBalance(t *testing.T) {
	m := &GenesisManifest{
		Alloc: map[string]GenesisAllocEntry{
			"1111111111111111111111111111111111111111": {BalanceWei: "not-a-number"},
		},
	}
	if _, err := m.BuildAlloc(); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestToGovernanceConfig_AllModes(t *testing.T) {
	key1 := hex.EncodeToString(append([]byte{0x02}, bytes.Repeat([]byte{0x01}, 32)...))
	key2 := hex.EncodeToString(append([]byte{0x03}, bytes.Repeat([]byte{0x02}, 32)...))

	cases := []struct {
		name    string
		manif   GenesisManifest
		wantMod covenant.GovernanceMode
		wantKC  int
	}{
		{
			name:    "none",
			manif:   GenesisManifest{Governance: GenesisGovernance{Mode: "none"}},
			wantMod: covenant.GovernanceNone,
			wantKC:  0,
		},
		{
			name:    "single_key",
			manif:   GenesisManifest{Governance: GenesisGovernance{Mode: "single_key", Keys: []string{key1}}},
			wantMod: covenant.GovernanceSingleKey,
			wantKC:  1,
		},
		{
			name:    "multisig",
			manif:   GenesisManifest{Governance: GenesisGovernance{Mode: "multisig", Threshold: 2, Keys: []string{key1, key2}}},
			wantMod: covenant.GovernanceMultiSig,
			wantKC:  2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gc, err := tc.manif.ToGovernanceConfig()
			if err != nil {
				t.Fatalf("ToGovernanceConfig: %v", err)
			}
			if gc.Mode != tc.wantMod {
				t.Errorf("mode = %v, want %v", gc.Mode, tc.wantMod)
			}
			if len(gc.Keys) != tc.wantKC {
				t.Errorf("keys count = %d, want %d", len(gc.Keys), tc.wantKC)
			}
		})
	}
}

func TestToGovernanceConfig_UnknownMode(t *testing.T) {
	m := &GenesisManifest{Governance: GenesisGovernance{Mode: "weird"}}
	if _, err := m.ToGovernanceConfig(); err == nil {
		t.Fatal("expected error for unknown governance mode")
	}
}

func TestToVerificationMode_AllModes(t *testing.T) {
	cases := []struct {
		in   string
		want covenant.VerificationMode
	}{
		{"fri", covenant.VerifyFRI},
		{"groth16", covenant.VerifyGroth16},
		{"groth16-wa", covenant.VerifyGroth16WA},
		{"devkey", covenant.VerifyDevKey},
	}
	for _, tc := range cases {
		m := &GenesisManifest{VerificationMode: tc.in}
		got, err := m.ToVerificationMode()
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.in, got, tc.want)
		}
	}
	// unknown mode
	m := &GenesisManifest{VerificationMode: "ml-dsa"}
	if _, err := m.ToVerificationMode(); err == nil {
		t.Fatal("expected error for unknown verification mode")
	}
}

func TestAllocFromMap_RoundTripsThroughManifest(t *testing.T) {
	addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	bal := new(uint256.Int)
	if err := bal.SetFromDecimal("12345"); err != nil {
		t.Fatal(err)
	}
	in := map[types.Address]block.GenesisAccount{
		addr: {
			Balance: bal,
			Nonce:   3,
		},
	}
	serialised := AllocFromMap(in)
	if len(serialised) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(serialised))
	}
	m := &GenesisManifest{Alloc: serialised}
	got, err := m.BuildAlloc()
	if err != nil {
		t.Fatalf("BuildAlloc: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	acc, ok := got[addr]
	if !ok {
		t.Fatal("missing address after round-trip")
	}
	if acc.Nonce != 3 {
		t.Errorf("nonce = %d, want 3", acc.Nonce)
	}
	if acc.Balance.Cmp(bal) != 0 {
		t.Errorf("balance = %v, want %v", acc.Balance, bal)
	}
}
