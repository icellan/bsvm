package types

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/crypto"
)

// -- Hash and Address conversion tests --

func TestBytesToHash(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"nil", nil, "0x0000000000000000000000000000000000000000000000000000000000000000"},
		{"empty", []byte{}, "0x0000000000000000000000000000000000000000000000000000000000000000"},
		{"single byte", []byte{0x01}, "0x0000000000000000000000000000000000000000000000000000000000000001"},
		{"full 32 bytes", make([]byte, 32), "0x0000000000000000000000000000000000000000000000000000000000000000"},
		{"overflow truncates left", append([]byte{0xff}, make([]byte, 32)...), "0x0000000000000000000000000000000000000000000000000000000000000000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := BytesToHash(tt.in)
			if h.Hex() != tt.want {
				t.Errorf("BytesToHash(%x) = %s, want %s", tt.in, h.Hex(), tt.want)
			}
		})
	}
}

func TestBytesToAddress(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"nil", nil, "0x0000000000000000000000000000000000000000"},
		{"single byte", []byte{0xab}, "0x00000000000000000000000000000000000000ab"},
		{"full 20 bytes", make([]byte, 20), "0x0000000000000000000000000000000000000000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := BytesToAddress(tt.in)
			if a.Hex() != tt.want {
				t.Errorf("BytesToAddress(%x) = %s, want %s", tt.in, a.Hex(), tt.want)
			}
		})
	}
}

func TestHexToHash(t *testing.T) {
	h := HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	if h[31] != 1 {
		t.Errorf("HexToHash last byte = %d, want 1", h[31])
	}
	// Without prefix.
	h2 := HexToHash("0000000000000000000000000000000000000000000000000000000000000002")
	if h2[31] != 2 {
		t.Errorf("HexToHash without prefix last byte = %d, want 2", h2[31])
	}
}

func TestBSVHashFromHex_RoundTrip(t *testing.T) {
	// A known BSV txid string (display / big-endian form, 64 lowercase
	// hex chars, no 0x). Pulled from a regtest deploy and pinned here
	// so we exercise the full reverse.
	const canonical = "d1f7b5b4b4d33b7c6e6e1e1e1d1e1f20a1b2c3d4e5f60718293a4b5c6d7e8f90"

	h := BSVHashFromHex(canonical)

	// 1. The receiver's bytes should be the reverse of the hex decode.
	if hex.EncodeToString(h[:]) == canonical {
		t.Fatalf("BSVHashFromHex did not reverse: got %s, want reversed form", hex.EncodeToString(h[:]))
	}

	// 2. BSVString() must reproduce the original canonical form.
	if got := h.BSVString(); got != canonical {
		t.Fatalf("BSVString() = %s, want %s", got, canonical)
	}

	// 3. An 0x prefix must be tolerated and stripped.
	if h2 := BSVHashFromHex("0x" + canonical); h2 != h {
		t.Fatalf("BSVHashFromHex: 0x-prefixed form diverged from plain form")
	}
}

func TestBSVHashFromHex_ZeroOnBadInput(t *testing.T) {
	if h := BSVHashFromHex(""); h != (Hash{}) {
		t.Fatalf("BSVHashFromHex(\"\") should return zero hash")
	}
	if h := BSVHashFromHex("abcd"); h != (Hash{}) {
		t.Fatalf("BSVHashFromHex short hex should return zero hash")
	}
}

func TestBSVString_ZeroReturnsEmpty(t *testing.T) {
	var zero Hash
	if got := zero.BSVString(); got != "" {
		t.Fatalf("zero.BSVString() = %q, want empty", got)
	}
}

func TestBSVString_MatchesChainhash(t *testing.T) {
	// A non-zero Hash with a recognisable byte pattern.
	var h Hash
	for i := 0; i < HashLength; i++ {
		h[i] = byte(i)
	}
	// BSVString must return the 64-hex byte-reversed form (i.e. the
	// same string chainhash.NewHash(h[:]).String() would emit).
	want := "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
	if got := h.BSVString(); got != want {
		t.Fatalf("BSVString() = %s, want %s", got, want)
	}
}

func TestBSVHashFromHex_ChainhashCrossCheck(t *testing.T) {
	const canonical = "d1f7b5b4b4d33b7c6e6e1e1e1d1e1f20a1b2c3d4e5f60718293a4b5c6d7e8f90"
	h := BSVHashFromHex(canonical)

	ch, err := chainhash.NewHash(h[:])
	if err != nil {
		t.Fatalf("chainhash.NewHash: %v", err)
	}
	if got := ch.String(); got != canonical {
		t.Fatalf("chainhash.String(BSVHashFromHex(%q)) = %s, want %s", canonical, got, canonical)
	}
}

func TestHexToAddress(t *testing.T) {
	a := HexToAddress("0x000000000000000000000000000000000000dEaD")
	if a[18] != 0xde || a[19] != 0xad {
		t.Errorf("HexToAddress = %x, want ...dead", a[:])
	}
}

func TestHashBig(t *testing.T) {
	h := HexToHash("0x0000000000000000000000000000000000000000000000000000000000000100")
	b := h.Big()
	if b.Cmp(big.NewInt(256)) != 0 {
		t.Errorf("Hash.Big() = %v, want 256", b)
	}
}

func TestBigToHash(t *testing.T) {
	b := big.NewInt(256)
	h := BigToHash(b)
	if h[30] != 1 || h[31] != 0 {
		t.Errorf("BigToHash(256) = %x, want ...0100", h[:])
	}
}

func TestSetBytes(t *testing.T) {
	var h Hash
	h.SetBytes([]byte{0x01, 0x02})
	if h[30] != 0x01 || h[31] != 0x02 {
		t.Errorf("Hash.SetBytes([01,02]) = %x", h[:])
	}

	var a Address
	a.SetBytes([]byte{0xff})
	if a[19] != 0xff {
		t.Errorf("Address.SetBytes([ff]) = %x", a[:])
	}
}

func TestEmptyHashes(t *testing.T) {
	// Verify EmptyCodeHash matches keccak256 of empty data.
	empty := crypto.Keccak256Hash()
	if BytesToHash(empty[:]) != EmptyCodeHash {
		t.Errorf("EmptyCodeHash mismatch: computed %x, constant %x", empty, EmptyCodeHash)
	}
}

// -- Bloom filter tests --

func TestBloomAddAndTest(t *testing.T) {
	var b Bloom
	data := []byte("hello world")
	b.Add(data)
	if !b.Test(data) {
		t.Error("bloom filter should contain 'hello world' after Add")
	}
	// Non-existent data may or may not be present (false positives possible),
	// but we can verify the bloom is non-zero.
	zero := Bloom{}
	if b == zero {
		t.Error("bloom filter should not be zero after Add")
	}
}

func TestBloomOrBloom(t *testing.T) {
	var b1, b2 Bloom
	b1.Add([]byte("foo"))
	b2.Add([]byte("bar"))
	b1.OrBloom(b2)
	if !b1.Test([]byte("foo")) {
		t.Error("OR'd bloom should still contain 'foo'")
	}
	if !b1.Test([]byte("bar")) {
		t.Error("OR'd bloom should contain 'bar'")
	}
}

func TestBloomLookupFunc(t *testing.T) {
	var b Bloom
	data := []byte("test-topic")
	b.Add(data)
	if !BloomLookup(b, data) {
		t.Error("BloomLookup should return true for added data")
	}
}

func TestCreateBloomFromReceipts(t *testing.T) {
	addr := HexToAddress("0x1111111111111111111111111111111111111111")
	topic := HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	log := &Log{Address: addr, Topics: []Hash{topic}}
	receipt := &Receipt{Logs: []*Log{log}}
	bloom := CreateBloom([]*Receipt{receipt})
	if !bloom.Test(addr.Bytes()) {
		t.Error("bloom should contain the log address")
	}
	if !bloom.Test(topic.Bytes()) {
		t.Error("bloom should contain the log topic")
	}
}

// -- AccessList tests --

func TestAccessListStorageKeys(t *testing.T) {
	al := AccessList{
		{Address: HexToAddress("0x01"), StorageKeys: []Hash{{}, {}}},
		{Address: HexToAddress("0x02"), StorageKeys: []Hash{{}}},
	}
	if al.StorageKeys() != 3 {
		t.Errorf("AccessList.StorageKeys() = %d, want 3", al.StorageKeys())
	}
	empty := AccessList{}
	if empty.StorageKeys() != 0 {
		t.Errorf("empty AccessList.StorageKeys() = %d, want 0", empty.StorageKeys())
	}
}

// -- Transaction tests --

func TestNewTxCopiesInner(t *testing.T) {
	to := HexToAddress("0xdead")
	inner := &LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(1000),
		Gas:      21000,
		To:       &to,
		Value:    uint256.NewInt(100),
		Data:     []byte{0x01},
		V:        big.NewInt(27),
		R:        big.NewInt(1),
		S:        big.NewInt(1),
	}
	tx := NewTx(inner)

	// Mutate original; tx should be unaffected.
	inner.Nonce = 999
	if tx.Nonce() != 1 {
		t.Errorf("NewTx should copy inner data, got nonce %d", tx.Nonce())
	}
}

func TestTransactionTypeAccessors(t *testing.T) {
	to := HexToAddress("0xdead")
	legacyTx := NewTx(&LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1),
		Gas:      21000,
		To:       &to,
		Value:    uint256.NewInt(0),
		V:        big.NewInt(27),
		R:        big.NewInt(1),
		S:        big.NewInt(1),
	})
	if legacyTx.Type() != LegacyTxType {
		t.Errorf("Type() = %d, want %d", legacyTx.Type(), LegacyTxType)
	}

	alTx := NewTx(&AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    1,
		GasPrice: big.NewInt(1),
		Gas:      21000,
		To:       &to,
		Value:    uint256.NewInt(0),
		V:        big.NewInt(0),
		R:        big.NewInt(1),
		S:        big.NewInt(1),
	})
	if alTx.Type() != AccessListTxType {
		t.Errorf("Type() = %d, want %d", alTx.Type(), AccessListTxType)
	}

	dynTx := NewTx(&DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     2,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       21000,
		To:        &to,
		Value:     uint256.NewInt(0),
		V:         big.NewInt(0),
		R:         big.NewInt(1),
		S:         big.NewInt(1),
	})
	if dynTx.Type() != DynamicFeeTxType {
		t.Errorf("Type() = %d, want %d", dynTx.Type(), DynamicFeeTxType)
	}
}

func TestTransactionHash(t *testing.T) {
	to := HexToAddress("0xdead")
	tx := NewTx(&LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1),
		Gas:      21000,
		To:       &to,
		Value:    uint256.NewInt(0),
		V:        big.NewInt(27),
		R:        big.NewInt(1),
		S:        big.NewInt(1),
	})
	h1 := tx.Hash()
	h2 := tx.Hash()
	if h1 != h2 {
		t.Error("Hash() should be deterministic")
	}
	zero := Hash{}
	if h1 == zero {
		t.Error("Hash() should not be zero")
	}
}

// -- Signer roundtrip test --

func TestSignerRoundtrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(key.PublicKey)

	chainID := big.NewInt(1)
	signer := NewLondonSigner(chainID)

	to := HexToAddress("0xdead")

	// Test legacy tx roundtrip.
	t.Run("legacy EIP-155", func(t *testing.T) {
		tx, err := SignNewTx(key, signer, &LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(1000000000),
			Gas:      21000,
			To:       &to,
			Value:    uint256.NewInt(1000),
			Data:     nil,
		})
		if err != nil {
			t.Fatalf("SignNewTx: %v", err)
		}
		recovered, err := signer.Sender(tx)
		if err != nil {
			t.Fatalf("Sender: %v", err)
		}
		if recovered != BytesToAddress(expectedAddr[:]) {
			t.Errorf("sender mismatch: got %s, want %s", recovered.Hex(), BytesToAddress(expectedAddr[:]).Hex())
		}
	})

	// Test EIP-2930 access list tx roundtrip.
	t.Run("access list", func(t *testing.T) {
		tx, err := SignNewTx(key, signer, &AccessListTx{
			ChainID:    chainID,
			Nonce:      1,
			GasPrice:   big.NewInt(1000000000),
			Gas:        21000,
			To:         &to,
			Value:      uint256.NewInt(500),
			AccessList: AccessList{{Address: to, StorageKeys: []Hash{{}}}},
		})
		if err != nil {
			t.Fatalf("SignNewTx: %v", err)
		}
		recovered, err := signer.Sender(tx)
		if err != nil {
			t.Fatalf("Sender: %v", err)
		}
		if recovered != BytesToAddress(expectedAddr[:]) {
			t.Errorf("sender mismatch: got %s, want %s", recovered.Hex(), BytesToAddress(expectedAddr[:]).Hex())
		}
	})

	// Test EIP-1559 dynamic fee tx roundtrip.
	t.Run("dynamic fee", func(t *testing.T) {
		tx, err := SignNewTx(key, signer, &DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     2,
			GasTipCap: big.NewInt(1000000000),
			GasFeeCap: big.NewInt(2000000000),
			Gas:       21000,
			To:        &to,
			Value:     uint256.NewInt(250),
		})
		if err != nil {
			t.Fatalf("SignNewTx: %v", err)
		}
		recovered, err := signer.Sender(tx)
		if err != nil {
			t.Fatalf("Sender: %v", err)
		}
		if recovered != BytesToAddress(expectedAddr[:]) {
			t.Errorf("sender mismatch: got %s, want %s", recovered.Hex(), BytesToAddress(expectedAddr[:]).Hex())
		}
	})
}

func TestHomesteadSignerRoundtrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(key.PublicKey)

	signer := HomesteadSigner{}
	to := HexToAddress("0xdead")

	tx, err := SignNewTx(key, signer, &LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1000000000),
		Gas:      21000,
		To:       &to,
		Value:    uint256.NewInt(1000),
	})
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}
	recovered, err := signer.Sender(tx)
	if err != nil {
		t.Fatalf("Sender: %v", err)
	}
	if recovered != BytesToAddress(expectedAddr[:]) {
		t.Errorf("sender mismatch: got %s, want %s", recovered.Hex(), BytesToAddress(expectedAddr[:]).Hex())
	}
}

// -- Receipt tests --

func TestReceiptsLen(t *testing.T) {
	rs := Receipts{
		{Status: ReceiptStatusSuccessful},
		{Status: ReceiptStatusFailed},
	}
	if rs.Len() != 2 {
		t.Errorf("Receipts.Len() = %d, want 2", rs.Len())
	}
}

// DeriveSha tests have been moved to pkg/mpt/trie_test.go. The
// canonical DeriveSha implementation lives in pkg/mpt/derive.go.

func TestMustSignNewTxPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustSignNewTx should panic on nil key")
		}
	}()
	MustSignNewTx(nil, HomesteadSigner{}, &LegacyTx{
		GasPrice: big.NewInt(1),
		Value:    uint256.NewInt(0),
	})
}

func TestLatestSignerForChainID(t *testing.T) {
	s := LatestSignerForChainID(big.NewInt(1))
	if s == nil {
		t.Error("LatestSignerForChainID should not return nil")
	}
	if s.ChainID().Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ChainID() = %v, want 1", s.ChainID())
	}
}

// -- Receipt rollback tests --

func TestReceipt_RolledBackFields(t *testing.T) {
	r := &Receipt{
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: 21000,
		Logs:              []*Log{},
	}

	// Default values.
	if r.RolledBack {
		t.Error("RolledBack should default to false")
	}
	if r.RolledBackAtBlock != 0 {
		t.Errorf("RolledBackAtBlock should default to 0, got %d", r.RolledBackAtBlock)
	}

	// Set values.
	r.RolledBack = true
	r.RolledBackAtBlock = 42

	if !r.RolledBack {
		t.Error("RolledBack should be true after setting")
	}
	if r.RolledBackAtBlock != 42 {
		t.Errorf("RolledBackAtBlock should be 42, got %d", r.RolledBackAtBlock)
	}
}

func TestReceipt_RolledBackDoesNotAffectRLP(t *testing.T) {
	// Create two identical receipts, one with rollback fields set.
	r1 := &Receipt{
		Type:              LegacyTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: 21000,
		Bloom:             Bloom{},
		Logs:              []*Log{},
		RolledBack:        false,
		RolledBackAtBlock: 0,
	}

	r2 := &Receipt{
		Type:              LegacyTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: 21000,
		Bloom:             Bloom{},
		Logs:              []*Log{},
		RolledBack:        true,
		RolledBackAtBlock: 99,
	}

	// Encode both via EncodeIndex (consensus encoding).
	var buf1, buf2 bytes.Buffer
	rs1 := Receipts{r1}
	rs2 := Receipts{r2}
	rs1.EncodeIndex(0, &buf1)
	rs2.EncodeIndex(0, &buf2)

	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("consensus RLP encoding should be identical regardless of rollback fields")
	}
}
