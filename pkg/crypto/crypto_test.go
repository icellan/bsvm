package crypto

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestKeccak256Empty(t *testing.T) {
	// keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
	expected := hexToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	result := Keccak256([]byte{})
	if !bytes.Equal(result, expected) {
		t.Errorf("Keccak256 empty: got %x, want %x", result, expected)
	}
}

func TestKeccak256Hello(t *testing.T) {
	// keccak256("hello") = 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
	expected := hexToBytes("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
	result := Keccak256([]byte("hello"))
	if !bytes.Equal(result, expected) {
		t.Errorf("Keccak256 hello: got %x, want %x", result, expected)
	}
}

func TestKeccak256MultipleInputs(t *testing.T) {
	// Concatenated input should equal single input
	single := Keccak256([]byte("helloworld"))
	multi := Keccak256([]byte("hello"), []byte("world"))
	if !bytes.Equal(single, multi) {
		t.Errorf("Keccak256 multi-input mismatch: single=%x, multi=%x", single, multi)
	}
}

func TestKeccak256Hash(t *testing.T) {
	expected := hexToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	result := Keccak256Hash([]byte{})
	if !bytes.Equal(result[:], expected) {
		t.Errorf("Keccak256Hash empty: got %x, want %x", result, expected)
	}
}

func TestCreateAddress(t *testing.T) {
	tests := []struct {
		name     string
		sender   string
		nonce    uint64
		expected string
	}{
		{
			// Known Ethereum test vector: sender 0x0000...0000, nonce 0
			name:     "zero sender nonce 0",
			sender:   "0000000000000000000000000000000000000000",
			nonce:    0,
			expected: "bd770416a3345f91e4b34576cb804a576fa48eb1",
		},
		{
			// Another known vector
			name:     "typical address nonce 0",
			sender:   "6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0",
			nonce:    0,
			expected: "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d",
		},
		{
			// Nonce = 1
			name:     "typical address nonce 1",
			sender:   "6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0",
			nonce:    1,
			expected: "343c43a37d37dff08ae8c4a11544c718abb4fcf8",
		},
		{
			// High nonce
			name:     "typical address nonce 256",
			sender:   "6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0",
			nonce:    256,
			expected: "3837c1ae70354f670550c746580199ac6a73cb0a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sender [20]byte
			copy(sender[:], hexToBytes(tt.sender))
			result := CreateAddress(sender, tt.nonce)
			expected := hexToBytes(tt.expected)
			if !bytes.Equal(result[:], expected) {
				t.Errorf("CreateAddress(%s, %d): got %x, want %x", tt.sender, tt.nonce, result, expected)
			}
		})
	}
}

func TestCreateAddress2(t *testing.T) {
	tests := []struct {
		name         string
		sender       string
		salt         string
		initCodeHash string
		expected     string
	}{
		{
			// EIP-1014 example 0: address=0x00..00, salt=0x00..00, init_code=0x00
			name:         "zero sender with 0x00 initcode",
			sender:       "0000000000000000000000000000000000000000",
			salt:         "0000000000000000000000000000000000000000000000000000000000000000",
			initCodeHash: "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
			expected:     "4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38",
		},
		{
			// EIP-1014 example 2: address=0xdeadbeef00..00, salt with 0xfeed, init_code=0x00
			name:         "deadbeef sender with feed salt",
			sender:       "deadbeef00000000000000000000000000000000",
			salt:         "000000000000000000000000feed000000000000000000000000000000000000",
			initCodeHash: "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
			expected:     "d04116cdd17bebe565eb2422f2497e06cc1c9833",
		},
		{
			// EIP-1014 example 3: address=0x00..00, salt=0x00..00, init_code=0xdeadbeef
			name:         "zero sender with deadbeef initcode",
			sender:       "0000000000000000000000000000000000000000",
			salt:         "0000000000000000000000000000000000000000000000000000000000000000",
			initCodeHash: "d4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1",
			expected:     "70f2b2914a2a4b783faefb75f459a580616fcb5e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sender [20]byte
			var salt [32]byte
			copy(sender[:], hexToBytes(tt.sender))
			copy(salt[:], hexToBytes(tt.salt))
			initCodeHash := hexToBytes(tt.initCodeHash)
			result := CreateAddress2(sender, salt, initCodeHash)
			expected := hexToBytes(tt.expected)
			if !bytes.Equal(result[:], expected) {
				t.Errorf("CreateAddress2: got %x, want %x", result, expected)
			}
		})
	}
}

func TestSignAndEcrecover(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := Keccak256([]byte("test message"))
	sig, err := Sign(msg, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != 65 {
		t.Fatalf("signature length: got %d, want 65", len(sig))
	}

	// Recover the public key
	pub, err := Ecrecover(msg, sig)
	if err != nil {
		t.Fatalf("Ecrecover failed: %v", err)
	}

	// Derive address from recovered key and original key
	recoveredPub, err := SigToPub(msg, sig)
	if err != nil {
		t.Fatalf("SigToPub failed: %v", err)
	}

	originalAddr := PubkeyToAddress(key.PublicKey)
	recoveredAddr := PubkeyToAddress(*recoveredPub)

	if originalAddr != recoveredAddr {
		t.Errorf("address mismatch: original=%x, recovered=%x", originalAddr, recoveredAddr)
	}

	// Verify the uncompressed public key format
	if len(pub) != 65 || pub[0] != 0x04 {
		t.Errorf("recovered pubkey has wrong format: len=%d, prefix=%x", len(pub), pub[0])
	}
}

func TestVerifySignature(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := Keccak256([]byte("verify test"))
	sig, err := Sign(msg, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// VerifySignature expects 64-byte [R || S] (no V)
	if !VerifySignature(CompressPubkey(&key.PublicKey), msg, sig[:64]) {
		t.Error("VerifySignature failed for compressed pubkey with valid signature")
	}

	// Verify with wrong message fails
	wrongMsg := Keccak256([]byte("wrong message"))
	if VerifySignature(CompressPubkey(&key.PublicKey), wrongMsg, sig[:64]) {
		t.Error("VerifySignature should fail for wrong message")
	}
}

func TestPubkeyToAddress(t *testing.T) {
	// Known private key and corresponding address
	// Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
	// (Hardhat account #0)
	// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
	privBytes := hexToBytes("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	key, err := ToECDSA(privBytes)
	if err != nil {
		t.Fatalf("ToECDSA failed: %v", err)
	}

	addr := PubkeyToAddress(key.PublicKey)
	expectedAddr := hexToBytes("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	if !bytes.Equal(addr[:], expectedAddr) {
		t.Errorf("PubkeyToAddress: got %x, want %x", addr, expectedAddr)
	}
}

func TestToECDSAAndFromECDSA(t *testing.T) {
	privBytes := hexToBytes("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	key, err := ToECDSA(privBytes)
	if err != nil {
		t.Fatalf("ToECDSA failed: %v", err)
	}

	exported := FromECDSA(key)
	if !bytes.Equal(exported, privBytes) {
		t.Errorf("FromECDSA roundtrip failed: got %x, want %x", exported, privBytes)
	}
}

func TestToECDSAInvalid(t *testing.T) {
	// Wrong length
	_, err := ToECDSA([]byte{1, 2, 3})
	if err == nil {
		t.Error("ToECDSA should fail for wrong length")
	}

	// Zero key
	_, err = ToECDSA(make([]byte, 32))
	if err == nil {
		t.Error("ToECDSA should fail for zero key")
	}
}

func TestCompressDecompressPubkey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	compressed := CompressPubkey(&key.PublicKey)
	if len(compressed) != 33 {
		t.Fatalf("compressed pubkey length: got %d, want 33", len(compressed))
	}

	decompressed, err := DecompressPubkey(compressed)
	if err != nil {
		t.Fatalf("DecompressPubkey failed: %v", err)
	}

	if key.PublicKey.X.Cmp(decompressed.X) != 0 || key.PublicKey.Y.Cmp(decompressed.Y) != 0 {
		t.Error("compress/decompress roundtrip failed")
	}
}

func TestValidateSignatureValues(t *testing.T) {
	secp256k1N, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	halfN := new(big.Int).Div(secp256k1N, big.NewInt(2))
	one := big.NewInt(1)
	zero := big.NewInt(0)

	tests := []struct {
		name      string
		v         byte
		r         *big.Int
		s         *big.Int
		homestead bool
		want      bool
	}{
		{
			name: "valid v=0",
			v:    0, r: one, s: one,
			homestead: false, want: true,
		},
		{
			name: "valid v=1",
			v:    1, r: one, s: one,
			homestead: false, want: true,
		},
		{
			name: "invalid v=2",
			v:    2, r: one, s: one,
			homestead: false, want: false,
		},
		{
			name: "zero r",
			v:    0, r: zero, s: one,
			homestead: false, want: false,
		},
		{
			name: "zero s",
			v:    0, r: one, s: zero,
			homestead: false, want: false,
		},
		{
			name: "negative r",
			v:    0, r: new(big.Int).Neg(one), s: one,
			homestead: false, want: false,
		},
		{
			name: "r == secp256k1N",
			v:    0, r: new(big.Int).Set(secp256k1N), s: one,
			homestead: false, want: false,
		},
		{
			name: "s == secp256k1N",
			v:    0, r: one, s: new(big.Int).Set(secp256k1N),
			homestead: false, want: false,
		},
		{
			name: "homestead s > halfN",
			v:    0, r: one, s: new(big.Int).Add(halfN, one),
			homestead: true, want: false,
		},
		{
			name: "homestead s == halfN",
			v:    0, r: one, s: new(big.Int).Set(halfN),
			homestead: true, want: true,
		},
		{
			name: "non-homestead s > halfN is ok",
			v:    0, r: one, s: new(big.Int).Add(halfN, one),
			homestead: false, want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSignatureValues(tt.v, tt.r, tt.s, tt.homestead)
			if got != tt.want {
				t.Errorf("ValidateSignatureValues(%d, %s, %s, %v) = %v, want %v",
					tt.v, tt.r, tt.s, tt.homestead, got, tt.want)
			}
		})
	}
}

func TestEcrecoverInvalidInputs(t *testing.T) {
	// Wrong hash length
	_, err := Ecrecover([]byte{1, 2, 3}, make([]byte, 65))
	if err == nil {
		t.Error("Ecrecover should fail for wrong hash length")
	}

	// Wrong sig length
	_, err = Ecrecover(make([]byte, 32), make([]byte, 64))
	if err == nil {
		t.Error("Ecrecover should fail for wrong sig length")
	}

	// Invalid recovery ID
	sig := make([]byte, 65)
	sig[64] = 4
	_, err = Ecrecover(make([]byte, 32), sig)
	if err == nil {
		t.Error("Ecrecover should fail for invalid recovery id")
	}
}

func TestSignInvalidInputs(t *testing.T) {
	key, _ := GenerateKey()

	// Wrong hash length
	_, err := Sign([]byte{1, 2, 3}, key)
	if err == nil {
		t.Error("Sign should fail for wrong hash length")
	}

	// Nil key
	_, err = Sign(make([]byte, 32), nil)
	if err == nil {
		t.Error("Sign should fail for nil key")
	}
}

func TestRlpEncodeUint64(t *testing.T) {
	tests := []struct {
		input    uint64
		expected []byte
	}{
		{0, []byte{0x80}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}},
		{1024, []byte{0x82, 0x04, 0x00}},
	}

	for _, tt := range tests {
		result := rlpEncodeUint64(tt.input)
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("rlpEncodeUint64(%d): got %x, want %x", tt.input, result, tt.expected)
		}
	}
}
