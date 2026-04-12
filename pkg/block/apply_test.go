package block

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// TestNewBlockContext_Random verifies that newBlockContext sets the Random
// field (PREVRANDAO) to a non-nil value that matches DeriveRandom.
func TestNewBlockContext_Random(t *testing.T) {
	header := &L2Header{
		ParentHash: types.HexToHash("0xaabbccdd"),
		Number:     big.NewInt(42),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	ctx := newBlockContext(header, nil, nil, nil)

	if ctx.Random == nil {
		t.Fatal("BlockContext.Random must not be nil")
	}

	// With nil bsvBlockHash, falls back to parentHash.
	expected := DeriveRandom(header.ParentHash, header.Number.Uint64())
	if *ctx.Random != expected {
		t.Fatalf("Random mismatch: got %s, want %s", ctx.Random.Hex(), expected.Hex())
	}
}

// TestNewBlockContext_RandomDeterministic verifies that the same inputs
// always produce the same Random value.
func TestNewBlockContext_RandomDeterministic(t *testing.T) {
	header := &L2Header{
		ParentHash: types.HexToHash("0x1234"),
		Number:     big.NewInt(100),
		GasLimit:   30_000_000,
		Timestamp:  5000,
		BaseFee:    new(big.Int),
	}

	ctx1 := newBlockContext(header, nil, nil, nil)
	ctx2 := newBlockContext(header, nil, nil, nil)

	if ctx1.Random == nil || ctx2.Random == nil {
		t.Fatal("Random must not be nil")
	}
	if *ctx1.Random != *ctx2.Random {
		t.Fatalf("Random is not deterministic: %s != %s", ctx1.Random.Hex(), ctx2.Random.Hex())
	}
}

// TestNewBlockContext_RandomDifferentBlocks verifies that different block
// numbers produce different Random values.
func TestNewBlockContext_RandomDifferentBlocks(t *testing.T) {
	parentHash := types.HexToHash("0xdeadbeef")

	header1 := &L2Header{
		ParentHash: parentHash,
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}
	header2 := &L2Header{
		ParentHash: parentHash,
		Number:     big.NewInt(2),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	ctx1 := newBlockContext(header1, nil, nil, nil)
	ctx2 := newBlockContext(header2, nil, nil, nil)

	if ctx1.Random == nil || ctx2.Random == nil {
		t.Fatal("Random must not be nil")
	}
	if *ctx1.Random == *ctx2.Random {
		t.Fatal("Different block numbers must produce different Random values")
	}
}

// TestNewBlockContext_RandomWithBSVBlockHash verifies that when a BSV block
// hash is provided, it is used for PREVRANDAO instead of the L2 parent hash.
func TestNewBlockContext_RandomWithBSVBlockHash(t *testing.T) {
	header := &L2Header{
		ParentHash: types.HexToHash("0xaaaa"),
		Number:     big.NewInt(10),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	bsvHash := types.HexToHash("0xbbbb")

	// With explicit BSV block hash.
	ctx := newBlockContext(header, nil, nil, &bsvHash)
	if ctx.Random == nil {
		t.Fatal("Random must not be nil")
	}
	expected := DeriveRandom(bsvHash, header.Number.Uint64())
	if *ctx.Random != expected {
		t.Fatalf("Random with BSV hash: got %s, want %s", ctx.Random.Hex(), expected.Hex())
	}

	// Without BSV block hash (nil fallback uses parentHash).
	ctxFallback := newBlockContext(header, nil, nil, nil)
	expectedFallback := DeriveRandom(header.ParentHash, header.Number.Uint64())
	if *ctxFallback.Random != expectedFallback {
		t.Fatalf("Random fallback: got %s, want %s", ctxFallback.Random.Hex(), expectedFallback.Hex())
	}

	// The two must differ since bsvHash != parentHash.
	if *ctx.Random == *ctxFallback.Random {
		t.Fatal("BSV hash and parentHash fallback should produce different Random values")
	}
}

// TestApplyTransaction_ReceiptBlockHash verifies that the receipt returned
// from ApplyTransaction has its BlockHash field set to header.Hash().
func TestApplyTransaction_ReceiptBlockHash(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	// Create genesis with a funded account.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	genesis := DefaultGenesis(testChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	// Build the block header for block 1.
	header := &L2Header{
		ParentHash: genesisHeader.Hash(),
		Coinbase:   types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc"),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	// Create a simple transfer transaction.
	signer := types.NewLondonSigner(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1000),
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	gp := new(GasPool)
	gp.SetGas(header.GasLimit)

	var usedGas uint64
	coinbase := header.Coinbase
	receipt, err := ApplyTransaction(config, nil, &coinbase, gp, statedb, header, tx, &usedGas, vm.Config{}, nil)
	if err != nil {
		t.Fatalf("ApplyTransaction failed: %v", err)
	}

	expectedBlockHash := header.Hash()
	if receipt.BlockHash != expectedBlockHash {
		t.Fatalf("receipt.BlockHash mismatch: got %s, want %s", receipt.BlockHash.Hex(), expectedBlockHash.Hex())
	}
	if receipt.BlockHash == (types.Hash{}) {
		t.Fatal("receipt.BlockHash must not be zero")
	}
}

// TestNewBlockContext_NilChain verifies that GetHash returns an empty hash
// when the chain context is nil.
func TestNewBlockContext_NilChain(t *testing.T) {
	header := &L2Header{
		ParentHash: types.HexToHash("0xaa"),
		Number:     big.NewInt(10),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	ctx := newBlockContext(header, nil, nil, nil)

	// Any block number should return empty hash when chain is nil.
	for _, n := range []uint64{0, 1, 5, 9} {
		h := ctx.GetHash(n)
		if h != (types.Hash{}) {
			t.Fatalf("GetHash(%d) with nil chain should return empty hash, got %s", n, h.Hex())
		}
	}
}

// TestNewBlockContext_GetHash256Limit verifies that GetHash returns an empty
// hash for blocks that are more than 256 ancestors back (EIP-2).
func TestNewBlockContext_GetHash256Limit(t *testing.T) {
	currentBlock := uint64(500)
	header := &L2Header{
		ParentHash: types.HexToHash("0xbb"),
		Number:     big.NewInt(int64(currentBlock)),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	// Use a chain context that returns a non-nil header for any request.
	chain := &testChainContext{
		headers: make(map[uint64]*L2Header),
	}
	// Populate headers for all blocks 0..499.
	for i := uint64(0); i < currentBlock; i++ {
		chain.headers[i] = &L2Header{
			Number:  big.NewInt(int64(i)),
			BaseFee: new(big.Int),
		}
	}

	ctx := newBlockContext(header, chain, nil, nil)

	// Block 244 = 500-256: exactly 256 away, should return empty (> 256 check
	// uses strict inequality: currentBlockNum - n > 256).
	// Block 243 = 500-257: 257 away, definitely out of range.
	outOfRange := currentBlock - 257 // block 243
	h := ctx.GetHash(outOfRange)
	if h != (types.Hash{}) {
		t.Fatalf("GetHash(%d) for block %d ancestors back should return empty, got %s",
			outOfRange, currentBlock-outOfRange, h.Hex())
	}

	// Block 244 = 500-256: exactly at boundary (currentBlock-n == 256),
	// should also return empty because the check is > 256 but 256 > 256 is false...
	// Wait, the check is: currentBlockNum-n > 256. For n=244: 500-244=256, 256 > 256 is false.
	// So block 244 is within range. Let's verify it returns a non-empty hash.
	atBoundary := currentBlock - 256 // block 244
	h = ctx.GetHash(atBoundary)
	if h == (types.Hash{}) {
		t.Fatalf("GetHash(%d) for exactly 256 blocks back should return non-empty hash", atBoundary)
	}

	// Block 499 = current block number. n >= currentBlockNum check should reject it.
	h = ctx.GetHash(currentBlock)
	if h != (types.Hash{}) {
		t.Fatalf("GetHash(%d) for current block should return empty, got %s",
			currentBlock, h.Hex())
	}

	// Block 501 = future block. Should also return empty.
	h = ctx.GetHash(currentBlock + 1)
	if h != (types.Hash{}) {
		t.Fatalf("GetHash(%d) for future block should return empty, got %s",
			currentBlock+1, h.Hex())
	}

	// Block 499 = one before current, well within range. Should return non-empty.
	h = ctx.GetHash(currentBlock - 1)
	if h == (types.Hash{}) {
		t.Fatal("GetHash for recent block should return non-empty hash")
	}
}
