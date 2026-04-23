package indexer

import (
	"crypto/ecdsa"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// Build a signed LegacyTx for the given sender key.
func mkTx(t *testing.T, key *ecdsa.PrivateKey, chainID uint64, nonce uint64, to *types.Address) *types.Transaction {
	t.Helper()
	signer := types.LatestSignerForChainID(new(big.Int).SetUint64(chainID))
	data := &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: big.NewInt(1),
		Gas:      21000,
		To:       to,
		Value:    uint256.NewInt(1),
	}
	tx, err := types.SignNewTx(key, signer, data)
	if err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	return tx
}

func mkHeader(number uint64) *block.L2Header {
	return &block.L2Header{
		Number:       new(big.Int).SetUint64(number),
		ParentHash:   types.Hash{},
		Coinbase:     types.Address{},
		StateRoot:    types.Hash{},
		TxHash:       types.Hash{},
		ReceiptHash:  types.Hash{},
		Timestamp:    1000 + number,
		GasLimit:     1_000_000,
		GasUsed:      0,
	}
}

func TestIngestAndLookup(t *testing.T) {
	dir := t.TempDir()
	idx, err := New(Config{Path: filepath.Join(dir, "idx"), ChainID: 31337})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer idx.Close()

	// Two senders, one recipient shared across both.
	alice, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	aliceAddr := types.Address(crypto.PubkeyToAddress(alice.PublicKey))
	bob, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	bobAddr := types.Address(crypto.PubkeyToAddress(bob.PublicKey))
	carol := types.HexToAddress("0x0000000000000000000000000000000000001234")

	// Block 1: alice → carol; bob → carol.
	tx1 := mkTx(t, alice, 31337, 0, &carol)
	tx2 := mkTx(t, bob, 31337, 0, &carol)
	h1 := mkHeader(1)
	b1 := block.NewBlock(h1, []*types.Transaction{tx1, tx2}, []*types.Receipt{
		{TxHash: tx1.Hash(), BlockNumber: big.NewInt(1), TransactionIndex: 0, Status: 1},
		{TxHash: tx2.Hash(), BlockNumber: big.NewInt(1), TransactionIndex: 1, Status: 1},
	})
	if err := idx.Ingest(b1); err != nil {
		t.Fatalf("ingest b1: %v", err)
	}

	// Block 2: alice creates contract (to=nil).
	tx3 := mkTx(t, alice, 31337, 1, nil)
	createdAddr := types.Address(crypto.CreateAddress(aliceAddr, 1))
	h2 := mkHeader(2)
	b2 := block.NewBlock(h2, []*types.Transaction{tx3}, []*types.Receipt{
		{TxHash: tx3.Hash(), BlockNumber: big.NewInt(2), TransactionIndex: 0, Status: 1, ContractAddress: createdAddr},
	})
	if err := idx.Ingest(b2); err != nil {
		t.Fatalf("ingest b2: %v", err)
	}

	// Alice has 2 entries (tx1 from, tx3 from).
	aliceEntries, err := idx.LookupEntries(Query{Address: aliceAddr})
	if err != nil {
		t.Fatalf("lookup alice: %v", err)
	}
	if len(aliceEntries) != 2 {
		t.Fatalf("alice entries = %d, want 2: %+v", len(aliceEntries), aliceEntries)
	}
	// Newest first.
	if aliceEntries[0].BlockNumber != 2 {
		t.Fatalf("alice[0].BlockNumber = %d, want 2", aliceEntries[0].BlockNumber)
	}
	if aliceEntries[0].Direction != DirectionFrom {
		t.Fatalf("alice[0].Direction = %q, want from", aliceEntries[0].Direction)
	}

	// Bob has 1 entry (tx2 from).
	bobEntries, err := idx.LookupEntries(Query{Address: bobAddr})
	if err != nil {
		t.Fatalf("lookup bob: %v", err)
	}
	if len(bobEntries) != 1 {
		t.Fatalf("bob entries = %d, want 1", len(bobEntries))
	}
	if bobEntries[0].Direction != DirectionFrom {
		t.Fatalf("bob[0].Direction = %q, want from", bobEntries[0].Direction)
	}

	// Carol has 2 entries (tx1 to, tx2 to).
	carolEntries, err := idx.LookupEntries(Query{Address: carol})
	if err != nil {
		t.Fatalf("lookup carol: %v", err)
	}
	if len(carolEntries) != 2 {
		t.Fatalf("carol entries = %d, want 2: %+v", len(carolEntries), carolEntries)
	}

	// Created contract has 1 entry (tx3 create).
	createdEntries, err := idx.LookupEntries(Query{Address: createdAddr})
	if err != nil {
		t.Fatalf("lookup created: %v", err)
	}
	if len(createdEntries) != 1 {
		t.Fatalf("created entries = %d, want 1", len(createdEntries))
	}
	if createdEntries[0].Direction != DirectionCreate {
		t.Fatalf("created[0].Direction = %q, want create", createdEntries[0].Direction)
	}

	// Block range filter: alice with FromBlock=2 should see only the create.
	aliceFiltered, err := idx.LookupEntries(Query{Address: aliceAddr, FromBlock: 2})
	if err != nil {
		t.Fatalf("lookup alice filtered: %v", err)
	}
	if len(aliceFiltered) != 1 || aliceFiltered[0].BlockNumber != 2 {
		t.Fatalf("alice filtered = %+v", aliceFiltered)
	}

	// ToBlock filter: alice with ToBlock=1 should see only tx1.
	aliceUpTo1, err := idx.LookupEntries(Query{Address: aliceAddr, ToBlock: 1})
	if err != nil {
		t.Fatalf("lookup alice toBlock=1: %v", err)
	}
	if len(aliceUpTo1) != 1 || aliceUpTo1[0].BlockNumber != 1 {
		t.Fatalf("alice toBlock=1 = %+v", aliceUpTo1)
	}

	// Stats reflect activity.
	s := idx.Stats()
	if s.LastBlock != 2 {
		t.Errorf("LastBlock = %d, want 2", s.LastBlock)
	}
	if s.Ingested != 3 {
		t.Errorf("Ingested = %d, want 3", s.Ingested)
	}
}
