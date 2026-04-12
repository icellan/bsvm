package block

import (
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// makeBloom creates a bloom filter containing the given addresses and topics.
func makeBloom(addresses []types.Address, topics []types.Hash) types.Bloom {
	var bloom types.Bloom
	for _, addr := range addresses {
		bloom.Add(addr.Bytes())
	}
	for _, topic := range topics {
		bloom.Add(topic.Bytes())
	}
	return bloom
}

func TestLogIndex_IndexAndQuery(t *testing.T) {
	database := db.NewMemoryDB()
	li := NewLogIndex(database)

	addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	topic := types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	bloom := makeBloom([]types.Address{addr}, []types.Hash{topic})

	if err := li.IndexBlock(1, bloom); err != nil {
		t.Fatalf("IndexBlock failed: %v", err)
	}

	// Query with matching address.
	mayContain, err := li.BlockMayContainLog(1, []types.Address{addr}, nil)
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match address")
	}

	// Query with matching topic.
	mayContain, err = li.BlockMayContainLog(1, nil, [][]types.Hash{{topic}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match topic")
	}

	// Query with matching address and topic.
	mayContain, err = li.BlockMayContainLog(1, []types.Address{addr}, [][]types.Hash{{topic}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match address+topic")
	}
}

func TestLogIndex_NoMatch(t *testing.T) {
	database := db.NewMemoryDB()
	li := NewLogIndex(database)

	addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	otherAddr := types.HexToAddress("0x2222222222222222222222222222222222222222")

	bloom := makeBloom([]types.Address{addr}, nil)

	if err := li.IndexBlock(5, bloom); err != nil {
		t.Fatalf("IndexBlock failed: %v", err)
	}

	// Query with non-matching address.
	mayContain, err := li.BlockMayContainLog(5, []types.Address{otherAddr}, nil)
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if mayContain {
		t.Error("expected bloom NOT to match different address")
	}
}

func TestLogIndex_TopicMatch(t *testing.T) {
	database := db.NewMemoryDB()
	li := NewLogIndex(database)

	topic1 := types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	topic2 := types.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	topic3 := types.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

	bloom := makeBloom(nil, []types.Hash{topic1, topic2})

	if err := li.IndexBlock(10, bloom); err != nil {
		t.Fatalf("IndexBlock failed: %v", err)
	}

	// Topic1 should match.
	mayContain, err := li.BlockMayContainLog(10, nil, [][]types.Hash{{topic1}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match topic1")
	}

	// Topic2 should match.
	mayContain, err = li.BlockMayContainLog(10, nil, [][]types.Hash{{topic2}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match topic2")
	}

	// Topic3 should NOT match.
	mayContain, err = li.BlockMayContainLog(10, nil, [][]types.Hash{{topic3}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if mayContain {
		t.Error("expected bloom NOT to match topic3")
	}

	// OR'd topic set: [topic1 OR topic3] should match (topic1 is present).
	mayContain, err = li.BlockMayContainLog(10, nil, [][]types.Hash{{topic1, topic3}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match OR'd topic set containing topic1")
	}

	// Wildcard topic position: [nil, {topic2}] should match.
	mayContain, err = li.BlockMayContainLog(10, nil, [][]types.Hash{nil, {topic2}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match wildcard + topic2")
	}
}

func TestLogIndex_DeleteBlock(t *testing.T) {
	database := db.NewMemoryDB()
	li := NewLogIndex(database)

	addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	bloom := makeBloom([]types.Address{addr}, nil)

	if err := li.IndexBlock(3, bloom); err != nil {
		t.Fatalf("IndexBlock failed: %v", err)
	}

	// Verify it exists.
	mayContain, err := li.BlockMayContainLog(3, []types.Address{addr}, nil)
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected bloom to match before delete")
	}

	// Delete the block.
	if err := li.DeleteBlock(3); err != nil {
		t.Fatalf("DeleteBlock failed: %v", err)
	}

	// After deletion, BlockMayContainLog returns false (not found).
	mayContain, err = li.BlockMayContainLog(3, []types.Address{addr}, nil)
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if mayContain {
		t.Error("expected bloom NOT to match after delete")
	}
}

func TestLogIndex_MultipleBlocks(t *testing.T) {
	database := db.NewMemoryDB()
	li := NewLogIndex(database)

	// Index 10 blocks, each with a unique address.
	addrs := make([]types.Address, 10)
	for i := 0; i < 10; i++ {
		addrs[i] = types.HexToAddress("0x" + string(rune('a'+i)) + "111111111111111111111111111111111111111")
		bloom := makeBloom([]types.Address{addrs[i]}, nil)
		if err := li.IndexBlock(uint64(i), bloom); err != nil {
			t.Fatalf("IndexBlock(%d) failed: %v", i, err)
		}
	}

	// Each block should match its own address and not match other addresses.
	for i := 0; i < 10; i++ {
		mayContain, err := li.BlockMayContainLog(uint64(i), []types.Address{addrs[i]}, nil)
		if err != nil {
			t.Fatalf("BlockMayContainLog(%d) failed: %v", i, err)
		}
		if !mayContain {
			t.Errorf("block %d should match its own address", i)
		}
	}
}

func TestLogIndex_EmptyBloom(t *testing.T) {
	database := db.NewMemoryDB()
	li := NewLogIndex(database)

	// Index a block with an empty bloom.
	var emptyBloom types.Bloom
	if err := li.IndexBlock(0, emptyBloom); err != nil {
		t.Fatalf("IndexBlock failed: %v", err)
	}

	// Empty bloom with no filters should match (any block may match).
	mayContain, err := li.BlockMayContainLog(0, nil, nil)
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if !mayContain {
		t.Error("expected empty bloom with no filters to return true")
	}

	// Empty bloom with an address filter should NOT match.
	addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	mayContain, err = li.BlockMayContainLog(0, []types.Address{addr}, nil)
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if mayContain {
		t.Error("expected empty bloom NOT to match any address")
	}

	// Empty bloom with a topic filter should NOT match.
	topic := types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	mayContain, err = li.BlockMayContainLog(0, nil, [][]types.Hash{{topic}})
	if err != nil {
		t.Fatalf("BlockMayContainLog failed: %v", err)
	}
	if mayContain {
		t.Error("expected empty bloom NOT to match any topic")
	}
}
