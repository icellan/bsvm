package block

import (
	"encoding/binary"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// bloomIndexPrefix is the database key prefix for bloom index entries.
var bloomIndexPrefix = []byte("B")

// LogIndex provides bloom-based log filtering across blocks. For each block,
// the block's logs bloom is stored. When querying for logs, the bloom is
// checked first to skip blocks that definitely don't contain matching logs.
type LogIndex struct {
	db db.Database
}

// NewLogIndex creates a new log index backed by the given database.
func NewLogIndex(database db.Database) *LogIndex {
	return &LogIndex{db: database}
}

// bloomKey returns the database key for a bloom index entry: "B" + blockNum(8 BE).
func bloomKey(blockNum uint64) []byte {
	key := make([]byte, 1+8)
	copy(key, bloomIndexPrefix)
	binary.BigEndian.PutUint64(key[1:], blockNum)
	return key
}

// IndexBlock stores the logs bloom for a block. Called after block is committed.
func (li *LogIndex) IndexBlock(blockNum uint64, bloom types.Bloom) error {
	return li.db.Put(bloomKey(blockNum), bloom.Bytes())
}

// BlockMayContainLog checks the bloom filter for a block. Returns true if the
// block's bloom indicates it MAY contain logs matching the given addresses and
// topics. False means the block definitely does NOT contain matching logs.
// If the bloom for the given block is not found, returns true (conservative).
func (li *LogIndex) BlockMayContainLog(blockNum uint64, addresses []types.Address, topics [][]types.Hash) (bool, error) {
	data, err := li.db.Get(bloomKey(blockNum))
	if err != nil {
		// If not found, be conservative and say it may contain logs.
		return false, nil
	}

	if len(data) != types.BloomByteLength {
		// Invalid bloom data; be conservative.
		return true, nil
	}

	var bloom types.Bloom
	copy(bloom[:], data)

	// If no filters specified, any block may match.
	if len(addresses) == 0 && len(topics) == 0 {
		return true, nil
	}

	// Check addresses: the bloom must contain at least one of the requested
	// addresses. If addresses filter is set and none match the bloom, this
	// block cannot contain matching logs.
	if len(addresses) > 0 {
		addressMatch := false
		for _, addr := range addresses {
			if bloom.Test(addr.Bytes()) {
				addressMatch = true
				break
			}
		}
		if !addressMatch {
			return false, nil
		}
	}

	// Check topics: for each topic position, if the topic set is non-nil,
	// at least one topic in the set must be present in the bloom.
	for _, topicSet := range topics {
		if len(topicSet) == 0 {
			// Wildcard position, skip.
			continue
		}
		topicMatch := false
		for _, topic := range topicSet {
			if bloom.Test(topic.Bytes()) {
				topicMatch = true
				break
			}
		}
		if !topicMatch {
			return false, nil
		}
	}

	return true, nil
}

// DeleteBlock removes the bloom index for a block (used during rollback).
func (li *LogIndex) DeleteBlock(blockNum uint64) error {
	return li.db.Delete(bloomKey(blockNum))
}
