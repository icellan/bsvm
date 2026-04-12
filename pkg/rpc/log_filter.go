package rpc

import (
	"math/big"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/types"
)

// FilterQuery represents a log filter query for eth_getLogs.
type FilterQuery struct {
	FromBlock *big.Int        `json:"fromBlock"`
	ToBlock   *big.Int        `json:"toBlock"`
	Addresses []types.Address `json:"address"`
	Topics    [][]types.Hash  `json:"topics"`
	BlockHash *types.Hash     `json:"blockHash"`
}

// filterLogs returns the logs from the given set that match the filter criteria.
func filterLogs(logs []*types.Log, addresses []types.Address, topics [][]types.Hash) []*types.Log {
	var result []*types.Log
	for _, log := range logs {
		if matchLog(log, addresses, topics) {
			result = append(result, log)
		}
	}
	return result
}

// matchLog checks whether a single log matches the filter criteria.
func matchLog(log *types.Log, addresses []types.Address, topics [][]types.Hash) bool {
	// Check address filter.
	if len(addresses) > 0 {
		found := false
		for _, addr := range addresses {
			if log.Address == addr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check topic filters.
	for i, sub := range topics {
		if len(sub) == 0 {
			// Wildcard: any value for this position.
			continue
		}
		if i >= len(log.Topics) {
			return false
		}
		found := false
		for _, topic := range sub {
			if log.Topics[i] == topic {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// getBlockLogs retrieves all logs for a given block from ChainDB and filters
// them according to the provided address and topic criteria.
func getBlockLogs(chainDB *block.ChainDB, hash types.Hash, number uint64, addresses []types.Address, topics [][]types.Hash) []*types.Log {
	receipts := chainDB.ReadReceipts(hash, number)
	if receipts == nil {
		return nil
	}

	var allLogs []*types.Log
	for _, receipt := range receipts {
		for _, log := range receipt.Logs {
			// Fill in block context that might be missing from storage.
			log.BlockNumber = number
			log.BlockHash = hash
			allLogs = append(allLogs, log)
		}
	}

	return filterLogs(allLogs, addresses, topics)
}
