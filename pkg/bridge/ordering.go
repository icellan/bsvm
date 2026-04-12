package bridge

import (
	"sort"
)

// SortDeposits sorts deposit transactions deterministically by
// (BSV block height ASC, BSV tx index ASC, output index ASC).
// This ensures all nodes produce identical ordering for the same
// set of deposits, which is critical for deterministic state
// transitions.
func SortDeposits(deposits []*Deposit) {
	sort.SliceStable(deposits, func(i, j int) bool {
		if deposits[i].BSVBlockHeight != deposits[j].BSVBlockHeight {
			return deposits[i].BSVBlockHeight < deposits[j].BSVBlockHeight
		}
		if deposits[i].TxIndex != deposits[j].TxIndex {
			return deposits[i].TxIndex < deposits[j].TxIndex
		}
		return deposits[i].Vout < deposits[j].Vout
	})
}
