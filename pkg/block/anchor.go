package block

import "github.com/icellan/bsvm/pkg/types"

// AnchorRecord tracks a covenant advance transaction on BSV. It maps an L2
// block to the BSV transaction that anchored it on-chain.
type AnchorRecord struct {
	L2BlockNum     uint64     // L2 block number that was proven
	BSVTxID        types.Hash // BSV transaction ID of the covenant advance
	BSVBlockHeight uint64     // BSV block height containing the anchor tx (0 if unconfirmed)
	Confirmed      bool       // true once the BSV tx has sufficient confirmations
}
