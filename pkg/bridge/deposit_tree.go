package bridge

import (
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/types"
)

// DepositTree wraps an MPT trie for deposit deduplication and queries.
// It maintains a persistent Merkle tree of all processed deposits,
// keyed by BSV txid. This tree is used for:
//   - Deduplication on restart: processedDeposits is the hot cache;
//     the tree is the persistent index.
//   - RPC queries: bsv_getDepositStatus(bsvTxID) can prove inclusion.
//   - State export: the deposit set is included in state snapshots
//     for fast sync.
//
// This is NOT used for fraud proofs (the system uses validity proofs).
type DepositTree struct {
	tree   *mpt.Trie
	trieDB *mpt.Database
}

// NewDepositTree creates a new DepositTree backed by the given database.
// If root is the empty root hash, a fresh empty trie is created.
func NewDepositTree(diskDB db.Database, root types.Hash) (*DepositTree, error) {
	trieDB := mpt.NewDatabase(diskDB)
	id := mpt.TrieID(root)
	tree, err := mpt.New(id, trieDB)
	if err != nil {
		return nil, err
	}
	return &DepositTree{tree: tree, trieDB: trieDB}, nil
}

// AddDeposit inserts a deposit into the tree, keyed by BSV txid.
// Returns the new root hash after insertion.
func (dt *DepositTree) AddDeposit(deposit *Deposit) types.Hash {
	key := deposit.BSVTxID[:]
	value := encodeDeposit(deposit)
	dt.tree.MustUpdate(key, value)
	return dt.tree.Hash()
}

// HasDeposit checks whether a deposit with the given BSV txid exists
// in the tree.
func (dt *DepositTree) HasDeposit(bsvTxID types.Hash) bool {
	val, err := dt.tree.Get(bsvTxID[:])
	return err == nil && len(val) > 0
}

// GetDeposit retrieves a deposit from the tree by BSV txid. Returns
// nil if the deposit is not found.
func (dt *DepositTree) GetDeposit(bsvTxID types.Hash) *Deposit {
	val, err := dt.tree.Get(bsvTxID[:])
	if err != nil || len(val) == 0 {
		return nil
	}
	dep, err := decodeDeposit(val)
	if err != nil {
		return nil
	}
	return dep
}

// Hash returns the current root hash of the deposit tree.
func (dt *DepositTree) Hash() types.Hash {
	return dt.tree.Hash()
}

// Commit persists the deposit tree to the underlying database.
// Returns the root hash.
func (dt *DepositTree) Commit() (types.Hash, error) {
	root, nodes, err := dt.tree.Commit(false)
	if err != nil {
		return types.Hash{}, err
	}
	if nodes != nil {
		dt.trieDB.CommitNodeSet(nodes)
	}
	if err := dt.trieDB.Commit(root); err != nil {
		return types.Hash{}, err
	}
	return root, nil
}
