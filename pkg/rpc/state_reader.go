package rpc

import (
	"fmt"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// StateReader provides read-only access to the state at any block.
type StateReader interface {
	// StateAt opens a state database at the given root hash.
	StateAt(root types.Hash) (*state.StateDB, error)
	// StateAtBlock opens a state database at the given block number by
	// looking up the block's state root in the chain database.
	StateAtBlock(blockNumber uint64) (*state.StateDB, error)
	// LatestState returns a state database at the latest block.
	LatestState() (*state.StateDB, error)
}

// stateReaderImpl implements StateReader using the chain database and the
// underlying key-value store.
type stateReaderImpl struct {
	db      db.Database
	chainDB *block.ChainDB
}

// NewStateReader creates a new StateReader backed by the given database and
// chain database.
func NewStateReader(database db.Database, chainDB *block.ChainDB) StateReader {
	return &stateReaderImpl{
		db:      database,
		chainDB: chainDB,
	}
}

// StateAt opens a state database at the given root hash.
func (r *stateReaderImpl) StateAt(root types.Hash) (*state.StateDB, error) {
	return state.New(root, r.db)
}

// StateAtBlock opens a state database at the given block number by looking up
// the block's state root in the chain database.
func (r *stateReaderImpl) StateAtBlock(blockNumber uint64) (*state.StateDB, error) {
	header := r.chainDB.ReadHeaderByNumber(blockNumber)
	if header == nil {
		return nil, fmt.Errorf("block %d not found", blockNumber)
	}
	return state.New(header.StateRoot, r.db)
}

// LatestState returns a state database at the latest (head) block.
func (r *stateReaderImpl) LatestState() (*state.StateDB, error) {
	header := r.chainDB.ReadHeadHeader()
	if header == nil {
		return nil, fmt.Errorf("no head block found")
	}
	return state.New(header.StateRoot, r.db)
}
