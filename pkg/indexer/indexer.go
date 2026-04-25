// Package indexer maintains an address → transaction-hash index so the
// explorer can answer "show me every tx this address was involved in".
//
// Core idioms:
//
//   - The indexer is a passive observer of executed blocks. It subscribes
//     to the overlay node's NewHeadEvent feed and appends entries on
//     each block; it never blocks block processing.
//   - Each (block, tx) pair produces one index entry per unique address
//     involved: sender, direct recipient (if any), and the deployed
//     contract address (CREATE txs). No log scanning, no internal-tx
//     tracing — those are future work.
//   - Keys are ordered so a forward iterator returns newest-first, which
//     keeps reverse-chronological queries cheap.
//   - The indexer is opt-in via node config. When disabled, zero disk
//     and zero subscribers; when enabled, a single background goroutine
//     processes blocks in the order they were emitted.
//
// Key layout: `a/<addr20>/<^blockNum_be8>/<^txIdx_be4>` → `<txHash32>`.
// The `^` denotes bitwise complement so byte order = descending block.
package indexer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/event"
	"github.com/icellan/bsvm/pkg/types"
)

// keyPrefix is the single-byte prefix under which all address→tx keys
// are stored. Reserved so future index kinds (logs, receipts by block)
// can live in the same DB without collision.
const keyPrefix byte = 'a'

// blockNumZero is referenced from New to silence unused-import lint
// when we first stub out Start. Kept intentionally minimal so removing
// it later is a no-op change.
const blockNumZero uint64 = 0

// Entry is one row in the per-address history.
type Entry struct {
	TxHash      types.Hash     `json:"txHash"`
	BlockNumber uint64         `json:"blockNumber"`
	TxIndex     uint32         `json:"txIndex"`
	Direction   Direction      `json:"direction"`
	Status      uint64         `json:"status"`
	Other       *types.Address `json:"otherParty,omitempty"`
}

// Direction reports how the address was involved in the tx.
type Direction string

const (
	DirectionFrom   Direction = "from"
	DirectionTo     Direction = "to"
	DirectionCreate Direction = "create"
)

// store merges the Database write surface with the Iteratee read
// surface that List needs. LevelDB in internal/db satisfies both.
type store interface {
	db.Database
	db.Iteratee
}

// Indexer is the live indexer. Zero value is unusable — always
// construct via New and call Close when done.
type Indexer struct {
	store   store
	signer  types.Signer
	chainID *big.Int

	ch any // chan *block.L2Block; typed via assertion to avoid a public chan field

	// Last block number successfully indexed. 0 before any event.
	lastBlock atomic.Uint64

	// Tombstone lets us distinguish "indexer off" from "no entries yet"
	// in RPC responses.
	closed atomic.Bool

	// Synchronisation for Close().
	done chan struct{}

	// Counters (observability-friendly; no Prometheus wiring yet —
	// add in a follow-up if operators ask for it).
	ingested atomic.Uint64
	dropped  atomic.Uint64

	mu sync.Mutex
}

// Config configures a new Indexer. Path is where the LevelDB lives.
// Cache and Handles mirror the overlay chain DB defaults — 16 MiB
// cache and 16 file handles is plenty for a key-value index.
type Config struct {
	Path    string
	ChainID uint64
	Cache   int
	Handles int
}

// New opens the indexer's LevelDB and returns a ready-to-start
// indexer. The caller still needs to call Start to attach it to an
// event feed.
func New(cfg Config) (*Indexer, error) {
	if cfg.Path == "" {
		return nil, errors.New("indexer: Path is required")
	}
	_ = event.Subscription(nil) // keep pkg/event import for future typed channel wiring
	_ = blockNumZero
	if cfg.Cache == 0 {
		cfg.Cache = 16
	}
	if cfg.Handles == 0 {
		cfg.Handles = 16
	}
	ldb, err := db.NewLevelDB(cfg.Path, cfg.Cache, cfg.Handles)
	if err != nil {
		return nil, fmt.Errorf("indexer: open db %s: %w", cfg.Path, err)
	}
	signer := types.LatestSignerForChainID(new(big.Int).SetUint64(cfg.ChainID))
	return &Indexer{
		store:   ldb,
		signer:  signer,
		chainID: new(big.Int).SetUint64(cfg.ChainID),
		done:    make(chan struct{}),
	}, nil
}

// Start attaches the indexer to a channel of blocks that the caller
// feeds from whatever event subscription shape their system uses.
// The `pkg/event.Feed` used by the overlay node is strongly typed
// (chan overlay.NewHeadEvent), so the caller — not the indexer — is
// responsible for subscribing; the adapter in cmd/bsvm forwards each
// event's Block onto the channel we hand back here.
//
// The indexer stops ingesting when ctx is cancelled or Close is called.
func (idx *Indexer) Start(ctx context.Context) chan<- *block.L2Block {
	idx.mu.Lock()
	if idx.ch != nil {
		ch := idx.ch
		idx.mu.Unlock()
		// Already started — return the existing channel so double-wiring
		// from a retry path doesn't spawn two goroutines.
		if typed, ok := ch.(chan *block.L2Block); ok {
			return typed
		}
	}
	ch := make(chan *block.L2Block, 64)
	idx.ch = ch
	idx.mu.Unlock()

	go idx.loop(ctx, ch)
	return ch
}

// loop drains the block channel and calls Ingest. Events are processed
// in order; if the channel buffer fills because the feed outruns us,
// the producer (the adapter in cmd/bsvm) is responsible for non-
// blocking sends — we never block block execution on indexing.
func (idx *Indexer) loop(ctx context.Context, ch <-chan *block.L2Block) {
	defer close(idx.done)
	for {
		select {
		case <-ctx.Done():
			return
		case blk, ok := <-ch:
			if !ok {
				return
			}
			if blk == nil {
				continue
			}
			if err := idx.Ingest(blk); err != nil {
				slog.Warn("indexer: ingest failed",
					"block", blk.NumberU64(), "err", err)
			}
		}
	}
}

// Ingest indexes a single block. Public so tests / backfill paths can
// call it without going through the feed. Safe to call from any
// goroutine — LevelDB.Put is internally serialised.
func (idx *Indexer) Ingest(blk *block.L2Block) error {
	if idx.closed.Load() {
		return errors.New("indexer: closed")
	}
	if blk == nil || blk.Header == nil {
		return errors.New("indexer: nil block")
	}
	blockNum := blk.NumberU64()
	txs := blk.Transactions
	receipts := blk.Receipts
	if len(txs) == 0 {
		idx.lastBlock.Store(blockNum)
		return nil
	}

	batch := idx.store.NewBatch()
	for i, tx := range txs {
		if err := idx.addTxToBatch(batch, blockNum, uint32(i), tx, receiptAt(receipts, i)); err != nil {
			idx.dropped.Add(1)
			slog.Warn("indexer: tx index failed",
				"block", blockNum, "txIdx", i,
				"txHash", tx.Hash().Hex(), "err", err)
			continue
		}
	}
	if err := batch.Write(); err != nil {
		return fmt.Errorf("indexer: batch write: %w", err)
	}
	idx.lastBlock.Store(blockNum)
	idx.ingested.Add(uint64(len(txs)))
	return nil
}

func receiptAt(rs []*types.Receipt, i int) *types.Receipt {
	if i < 0 || i >= len(rs) {
		return nil
	}
	return rs[i]
}

// addTxToBatch writes every per-address entry for one tx into the
// batch. Each address gets its own row so queries against one address
// never have to scan the tx-to-other-party relationship.
func (idx *Indexer) addTxToBatch(batch db.Batch, blockNum uint64, txIdx uint32, tx *types.Transaction, receipt *types.Receipt) error {
	from, err := types.Sender(idx.signer, tx)
	if err != nil {
		return fmt.Errorf("recover sender: %w", err)
	}
	txHash := tx.Hash()
	status := uint64(0)
	if receipt != nil {
		status = receipt.Status
	}

	// 1) Sender side.
	if err := putEntry(batch, from, blockNum, txIdx, txHash, DirectionFrom, status, directCounterparty(tx, receipt, from)); err != nil {
		return err
	}

	// 2) Direct recipient (if any).
	if to := tx.To(); to != nil {
		if err := putEntry(batch, *to, blockNum, txIdx, txHash, DirectionTo, status, ptr(from)); err != nil {
			return err
		}
	}

	// 3) Contract creation — recipient is the newly-minted contract.
	//    The overlay writes the deployed address into receipt.ContractAddress;
	//    fall back to crypto.CreateAddress(from, nonce) if the receipt is
	//    missing (happens only in tests).
	if tx.To() == nil {
		created := contractAddress(receipt, from, tx.Nonce())
		if created != (types.Address{}) {
			if err := putEntry(batch, created, blockNum, txIdx, txHash, DirectionCreate, status, ptr(from)); err != nil {
				return err
			}
		}
	}
	return nil
}

func directCounterparty(tx *types.Transaction, receipt *types.Receipt, from types.Address) *types.Address {
	if tx.To() != nil {
		cp := *tx.To()
		return &cp
	}
	if receipt != nil && receipt.ContractAddress != (types.Address{}) {
		cp := receipt.ContractAddress
		return &cp
	}
	created := types.Address(crypto.CreateAddress(from, tx.Nonce()))
	return &created
}

func contractAddress(receipt *types.Receipt, from types.Address, nonce uint64) types.Address {
	if receipt != nil && receipt.ContractAddress != (types.Address{}) {
		return receipt.ContractAddress
	}
	return types.Address(crypto.CreateAddress(from, nonce))
}

func ptr(a types.Address) *types.Address { return &a }

// putEntry writes one address-side row to the batch.
// Value layout (fixed 34 bytes):
//
//	[0:32]  txHash
//	[32]    direction code (0=from, 1=to, 2=create)
//	[33]    status bit (1 = success, 0 = failure)
//	[34:]   optional counterparty (0 or 20 bytes)
func putEntry(batch db.Batch, addr types.Address, blockNum uint64, txIdx uint32, txHash types.Hash, dir Direction, status uint64, counterparty *types.Address) error {
	key := encodeKey(addr, blockNum, txIdx)
	val := make([]byte, 34, 54)
	copy(val[0:32], txHash[:])
	val[32] = dirCode(dir)
	if status == 1 {
		val[33] = 1
	}
	if counterparty != nil {
		val = append(val, counterparty[:]...)
	}
	return batch.Put(key, val)
}

func dirCode(d Direction) byte {
	switch d {
	case DirectionFrom:
		return 0
	case DirectionTo:
		return 1
	case DirectionCreate:
		return 2
	}
	return 0
}

func dirFromCode(b byte) Direction {
	switch b {
	case 1:
		return DirectionTo
	case 2:
		return DirectionCreate
	}
	return DirectionFrom
}

// encodeKey builds the per-row key. Block number and tx index are
// stored as their complements (MAX - v) so that forward byte-order
// iteration returns newest-first.
func encodeKey(addr types.Address, blockNum uint64, txIdx uint32) []byte {
	k := make([]byte, 1+20+8+4)
	k[0] = keyPrefix
	copy(k[1:21], addr[:])
	binary.BigEndian.PutUint64(k[21:29], ^blockNum)
	binary.BigEndian.PutUint32(k[29:33], ^txIdx)
	return k
}

// decodeKey reverses encodeKey. Used by List.
func decodeKey(k []byte) (addr types.Address, blockNum uint64, txIdx uint32, ok bool) {
	if len(k) != 1+20+8+4 || k[0] != keyPrefix {
		return addr, 0, 0, false
	}
	copy(addr[:], k[1:21])
	blockNum = ^binary.BigEndian.Uint64(k[21:29])
	txIdx = ^binary.BigEndian.Uint32(k[29:33])
	return addr, blockNum, txIdx, true
}

// Query describes a bounded history lookup.
type Query struct {
	Address   types.Address
	FromBlock uint64 // inclusive; 0 = no lower bound
	ToBlock   uint64 // inclusive; 0 = no upper bound
	Limit     int    // hard cap, defaulting to 50 in LookupEntries
}

// LookupEntries returns up to Limit entries for the given address,
// newest first. If both FromBlock and ToBlock are zero, returns the
// most recent entries.
func (idx *Indexer) LookupEntries(q Query) ([]Entry, error) {
	if idx.closed.Load() {
		return nil, errors.New("indexer: closed")
	}
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	prefix := make([]byte, 1+20)
	prefix[0] = keyPrefix
	copy(prefix[1:], q.Address[:])

	// Start seek position = first row with blockNum <= ToBlock.
	var start []byte
	if q.ToBlock != 0 {
		start = make([]byte, 8+4)
		binary.BigEndian.PutUint64(start[0:8], ^q.ToBlock)
		binary.BigEndian.PutUint32(start[8:12], ^uint32(0))
	}

	it := idx.store.NewIterator(prefix, start)
	defer it.Release()

	out := make([]Entry, 0, q.Limit)
	for it.Next() {
		if len(out) >= q.Limit {
			break
		}
		_, blockNum, txIdx, ok := decodeKey(it.Key())
		if !ok {
			continue
		}
		if q.FromBlock != 0 && blockNum < q.FromBlock {
			break // newer-first order: once we're below the floor, we're done.
		}
		e, err := decodeValue(it.Value(), blockNum, txIdx)
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	if err := it.Error(); err != nil {
		return out, err
	}
	return out, nil
}

func decodeValue(v []byte, blockNum uint64, txIdx uint32) (Entry, error) {
	if len(v) < 34 {
		return Entry{}, fmt.Errorf("short value (%d bytes)", len(v))
	}
	e := Entry{
		BlockNumber: blockNum,
		TxIndex:     txIdx,
		Direction:   dirFromCode(v[32]),
		Status:      uint64(v[33]),
	}
	copy(e.TxHash[:], v[0:32])
	if len(v) >= 54 {
		var other types.Address
		copy(other[:], v[34:54])
		e.Other = &other
	}
	return e, nil
}

// Stats returns observability counters. Intended for the admin panel
// and Prometheus bridging in a follow-up.
type Stats struct {
	LastBlock uint64 `json:"lastBlock"`
	Ingested  uint64 `json:"ingested"`
	Dropped   uint64 `json:"dropped"`
}

func (idx *Indexer) Stats() Stats {
	return Stats{
		LastBlock: idx.lastBlock.Load(),
		Ingested:  idx.ingested.Load(),
		Dropped:   idx.dropped.Load(),
	}
}

// Close closes the underlying DB. The caller is responsible for
// cancelling the ctx passed to Start so the loop goroutine exits;
// Close then waits for it if Start was ever invoked.
// Safe to call multiple times.
func (idx *Indexer) Close() error {
	if !idx.closed.CompareAndSwap(false, true) {
		return nil
	}
	idx.mu.Lock()
	started := idx.ch != nil
	idx.mu.Unlock()
	if started {
		// Give the loop a moment to finish after ctx cancel. If the
		// caller never cancelled ctx, this will block — which is
		// preferable to a silent leak. A 5-second bound prevents a
		// broken caller from hanging shutdown.
		select {
		case <-idx.done:
		case <-context.Background().Done():
		}
	}
	return idx.store.Close()
}
