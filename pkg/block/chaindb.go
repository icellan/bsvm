package block

import (
	"encoding/binary"
	"fmt"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// Key prefixes for the chain database.
var (
	headerPrefix       = []byte("h")  // h + blockNum(8) + blockHash(32) -> RLP header
	canonicalHashKey   = []byte("H")  // H + blockNum(8) -> canonical hash (32 bytes)
	bodyPrefix         = []byte("b")  // b + blockNum(8) + blockHash(32) -> RLP body
	receiptPrefix      = []byte("r")  // r + blockNum(8) + blockHash(32) -> RLP receipts
	headBlockHashKey   = []byte("l")  // l -> head block hash (32 bytes)
	headBlockNumberKey = []byte("n")  // n -> head block number (8 bytes big-endian)
	hashToNumberPrefix = []byte("H#") // H# + blockHash(32) -> blockNum (8 bytes)
	txLookupPrefix     = []byte("t")  // t + txHash(32) -> RLP TxLookupEntry
	anchorPrefix       = []byte("a")  // a + blockNum(8) -> RLP AnchorRecord
	covenantTxIDKey    = []byte("c")  // c -> current covenant UTXO txid (32 bytes)
	covenantStateKey   = []byte("C")  // C -> current covenant state (serialized)
	syncCheckpointKey  = []byte("S")  // S -> RLP-encoded SyncCheckpoint
)

// TxLookupEntry maps a transaction hash to its containing block.
type TxLookupEntry struct {
	BlockHash   types.Hash
	BlockNumber uint64
	Index       uint64
}

// ChainDB stores L2 blocks, headers, receipts, and indices. It wraps the
// low-level database and provides typed read/write operations.
type ChainDB struct {
	db db.Database
}

// NewChainDB creates a new chain database backed by the given storage.
func NewChainDB(database db.Database) *ChainDB {
	return &ChainDB{db: database}
}

// encodeBlockNumber encodes a block number as an 8-byte big-endian value.
func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

// headerKey returns the database key for a header: "h" + number(8) + hash(32).
func headerKey(hash types.Hash, number uint64) []byte {
	key := make([]byte, 0, 1+8+32)
	key = append(key, headerPrefix...)
	key = append(key, encodeBlockNumber(number)...)
	key = append(key, hash.Bytes()...)
	return key
}

// canonicalKey returns the database key for a canonical hash: "H" + number(8).
func canonicalKey(number uint64) []byte {
	key := make([]byte, 0, 1+8)
	key = append(key, canonicalHashKey...)
	key = append(key, encodeBlockNumber(number)...)
	return key
}

// bodyKey returns the database key for a block body: "b" + number(8) + hash(32).
func bodyKey(hash types.Hash, number uint64) []byte {
	key := make([]byte, 0, 1+8+32)
	key = append(key, bodyPrefix...)
	key = append(key, encodeBlockNumber(number)...)
	key = append(key, hash.Bytes()...)
	return key
}

// receiptKey returns the database key for receipts: "r" + number(8) + hash(32).
func receiptKey(hash types.Hash, number uint64) []byte {
	key := make([]byte, 0, 1+8+32)
	key = append(key, receiptPrefix...)
	key = append(key, encodeBlockNumber(number)...)
	key = append(key, hash.Bytes()...)
	return key
}

// hashToNumberKey returns the database key for hash-to-number index: "H#" + hash(32).
func hashToNumberKey(hash types.Hash) []byte {
	key := make([]byte, 0, 2+32)
	key = append(key, hashToNumberPrefix...)
	key = append(key, hash.Bytes()...)
	return key
}

// txLookupKey returns the database key for a tx lookup: "t" + txHash(32).
func txLookupKey(txHash types.Hash) []byte {
	key := make([]byte, 0, 1+32)
	key = append(key, txLookupPrefix...)
	key = append(key, txHash.Bytes()...)
	return key
}

// WriteHeader writes a header to the database and updates the hash-to-number
// index so that ReadHeaderByHash can perform O(1) lookups.
func (cdb *ChainDB) WriteHeader(header *L2Header) error {
	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		return fmt.Errorf("failed to encode header: %w", err)
	}
	hash := header.Hash()
	number := header.Number.Uint64()
	if err := cdb.db.Put(headerKey(hash, number), data); err != nil {
		return err
	}
	return cdb.db.Put(hashToNumberKey(hash), encodeBlockNumber(number))
}

// ReadHeader returns the header for the given hash and number, or nil if
// not found.
func (cdb *ChainDB) ReadHeader(hash types.Hash, number uint64) *L2Header {
	data, err := cdb.db.Get(headerKey(hash, number))
	if err != nil {
		return nil
	}
	var header L2Header
	if err := rlp.DecodeBytes(data, &header); err != nil {
		return nil
	}
	return &header
}

// ReadHeaderByNumber returns the canonical header at the given block number,
// or nil if not found.
func (cdb *ChainDB) ReadHeaderByNumber(number uint64) *L2Header {
	hash := cdb.ReadCanonicalHash(number)
	if hash == (types.Hash{}) {
		return nil
	}
	return cdb.ReadHeader(hash, number)
}

// ReadHeaderByHash returns the header with the given hash using the
// hash-to-number index for O(1) lookup. Returns nil if not found.
func (cdb *ChainDB) ReadHeaderByHash(hash types.Hash) *L2Header {
	data, err := cdb.db.Get(hashToNumberKey(hash))
	if err != nil || len(data) < 8 {
		return nil
	}
	number := binary.BigEndian.Uint64(data)
	return cdb.ReadHeader(hash, number)
}

// WriteBody writes block transactions to the database.
func (cdb *ChainDB) WriteBody(hash types.Hash, number uint64, txs []*types.Transaction) error {
	data, err := rlp.EncodeToBytes(txs)
	if err != nil {
		return fmt.Errorf("failed to encode body: %w", err)
	}
	return cdb.db.Put(bodyKey(hash, number), data)
}

// ReadBody returns the transactions for the given block, or nil if not found.
func (cdb *ChainDB) ReadBody(hash types.Hash, number uint64) []*types.Transaction {
	data, err := cdb.db.Get(bodyKey(hash, number))
	if err != nil {
		return nil
	}
	var txs []*types.Transaction
	if err := rlp.DecodeBytes(data, &txs); err != nil {
		return nil
	}
	return txs
}

// WriteReceipts writes receipts to the database.
func (cdb *ChainDB) WriteReceipts(hash types.Hash, number uint64, receipts []*types.Receipt) error {
	data, err := rlp.EncodeToBytes(receipts)
	if err != nil {
		return fmt.Errorf("failed to encode receipts: %w", err)
	}
	return cdb.db.Put(receiptKey(hash, number), data)
}

// ReadReceipts returns the receipts for the given block, or nil if not found.
func (cdb *ChainDB) ReadReceipts(hash types.Hash, number uint64) []*types.Receipt {
	data, err := cdb.db.Get(receiptKey(hash, number))
	if err != nil {
		return nil
	}
	var receipts []*types.Receipt
	if err := rlp.DecodeBytes(data, &receipts); err != nil {
		return nil
	}
	return receipts
}

// WriteCanonicalHash writes the canonical block hash for the given number.
func (cdb *ChainDB) WriteCanonicalHash(hash types.Hash, number uint64) error {
	return cdb.db.Put(canonicalKey(number), hash.Bytes())
}

// ReadCanonicalHash returns the canonical block hash for the given number,
// or the zero hash if not found.
func (cdb *ChainDB) ReadCanonicalHash(number uint64) types.Hash {
	data, err := cdb.db.Get(canonicalKey(number))
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(data)
}

// WriteHeadBlockHash writes the hash of the current head block.
func (cdb *ChainDB) WriteHeadBlockHash(hash types.Hash) error {
	return cdb.db.Put(headBlockHashKey, hash.Bytes())
}

// ReadHeadBlockHash returns the hash of the current head block, or the
// zero hash if not set.
func (cdb *ChainDB) ReadHeadBlockHash() types.Hash {
	data, err := cdb.db.Get(headBlockHashKey)
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(data)
}

// WriteTxLookup writes a transaction lookup entry mapping a tx hash to its
// containing block.
func (cdb *ChainDB) WriteTxLookup(txHash types.Hash, blockHash types.Hash, blockNumber uint64, index uint64) error {
	entry := TxLookupEntry{
		BlockHash:   blockHash,
		BlockNumber: blockNumber,
		Index:       index,
	}
	data, err := rlp.EncodeToBytes(entry)
	if err != nil {
		return fmt.Errorf("failed to encode tx lookup: %w", err)
	}
	return cdb.db.Put(txLookupKey(txHash), data)
}

// ReadTxLookup returns the lookup entry for the given transaction hash, or
// an error if not found.
func (cdb *ChainDB) ReadTxLookup(txHash types.Hash) (*TxLookupEntry, error) {
	data, err := cdb.db.Get(txLookupKey(txHash))
	if err != nil {
		return nil, err
	}
	var entry TxLookupEntry
	if err := rlp.DecodeBytes(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to decode tx lookup: %w", err)
	}
	return &entry, nil
}

// WriteHeadBlockNumber writes the current head block number.
func (cdb *ChainDB) WriteHeadBlockNumber(number uint64) error {
	return cdb.db.Put(headBlockNumberKey, encodeBlockNumber(number))
}

// ReadHeadBlockNumber returns the current head block number, or 0 if not set.
// The second return value indicates whether a value was found.
func (cdb *ChainDB) ReadHeadBlockNumber() (uint64, bool) {
	data, err := cdb.db.Get(headBlockNumberKey)
	if err != nil || len(data) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(data), true
}

// ReadHeadHeader returns the header of the current head block, or nil if
// no head is set.
func (cdb *ChainDB) ReadHeadHeader() *L2Header {
	hash := cdb.ReadHeadBlockHash()
	if hash == (types.Hash{}) {
		return nil
	}
	// Use the head block number key for O(1) lookup.
	if number, ok := cdb.ReadHeadBlockNumber(); ok {
		return cdb.ReadHeader(hash, number)
	}
	// Fallback: use hash-to-number index.
	return cdb.ReadHeaderByHash(hash)
}

// WriteBlock atomically writes a complete block (header, body, receipts,
// tx lookups, and canonical hash) to the database.
func (cdb *ChainDB) WriteBlock(block *L2Block, receipts []*types.Receipt) error {
	batch := cdb.db.NewBatch()

	hash := block.Hash()
	number := block.NumberU64()

	// Write header.
	headerData, err := rlp.EncodeToBytes(block.Header)
	if err != nil {
		return fmt.Errorf("failed to encode header: %w", err)
	}
	if err := batch.Put(headerKey(hash, number), headerData); err != nil {
		return err
	}

	// Write body (transactions).
	bodyData, err := rlp.EncodeToBytes(block.Transactions)
	if err != nil {
		return fmt.Errorf("failed to encode body: %w", err)
	}
	if err := batch.Put(bodyKey(hash, number), bodyData); err != nil {
		return err
	}

	// Write receipts.
	if receipts != nil {
		receiptData, err := rlp.EncodeToBytes(receipts)
		if err != nil {
			return fmt.Errorf("failed to encode receipts: %w", err)
		}
		if err := batch.Put(receiptKey(hash, number), receiptData); err != nil {
			return err
		}
	}

	// Write canonical hash.
	if err := batch.Put(canonicalKey(number), hash.Bytes()); err != nil {
		return err
	}

	// Write head block hash and number.
	if err := batch.Put(headBlockHashKey, hash.Bytes()); err != nil {
		return err
	}
	if err := batch.Put(headBlockNumberKey, encodeBlockNumber(number)); err != nil {
		return err
	}

	// Write hash-to-number index.
	if err := batch.Put(hashToNumberKey(hash), encodeBlockNumber(number)); err != nil {
		return err
	}

	// Write tx lookup entries.
	for i, tx := range block.Transactions {
		entry := TxLookupEntry{
			BlockHash:   hash,
			BlockNumber: number,
			Index:       uint64(i),
		}
		lookupData, err := rlp.EncodeToBytes(entry)
		if err != nil {
			return fmt.Errorf("failed to encode tx lookup: %w", err)
		}
		if err := batch.Put(txLookupKey(tx.Hash()), lookupData); err != nil {
			return err
		}
	}

	return batch.Write()
}

// ReadBlock reads a complete block (header + transactions) from the database.
// Returns nil if not found.
func (cdb *ChainDB) ReadBlock(hash types.Hash, number uint64) *L2Block {
	header := cdb.ReadHeader(hash, number)
	if header == nil {
		return nil
	}
	txs := cdb.ReadBody(hash, number)
	block := NewBlockWithHeader(header)
	block.Transactions = txs
	return block
}

// anchorKey returns the database key for an anchor record: "a" + number(8).
func anchorKey(blockNum uint64) []byte {
	key := make([]byte, 0, 1+8)
	key = append(key, anchorPrefix...)
	key = append(key, encodeBlockNumber(blockNum)...)
	return key
}

// WriteAnchorRecord writes an anchor record for the given L2 block number.
func (cdb *ChainDB) WriteAnchorRecord(record *AnchorRecord) error {
	data, err := rlp.EncodeToBytes(record)
	if err != nil {
		return fmt.Errorf("failed to encode anchor record: %w", err)
	}
	return cdb.db.Put(anchorKey(record.L2BlockNum), data)
}

// ReadAnchorRecord reads the anchor record for the given L2 block number.
// Returns nil if not found.
func (cdb *ChainDB) ReadAnchorRecord(blockNum uint64) *AnchorRecord {
	data, err := cdb.db.Get(anchorKey(blockNum))
	if err != nil {
		return nil
	}
	var record AnchorRecord
	if err := rlp.DecodeBytes(data, &record); err != nil {
		return nil
	}
	return &record
}

// WriteCovenantTxID writes the current covenant UTXO transaction ID.
func (cdb *ChainDB) WriteCovenantTxID(txid types.Hash) error {
	return cdb.db.Put(covenantTxIDKey, txid.Bytes())
}

// ReadCovenantTxID reads the current covenant UTXO transaction ID.
// Returns zero hash if not set.
func (cdb *ChainDB) ReadCovenantTxID() types.Hash {
	data, err := cdb.db.Get(covenantTxIDKey)
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(data)
}

// WriteCovenantState writes the serialized covenant state.
func (cdb *ChainDB) WriteCovenantState(state []byte) error {
	return cdb.db.Put(covenantStateKey, state)
}

// ReadCovenantState reads the serialized covenant state.
// Returns nil if not set.
func (cdb *ChainDB) ReadCovenantState() []byte {
	data, err := cdb.db.Get(covenantStateKey)
	if err != nil {
		return nil
	}
	return data
}

// SyncCheckpoint records a sync progress marker so that SyncFromBSV can
// resume from a known position in the covenant UTXO chain instead of
// replaying from genesis.
type SyncCheckpoint struct {
	CovenantTxID types.Hash
	L2BlockNum   uint64
}

// WriteSyncCheckpoint writes a sync checkpoint to the database.
func (cdb *ChainDB) WriteSyncCheckpoint(cp *SyncCheckpoint) error {
	data, err := rlp.EncodeToBytes(cp)
	if err != nil {
		return fmt.Errorf("failed to encode sync checkpoint: %w", err)
	}
	return cdb.db.Put(syncCheckpointKey, data)
}

// ReadSyncCheckpoint reads the sync checkpoint from the database.
// Returns nil if no checkpoint has been written.
func (cdb *ChainDB) ReadSyncCheckpoint() *SyncCheckpoint {
	data, err := cdb.db.Get(syncCheckpointKey)
	if err != nil {
		return nil
	}
	var cp SyncCheckpoint
	if err := rlp.DecodeBytes(data, &cp); err != nil {
		return nil
	}
	return &cp
}

// MarkReceiptsRolledBack marks all receipts in the given block range
// (fromBlock to toBlock inclusive) as rolled back. It reads each block's
// receipts, sets RolledBack=true and RolledBackAtBlock=rollbackBlock,
// then re-writes them. This is called during cascade rollback.
func (cdb *ChainDB) MarkReceiptsRolledBack(fromBlock, toBlock, rollbackBlock uint64) error {
	for blockNum := fromBlock; blockNum <= toBlock; blockNum++ {
		hash := cdb.ReadCanonicalHash(blockNum)
		if hash == (types.Hash{}) {
			// Already invalidated or never existed; skip.
			continue
		}

		receipts := cdb.ReadReceipts(hash, blockNum)
		if receipts == nil {
			continue
		}

		for _, r := range receipts {
			r.RolledBack = true
			r.RolledBackAtBlock = rollbackBlock
		}

		if err := cdb.WriteReceipts(hash, blockNum, receipts); err != nil {
			return fmt.Errorf("failed to write rolled-back receipts for block %d: %w", blockNum, err)
		}
	}
	return nil
}
