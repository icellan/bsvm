package bridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// depositPrefix is the DB key prefix for persisted deposits.
// Key format: "d" + txid(32 bytes) + vout(4 bytes big-endian).
var depositPrefix = []byte("d")

// horizonKey is the DB key for the persisted deposit horizon.
var horizonKey = []byte("dh")

// stalenessLimit is the maximum allowed distance (in blocks) between
// the deposit horizon and the observed BSV tip.
const stalenessLimit = 3

// BSVClient is the interface for reading BSV blockchain data.
// This is implemented by the BSV node client or a mock for testing.
type BSVClient interface {
	// GetTransaction returns a BSV transaction by its txid.
	GetTransaction(txid types.Hash) (*BSVTransaction, error)

	// GetBlockHeight returns the current BSV chain tip height.
	GetBlockHeight() (uint64, error)

	// GetBlockTransactions returns all transactions in a BSV block
	// at the given height.
	GetBlockTransactions(height uint64) ([]*BSVTransaction, error)

	// SubscribeNewBlocks returns a channel that receives new BSV
	// block heights as they are mined. The channel is closed when
	// the context is cancelled.
	SubscribeNewBlocks(ctx context.Context) (<-chan uint64, error)
}

// OverlaySubmitter is the interface for submitting deposit system
// transactions to the overlay node for inclusion in L2 blocks.
type OverlaySubmitter interface {
	// SubmitDepositTx submits a deposit system transaction for
	// inclusion in the next L2 block.
	SubmitDepositTx(tx *types.DepositTransaction) error
}

// DepositStore extends db.Database with iteration support for
// scanning persisted deposits.
type DepositStore interface {
	db.Database
	db.Iteratee
}

// depositID is a composite key for deposit deduplication, using both
// the BSV txid and the output index (vout).
type depositID struct {
	TxID types.Hash
	Vout uint32
}

// BridgeMonitor watches the BSV blockchain for deposits to the bridge
// covenant and submits corresponding system transactions to the L2
// overlay node.
type BridgeMonitor struct {
	config            Config
	bsvClient         BSVClient
	overlay           OverlaySubmitter
	db                DepositStore
	bridgeScriptHash  []byte
	localShardID      uint32
	processedDeposits map[depositID]bool
	pendingDeposits   []*Deposit
	lastHorizon       uint64
	mu                sync.Mutex
}

// NewBridgeMonitor creates a new BridgeMonitor with the given
// configuration, BSV client, overlay submitter, and deposit database.
// The database is used to persist processed deposits and the deposit
// horizon across restarts. Pass nil for the database to use in-memory
// only storage (no persistence across restarts).
func NewBridgeMonitor(config Config, bsvClient BSVClient, overlay OverlaySubmitter, store DepositStore) *BridgeMonitor {
	return &BridgeMonitor{
		config:            config,
		bsvClient:         bsvClient,
		overlay:           overlay,
		db:                store,
		processedDeposits: make(map[depositID]bool),
	}
}

// SetBridgeScriptHash sets the bridge covenant script hash used to
// identify deposit outputs. This must be called before processing
// blocks.
func (m *BridgeMonitor) SetBridgeScriptHash(scriptHash []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bridgeScriptHash = make([]byte, len(scriptHash))
	copy(m.bridgeScriptHash, scriptHash)
}

// SetLocalShardID configures the shard ID this monitor accepts deposits
// for. Deposits whose OP_RETURN encodes a different shard_id are
// rejected at parse time to prevent cross-shard credit.
func (m *BridgeMonitor) SetLocalShardID(shardID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localShardID = shardID
}

// LocalShardID returns the shard ID this monitor accepts deposits for.
func (m *BridgeMonitor) LocalShardID() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.localShardID
}

// depositKey builds the DB key for a deposit: "d" + txid(32) + vout(4 BE).
func depositKey(txid types.Hash, vout uint32) []byte {
	key := make([]byte, 1+32+4)
	key[0] = depositPrefix[0]
	copy(key[1:33], txid[:])
	binary.BigEndian.PutUint32(key[33:37], vout)
	return key
}

// encodeDeposit serializes a Deposit to bytes for DB storage.
// Format: txid(32) + vout(4) + blockHeight(8) + l2Address(20) +
// satoshiAmount(8) + confirmed(1) = 73 bytes.
func encodeDeposit(d *Deposit) []byte {
	buf := make([]byte, 73)
	copy(buf[0:32], d.BSVTxID[:])
	binary.BigEndian.PutUint32(buf[32:36], d.Vout)
	binary.BigEndian.PutUint64(buf[36:44], d.BSVBlockHeight)
	copy(buf[44:64], d.L2Address[:])
	binary.BigEndian.PutUint64(buf[64:72], d.SatoshiAmount)
	if d.Confirmed {
		buf[72] = 1
	}
	return buf
}

// decodeDeposit deserializes a Deposit from bytes.
func decodeDeposit(data []byte) (*Deposit, error) {
	if len(data) < 73 {
		return nil, fmt.Errorf("deposit data too short: %d bytes", len(data))
	}
	d := &Deposit{}
	copy(d.BSVTxID[:], data[0:32])
	d.Vout = binary.BigEndian.Uint32(data[32:36])
	d.BSVBlockHeight = binary.BigEndian.Uint64(data[36:44])
	copy(d.L2Address[:], data[44:64])
	d.SatoshiAmount = binary.BigEndian.Uint64(data[64:72])
	d.L2WeiAmount = types.SatoshisToWei(d.SatoshiAmount)
	d.Confirmed = data[72] == 1
	return d, nil
}

// PersistDeposit writes a deposit to the database and marks it as
// processed in memory. Returns an error if the database write fails.
func (m *BridgeMonitor) PersistDeposit(deposit *Deposit) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return errors.New("no database configured")
	}

	key := depositKey(deposit.BSVTxID, deposit.Vout)
	val := encodeDeposit(deposit)
	if err := m.db.Put(key, val); err != nil {
		return fmt.Errorf("failed to persist deposit: %w", err)
	}

	m.processedDeposits[depositID{deposit.BSVTxID, deposit.Vout}] = true
	return nil
}

// LoadProcessedDeposits scans the database for all persisted deposits
// and populates the in-memory processedDeposits map. It also loads
// the persisted deposit horizon. This should be called on startup
// before processing any blocks.
func (m *BridgeMonitor) LoadProcessedDeposits() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return nil
	}

	// Load all deposits with the "d" prefix. Skip keys that are not
	// exactly the expected deposit key length (37 bytes: 1 prefix +
	// 32 txid + 4 vout), since other keys like the horizon key "dh"
	// also share the "d" prefix.
	const depositKeyLen = 1 + 32 + 4
	iter := m.db.NewIterator(depositPrefix, nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		if len(key) != depositKeyLen {
			continue
		}
		val := iter.Value()
		dep, err := decodeDeposit(val)
		if err != nil {
			return fmt.Errorf("failed to decode persisted deposit: %w", err)
		}
		m.processedDeposits[depositID{dep.BSVTxID, dep.Vout}] = true
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error loading deposits: %w", err)
	}

	// Load the persisted deposit horizon.
	horizonData, err := m.db.Get(horizonKey)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return fmt.Errorf("failed to load deposit horizon: %w", err)
	}
	if err == nil && len(horizonData) == 8 {
		m.lastHorizon = binary.BigEndian.Uint64(horizonData)
	}

	return nil
}

// IsDepositProcessed checks whether a deposit identified by its BSV
// txid and vout has been processed. It first checks the in-memory map,
// then falls back to the database.
func (m *BridgeMonitor) IsDepositProcessed(txid types.Hash, vout uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check in-memory map first.
	if m.processedDeposits[depositID{txid, vout}] {
		return true
	}

	// Fall back to database lookup.
	if m.db == nil {
		return false
	}

	key := depositKey(txid, vout)
	has, err := m.db.Has(key)
	if err != nil {
		return false
	}
	return has
}

// ProcessBlock scans a BSV block's transactions for deposits to the
// bridge covenant. Valid deposits are added to the pending list if
// they need more confirmations, or processed immediately if they
// have sufficient confirmations.
func (m *BridgeMonitor) ProcessBlock(height uint64, txs []*BSVTransaction) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, tx := range txs {
		deposit := ParseDeposit(tx, m.bridgeScriptHash, m.localShardID)
		if deposit == nil {
			continue
		}

		// Check minimum deposit amount.
		if deposit.SatoshiAmount < m.config.MinDepositSatoshis {
			continue
		}

		// Skip already-processed deposits.
		if m.processedDeposits[depositID{deposit.BSVTxID, deposit.Vout}] {
			continue
		}

		// Set the block height from the block being processed.
		deposit.BSVBlockHeight = height

		m.pendingDeposits = append(m.pendingDeposits, deposit)

		// Persist deposit to DB if available.
		if m.db != nil {
			key := depositKey(deposit.BSVTxID, deposit.Vout)
			val := encodeDeposit(deposit)
			_ = m.db.Put(key, val)
		}
	}
}

// EligibleDeposits returns all pending deposits that have at least
// the required number of BSV confirmations given the current BSV
// chain tip height (horizon).
//
// The returned deposits are sorted deterministically by
// (BSVBlockHeight ASC, BSVTxID ASC) to ensure all nodes produce the
// same deposit list for the same horizon.
func (m *BridgeMonitor) EligibleDeposits(horizon uint64) []*Deposit {
	m.mu.Lock()
	defer m.mu.Unlock()

	var eligible []*Deposit
	for _, dep := range m.pendingDeposits {
		if m.processedDeposits[depositID{dep.BSVTxID, dep.Vout}] {
			continue
		}
		// A deposit at height H is eligible when horizon >= H + confirmations.
		if horizon >= dep.BSVBlockHeight+uint64(m.config.BSVConfirmations) {
			eligible = append(eligible, dep)
		}
	}

	// Sort deterministically: (block height ASC, tx index ASC, output index ASC).
	SortDeposits(eligible)

	return eligible
}

// MarkProcessed marks a deposit as processed so it will not be
// included again. This should be called after the deposit's system
// transaction has been successfully included in an L2 block.
func (m *BridgeMonitor) MarkProcessed(depositTxID types.Hash, vout uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.processedDeposits[depositID{depositTxID, vout}] = true

	// Remove from pending list.
	filtered := m.pendingDeposits[:0]
	for _, dep := range m.pendingDeposits {
		if dep.BSVTxID != depositTxID || dep.Vout != vout {
			filtered = append(filtered, dep)
		}
	}
	m.pendingDeposits = filtered
}

// IsProcessed returns true if the given deposit (txid, vout) has
// already been processed.
func (m *BridgeMonitor) IsProcessed(depositTxID types.Hash, vout uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.processedDeposits[depositID{depositTxID, vout}]
}

// PendingCount returns the number of pending (unprocessed) deposits.
func (m *BridgeMonitor) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pendingDeposits)
}

// SetDepositHorizon sets the current deposit horizon. Returns an error
// if the new horizon is less than the previous one (monotonic
// enforcement). The horizon is persisted to the database.
func (m *BridgeMonitor) SetDepositHorizon(horizon uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if horizon < m.lastHorizon {
		return fmt.Errorf("deposit horizon cannot decrease: %d < %d", horizon, m.lastHorizon)
	}

	m.lastHorizon = horizon

	// Persist to DB.
	if m.db != nil {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, horizon)
		if err := m.db.Put(horizonKey, buf); err != nil {
			return fmt.Errorf("failed to persist deposit horizon: %w", err)
		}
	}

	return nil
}

// DepositHorizon returns the current deposit horizon.
func (m *BridgeMonitor) DepositHorizon() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastHorizon
}

// Run subscribes to new BSV blocks and processes them as they arrive.
// It blocks until the context is cancelled.
func (m *BridgeMonitor) Run(ctx context.Context) error {
	blockCh, err := m.bsvClient.SubscribeNewBlocks(ctx)
	if err != nil {
		return fmt.Errorf("failed to subscribe to new blocks: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case height, ok := <-blockCh:
			if !ok {
				return nil
			}
			txs, err := m.bsvClient.GetBlockTransactions(height)
			if err != nil {
				return fmt.Errorf("failed to get block transactions at height %d: %w", height, err)
			}
			m.ProcessBlock(height, txs)
		}
	}
}

// ValidateHorizon checks that the given horizon is within the
// staleness limit of the observed BSV tip. Returns an error if
// the absolute difference between horizon and tip exceeds 3 blocks.
func (m *BridgeMonitor) ValidateHorizon(horizon uint64, observedBSVTip uint64) error {
	var diff uint64
	if horizon > observedBSVTip {
		diff = horizon - observedBSVTip
	} else {
		diff = observedBSVTip - horizon
	}

	if diff > stalenessLimit {
		return fmt.Errorf("deposit horizon %d is too far from BSV tip %d (diff=%d, limit=%d)",
			horizon, observedBSVTip, diff, stalenessLimit)
	}

	return nil
}

// EligibleDepositsAtHorizon returns all confirmed deposits up to the
// given BSV block height, sorted deterministically by
// (BSVBlockHeight ASC, BSVTxID ASC). This scans the database for
// persisted deposits and the in-memory pending list.
func (m *BridgeMonitor) EligibleDepositsAtHorizon(horizon uint64) []*Deposit {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[depositID]bool)
	var eligible []*Deposit

	// Scan persisted deposits from DB.
	const dkLen = 1 + 32 + 4
	if m.db != nil {
		iter := m.db.NewIterator(depositPrefix, nil)
		defer iter.Release()

		for iter.Next() {
			if len(iter.Key()) != dkLen {
				continue
			}
			val := iter.Value()
			dep, err := decodeDeposit(val)
			if err != nil {
				continue
			}
			id := depositID{dep.BSVTxID, dep.Vout}
			if dep.Confirmed && dep.BSVBlockHeight <= horizon && !seen[id] {
				eligible = append(eligible, dep)
				seen[id] = true
			}
		}
	}

	// Also scan in-memory pending deposits.
	for _, dep := range m.pendingDeposits {
		id := depositID{dep.BSVTxID, dep.Vout}
		if dep.Confirmed && dep.BSVBlockHeight <= horizon && !seen[id] {
			eligible = append(eligible, dep)
			seen[id] = true
		}
	}

	// Sort deterministically: (block height ASC, tx index ASC, output index ASC).
	SortDeposits(eligible)

	return eligible
}
