package overlay

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// feeWalletPrefix is the database key prefix for fee wallet UTXOs.
var feeWalletPrefix = []byte("fw")

// FeeUTXO represents a BSV UTXO available for fee payment.
type FeeUTXO struct {
	TxID         types.Hash // BSV transaction ID
	Vout         uint32     // Output index
	Satoshis     uint64     // Amount in satoshis
	ScriptPubKey []byte     // Locking script
	Confirmed    bool       // Whether the UTXO is confirmed on BSV
}

// FeeWallet manages BSV UTXOs for paying mining fees on covenant advance
// transactions. It tracks available UTXOs, selects inputs for transactions,
// and supports consolidation of small UTXOs.
type FeeWallet struct {
	mu    sync.Mutex
	db    db.Database       // Persistent storage for UTXOs
	utxos map[string]*FeeUTXO // key: txid_hex + ":" + vout

	// Configuration
	dustLimit                      uint64 // Minimum UTXO value (default: 546 sats)
	consolidationThreshold         int    // Number of UTXOs before consolidation (default: 50)
	advancesSinceConsolidation     int    // Track advances for periodic consolidation
	maxAdvancesBeforeConsolidation int    // Default: 100
}

// NewFeeWallet creates a new fee wallet backed by the given database.
// Pass nil for in-memory only (testing).
func NewFeeWallet(database db.Database) *FeeWallet {
	return &FeeWallet{
		db:                             database,
		utxos:                          make(map[string]*FeeUTXO),
		dustLimit:                      546,
		consolidationThreshold:         50,
		maxAdvancesBeforeConsolidation: 100,
	}
}

// utxoKey returns the map key for a UTXO: hex(txid) + ":" + decimal(vout).
func utxoKey(txid types.Hash, vout uint32) string {
	return fmt.Sprintf("%s:%d", txid.Hex(), vout)
}

// dbKey returns the database key for a UTXO: prefix(2) + txid(32) + vout(4 BE).
func dbKey(txid types.Hash, vout uint32) []byte {
	key := make([]byte, len(feeWalletPrefix)+types.HashLength+4)
	copy(key, feeWalletPrefix)
	copy(key[len(feeWalletPrefix):], txid[:])
	binary.BigEndian.PutUint32(key[len(feeWalletPrefix)+types.HashLength:], vout)
	return key
}

// encodeUTXO encodes a FeeUTXO to bytes:
// satoshis(8 BE) + confirmed(1) + scriptLen(4 BE) + script.
func encodeUTXO(utxo *FeeUTXO) []byte {
	scriptLen := len(utxo.ScriptPubKey)
	buf := make([]byte, 8+1+4+scriptLen)
	binary.BigEndian.PutUint64(buf[0:8], utxo.Satoshis)
	if utxo.Confirmed {
		buf[8] = 1
	}
	binary.BigEndian.PutUint32(buf[9:13], uint32(scriptLen))
	copy(buf[13:], utxo.ScriptPubKey)
	return buf
}

// decodeUTXO decodes a FeeUTXO from a database key and value.
// Key format: prefix(2) + txid(32) + vout(4 BE).
// Value format: satoshis(8 BE) + confirmed(1) + scriptLen(4 BE) + script.
func decodeUTXO(key, value []byte) (*FeeUTXO, error) {
	prefixLen := len(feeWalletPrefix)
	if len(key) < prefixLen+types.HashLength+4 {
		return nil, fmt.Errorf("fee wallet db key too short: %d bytes", len(key))
	}
	if len(value) < 13 {
		return nil, fmt.Errorf("fee wallet db value too short: %d bytes", len(value))
	}

	utxo := &FeeUTXO{}
	copy(utxo.TxID[:], key[prefixLen:prefixLen+types.HashLength])
	utxo.Vout = binary.BigEndian.Uint32(key[prefixLen+types.HashLength:])

	utxo.Satoshis = binary.BigEndian.Uint64(value[0:8])
	utxo.Confirmed = value[8] == 1
	scriptLen := binary.BigEndian.Uint32(value[9:13])
	if uint32(len(value)-13) < scriptLen {
		return nil, fmt.Errorf("fee wallet db value truncated: script length %d but only %d bytes remain", scriptLen, len(value)-13)
	}
	utxo.ScriptPubKey = make([]byte, scriptLen)
	copy(utxo.ScriptPubKey, value[13:13+scriptLen])
	return utxo, nil
}

// AddUTXO adds a new UTXO to the wallet.
func (fw *FeeWallet) AddUTXO(utxo *FeeUTXO) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	key := utxoKey(utxo.TxID, utxo.Vout)
	fw.utxos[key] = utxo

	if err := fw.persistUTXO(utxo); err != nil {
		slog.Error("failed to persist fee wallet utxo", "txid", utxo.TxID.Hex(), "vout", utxo.Vout, "err", err)
		return err
	}
	return nil
}

// RemoveUTXO removes a UTXO (after spending). Removing a nonexistent
// UTXO is a no-op.
func (fw *FeeWallet) RemoveUTXO(txid types.Hash, vout uint32) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	key := utxoKey(txid, vout)
	if _, ok := fw.utxos[key]; !ok {
		return nil // no-op for nonexistent
	}
	delete(fw.utxos, key)

	if err := fw.deleteUTXO(txid, vout); err != nil {
		slog.Error("failed to delete fee wallet utxo from db", "txid", txid.Hex(), "vout", vout, "err", err)
		return err
	}
	return nil
}

// SelectUTXOs selects UTXOs to cover the target amount using a greedy
// algorithm (largest-first). Returns selected UTXOs and total value.
// Returns an error if insufficient funds.
func (fw *FeeWallet) SelectUTXOs(targetSatoshis uint64) ([]*FeeUTXO, uint64, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if targetSatoshis == 0 {
		return nil, 0, fmt.Errorf("target satoshis must be greater than zero")
	}

	// Collect all UTXOs.
	all := make([]*FeeUTXO, 0, len(fw.utxos))
	var totalBalance uint64
	for _, u := range fw.utxos {
		all = append(all, u)
		totalBalance += u.Satoshis
	}

	if totalBalance < targetSatoshis {
		return nil, 0, fmt.Errorf("insufficient funds: have %d satoshis, need %d", totalBalance, targetSatoshis)
	}

	// Sort largest-first.
	sort.Slice(all, func(i, j int) bool {
		return all[i].Satoshis > all[j].Satoshis
	})

	// Check if a single UTXO suffices.
	if all[0].Satoshis >= targetSatoshis {
		return []*FeeUTXO{all[0]}, all[0].Satoshis, nil
	}

	// Greedily pick UTXOs until target is met.
	var selected []*FeeUTXO
	var accumulated uint64
	for _, u := range all {
		selected = append(selected, u)
		accumulated += u.Satoshis
		if accumulated >= targetSatoshis {
			break
		}
	}

	return selected, accumulated, nil
}

// Balance returns the total balance of all UTXOs in satoshis.
func (fw *FeeWallet) Balance() uint64 {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	var total uint64
	for _, u := range fw.utxos {
		total += u.Satoshis
	}
	return total
}

// UTXOCount returns the number of UTXOs in the wallet.
func (fw *FeeWallet) UTXOCount() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return len(fw.utxos)
}

// NeedsConsolidation returns true if the wallet has too many small UTXOs
// and should consolidate them into fewer larger ones.
func (fw *FeeWallet) NeedsConsolidation() bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	return len(fw.utxos) >= fw.consolidationThreshold ||
		fw.advancesSinceConsolidation >= fw.maxAdvancesBeforeConsolidation
}

// ConsolidationInputs returns all UTXOs that should be consolidated.
// After calling this, the caller builds a consolidation transaction,
// broadcasts it, then calls AddUTXO with the consolidated output
// and RemoveUTXO for each spent input.
func (fw *FeeWallet) ConsolidationInputs() []*FeeUTXO {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	inputs := make([]*FeeUTXO, 0, len(fw.utxos))
	for _, u := range fw.utxos {
		inputs = append(inputs, u)
	}
	return inputs
}

// IsStarved returns true if the wallet has insufficient funds to cover
// a typical covenant advance fee (estimated at 1000 satoshis).
func (fw *FeeWallet) IsStarved() bool {
	return fw.Balance() < 1000
}

// Address returns the P2PKH address of the fee wallet. This is a
// placeholder until the actual BSV key derivation is implemented.
func (fw *FeeWallet) Address() string {
	return ""
}

// RecordAdvance increments the advance counter for consolidation timing.
func (fw *FeeWallet) RecordAdvance() {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.advancesSinceConsolidation++
}

// LoadFromDB loads all persisted UTXOs from the database. The database
// must implement the db.Iteratee interface for prefix iteration.
func (fw *FeeWallet) LoadFromDB() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.db == nil {
		return nil
	}

	iterDB, ok := fw.db.(db.Iteratee)
	if !ok {
		return fmt.Errorf("database does not support iteration")
	}

	iter := iterDB.NewIterator(feeWalletPrefix, nil)
	defer iter.Release()

	for iter.Next() {
		utxo, err := decodeUTXO(iter.Key(), iter.Value())
		if err != nil {
			slog.Error("failed to decode fee wallet utxo from db", "err", err)
			continue
		}
		key := utxoKey(utxo.TxID, utxo.Vout)
		fw.utxos[key] = utxo
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("fee wallet db iteration error: %w", err)
	}
	return nil
}

// persistUTXO writes a single UTXO to the database.
func (fw *FeeWallet) persistUTXO(utxo *FeeUTXO) error {
	if fw.db == nil {
		return nil
	}
	return fw.db.Put(dbKey(utxo.TxID, utxo.Vout), encodeUTXO(utxo))
}

// deleteUTXO removes a single UTXO from the database.
func (fw *FeeWallet) deleteUTXO(txid types.Hash, vout uint32) error {
	if fw.db == nil {
		return nil
	}
	return fw.db.Delete(dbKey(txid, vout))
}
