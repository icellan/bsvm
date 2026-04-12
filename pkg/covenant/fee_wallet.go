package covenant

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	"github.com/icellan/bsvm/pkg/types"
)

// FeeUTXO represents a BSV UTXO available for paying mining fees.
type FeeUTXO struct {
	TxID       types.Hash
	Vout       uint32
	Satoshis   uint64
	Script     []byte   // locking script (P2PKH)
	PubKeyHash [20]byte // extracted from the P2PKH script
}

// minViableFunding is the minimum total unspent satoshis below which the
// wallet is considered starved and unable to reliably fund covenant advances.
const minViableFunding = uint64(10000)

// FeeWallet manages BSV UTXOs used to pay mining fees for covenant-advance
// transactions. It implements a deterministic greedy UTXO selection algorithm
// so that multiple competing nodes pick the same fee inputs when given the
// same UTXO set.
type FeeWallet struct {
	mu            sync.Mutex
	utxos         []FeeUTXO
	spent         map[types.Hash]map[uint32]bool
	changeAddress []byte
	privKeys      map[string][]byte // hex(pubKeyHash) -> private key bytes
}

// NewFeeWallet creates a new fee wallet with the given change address.
// The change address is a 20-byte BSV address hash used for change outputs.
func NewFeeWallet(changeAddress []byte) *FeeWallet {
	return &FeeWallet{
		utxos:         make([]FeeUTXO, 0),
		spent:         make(map[types.Hash]map[uint32]bool),
		changeAddress: changeAddress,
		privKeys:      make(map[string][]byte),
	}
}

// AddUTXO adds a UTXO to the wallet, maintaining sorted order (descending by
// Satoshis, then ascending by TxID for deterministic tie-breaking).
func (fw *FeeWallet) AddUTXO(utxo FeeUTXO) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Find insertion point using binary search to maintain sorted order.
	idx := sort.Search(len(fw.utxos), func(i int) bool {
		return feeUTXOLess(utxo, fw.utxos[i])
	})

	// Insert at idx.
	fw.utxos = append(fw.utxos, FeeUTXO{})
	copy(fw.utxos[idx+1:], fw.utxos[idx:])
	fw.utxos[idx] = utxo
}

// AddPrivateKey stores a private key for signing fee inputs. The pubKeyHash
// must match the PubKeyHash field of any FeeUTXO this key can sign for.
func (fw *FeeWallet) AddPrivateKey(pubKeyHash [20]byte, privKey []byte) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	key := hex.EncodeToString(pubKeyHash[:])
	fw.privKeys[key] = make([]byte, len(privKey))
	copy(fw.privKeys[key], privKey)
}

// SelectUTXOs implements deterministic greedy UTXO selection. It selects the
// largest unspent UTXOs first until their sum meets or exceeds requiredSats.
// The selection is deterministic: given the same UTXO set and requirement,
// every caller gets the same result.
func (fw *FeeWallet) SelectUTXOs(requiredSats uint64) ([]FeeInput, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Collect unspent UTXOs (already sorted by AddUTXO).
	var selected []FeeInput
	var totalSelected uint64

	for i := range fw.utxos {
		u := &fw.utxos[i]
		if fw.isSpentLocked(u.TxID, u.Vout) {
			continue
		}
		selected = append(selected, FeeInput{
			TxID:     u.TxID,
			Vout:     u.Vout,
			Satoshis: u.Satoshis,
			Script:   u.Script,
		})
		totalSelected += u.Satoshis
		if totalSelected >= requiredSats {
			break
		}
	}

	if totalSelected < requiredSats {
		return nil, fmt.Errorf("fee wallet starved: have %d, need %d", totalSelected, requiredSats)
	}

	// Mark selected as spent.
	for _, inp := range selected {
		fw.markSpentLocked(inp.TxID, inp.Vout)
	}

	return selected, nil
}

// ReleaseUTXOs un-marks the given UTXOs as spent. This is called when a
// covenant advance fails or is abandoned and the UTXOs should be returned
// to the available pool.
func (fw *FeeWallet) ReleaseUTXOs(inputs []FeeInput) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	for _, inp := range inputs {
		fw.unmarkSpentLocked(inp.TxID, inp.Vout)
	}
}

// SignInput signs a BSV transaction input using SIGHASH_ALL|SIGHASH_FORKID.
// It looks up the private key by the UTXO's PubKeyHash and produces a
// scriptSig. Currently returns a placeholder signature structure — real BSV
// signing requires the full sighash preimage computation which depends on the
// BSV transaction format.
func (fw *FeeWallet) SignInput(rawTx []byte, inputIndex int, utxo FeeUTXO) ([]byte, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	key := hex.EncodeToString(utxo.PubKeyHash[:])
	privKey, ok := fw.privKeys[key]
	if !ok {
		return nil, fmt.Errorf("no private key for pubkey hash %s", key)
	}

	// Placeholder signature structure.
	// Real BSV signing (SIGHASH_ALL | SIGHASH_FORKID = 0x41) requires:
	// 1. Build sighash preimage per BIP143 (BSV fork)
	// 2. SHA256d the preimage
	// 3. Sign with secp256k1 private key
	// 4. Encode as DER + sighash byte
	// 5. Build scriptSig: <sig> <pubkey>
	//
	// For now, return a placeholder that includes the private key length
	// to confirm the key was found. The actual signing will be implemented
	// when the BSV SDK integration is complete (Milestone 5).
	_ = rawTx
	_ = inputIndex

	// Placeholder scriptSig: OP_0 (will be replaced with real signature).
	placeholder := make([]byte, 0, 2+len(privKey))
	placeholder = append(placeholder, 0x00)           // placeholder sig length
	placeholder = append(placeholder, byte(len(privKey))) // key length marker
	return placeholder, nil
}

// Balance returns the total unspent satoshis available in the wallet.
func (fw *FeeWallet) Balance() uint64 {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	var total uint64
	for i := range fw.utxos {
		u := &fw.utxos[i]
		if !fw.isSpentLocked(u.TxID, u.Vout) {
			total += u.Satoshis
		}
	}
	return total
}

// UTXOCount returns the number of unspent UTXOs in the wallet.
func (fw *FeeWallet) UTXOCount() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	count := 0
	for i := range fw.utxos {
		u := &fw.utxos[i]
		if !fw.isSpentLocked(u.TxID, u.Vout) {
			count++
		}
	}
	return count
}

// IsStarved returns true if the total unspent balance is below the minimum
// viable fee funding threshold (10000 satoshis).
func (fw *FeeWallet) IsStarved() bool {
	return fw.Balance() < minViableFunding
}

// ChangeAddress returns the configured change address for the wallet.
func (fw *FeeWallet) ChangeAddress() []byte {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	cp := make([]byte, len(fw.changeAddress))
	copy(cp, fw.changeAddress)
	return cp
}

// ConsolidateUTXOs builds a consolidation transaction that merges up to
// maxInputs of the smallest UTXOs into a single output sent to the wallet's
// change address. This reduces the UTXO set size and can improve fee
// efficiency for subsequent operations.
func (fw *FeeWallet) ConsolidateUTXOs(maxInputs int) (*BSVTx, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if maxInputs <= 0 {
		return nil, fmt.Errorf("maxInputs must be positive")
	}

	// Collect unspent UTXOs, smallest first (reverse of our sorted order).
	var unspent []FeeUTXO
	for i := len(fw.utxos) - 1; i >= 0; i-- {
		u := &fw.utxos[i]
		if !fw.isSpentLocked(u.TxID, u.Vout) {
			unspent = append(unspent, *u)
		}
	}

	if len(unspent) == 0 {
		return nil, fmt.Errorf("no unspent UTXOs to consolidate")
	}
	if len(unspent) < 2 {
		return nil, fmt.Errorf("need at least 2 unspent UTXOs to consolidate")
	}

	// Select up to maxInputs of the smallest UTXOs.
	if maxInputs > len(unspent) {
		maxInputs = len(unspent)
	}
	selected := unspent[:maxInputs]

	// Build inputs and compute total.
	inputs := make([]BSVInput, len(selected))
	var totalSats uint64
	for i, u := range selected {
		inputs[i] = BSVInput{
			PrevTxID: u.TxID,
			PrevVout: u.Vout,
			Script:   nil, // unsigned — caller signs later
			Sequence: 0xffffffff,
		}
		totalSats += u.Satoshis
	}

	// Build single output to change address.
	changeScript := buildP2PKHScript(fw.changeAddress)
	outputs := []BSVOutput{
		{
			Value:  0, // placeholder, set after fee estimation
			Script: changeScript,
		},
	}

	tx := &BSVTx{
		Version:  1,
		Inputs:   inputs,
		Outputs:  outputs,
		LockTime: 0,
	}

	// Estimate fee from serialized size.
	rawSize := uint64(len(tx.Serialize()))
	estimatedFee := (rawSize * defaultFeeRate) / 1000
	if estimatedFee == 0 {
		estimatedFee = 1
	}

	if totalSats <= estimatedFee {
		return nil, fmt.Errorf("consolidated value %d is not enough to cover fee %d", totalSats, estimatedFee)
	}

	tx.Outputs[0].Value = totalSats - estimatedFee

	return tx, nil
}

// isSpentLocked checks if an outpoint is marked as spent. Must be called with
// fw.mu held.
func (fw *FeeWallet) isSpentLocked(txID types.Hash, vout uint32) bool {
	vouts, ok := fw.spent[txID]
	if !ok {
		return false
	}
	return vouts[vout]
}

// markSpentLocked marks an outpoint as spent. Must be called with fw.mu held.
func (fw *FeeWallet) markSpentLocked(txID types.Hash, vout uint32) {
	vouts, ok := fw.spent[txID]
	if !ok {
		vouts = make(map[uint32]bool)
		fw.spent[txID] = vouts
	}
	vouts[vout] = true
}

// unmarkSpentLocked removes the spent mark from an outpoint. Must be called
// with fw.mu held.
func (fw *FeeWallet) unmarkSpentLocked(txID types.Hash, vout uint32) {
	vouts, ok := fw.spent[txID]
	if !ok {
		return
	}
	delete(vouts, vout)
	if len(vouts) == 0 {
		delete(fw.spent, txID)
	}
}

// feeUTXOLess returns true if a should come before b in the sorted order.
// Sort order: descending by Satoshis, then ascending by TxID bytes for
// deterministic tie-breaking.
func feeUTXOLess(a, b FeeUTXO) bool {
	if a.Satoshis != b.Satoshis {
		return a.Satoshis > b.Satoshis
	}
	cmp := bytes.Compare(a.TxID[:], b.TxID[:])
	if cmp != 0 {
		return cmp < 0
	}
	return a.Vout < b.Vout
}
