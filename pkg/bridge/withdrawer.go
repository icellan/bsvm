package bridge

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/icellan/bsvm/pkg/types"
)

// BridgeUTXO tracks the single bridge covenant UTXO.
type BridgeUTXO struct {
	TxID             types.Hash
	Vout             uint32
	Balance          uint64 // total BSV held in the bridge (satoshis)
	LastClaimedNonce uint64 // last withdrawal nonce claimed (sequential)
	Script           []byte // compiled bridge covenant locking script
}

// UpdateAfterWithdrawal updates the bridge UTXO state after a
// withdrawal claim is confirmed on BSV.
func (u *BridgeUTXO) UpdateAfterWithdrawal(newTxID types.Hash, amount uint64, nonce uint64) {
	u.TxID = newTxID
	u.Balance -= amount
	u.LastClaimedNonce = nonce
}

// PendingWithdrawal represents a withdrawal that has been initiated
// on L2 but not yet claimed on BSV.
type PendingWithdrawal struct {
	Nonce          uint64
	BSVAddress     []byte // 20-byte BSV address hash
	AmountSatoshis uint64
	L2BlockNum     uint64
	WithdrawalHash types.Hash
}

// WithdrawalScanner scans L2 blocks for pending withdrawal events.
type WithdrawalScanner interface {
	// ScanPendingWithdrawals returns all unclaimed withdrawals in
	// nonce order, starting from the first unclaimed nonce.
	ScanPendingWithdrawals(fromNonce uint64) ([]*PendingWithdrawal, error)
}

// CovenantAdvanceFinder locates the BSV covenant-advance transaction
// that includes a specific L2 block.
type CovenantAdvanceFinder interface {
	// FindCovenantAdvanceForBlock returns the BSV transaction that
	// advanced the covenant state to include the given L2 block.
	FindCovenantAdvanceForBlock(l2BlockNum uint64) (*BSVTransaction, error)
}

// BSVBroadcaster broadcasts raw BSV transactions.
type BSVBroadcaster interface {
	// Broadcast submits a raw BSV transaction and returns its txid.
	Broadcast(rawTx []byte) (types.Hash, error)
}

// Withdrawer orchestrates the complete withdrawal lifecycle:
// scanning for finalized withdrawals on L2, building BSV claim
// transactions, and broadcasting them.
type Withdrawer struct {
	bsvBroadcaster BSVBroadcaster
	bridgeUTXO     *BridgeUTXO
	scanner        WithdrawalScanner
	advanceFinder  CovenantAdvanceFinder
	config         WithdrawalConfig
}

// NewWithdrawer creates a new Withdrawer with the given dependencies.
func NewWithdrawer(
	broadcaster BSVBroadcaster,
	bridgeUTXO *BridgeUTXO,
	scanner WithdrawalScanner,
	advanceFinder CovenantAdvanceFinder,
	config WithdrawalConfig,
) *Withdrawer {
	return &Withdrawer{
		bsvBroadcaster: broadcaster,
		bridgeUTXO:     bridgeUTXO,
		scanner:        scanner,
		advanceFinder:  advanceFinder,
		config:         config,
	}
}

// ProcessFinalizedWithdrawals scans for finalized withdrawal events
// on L2 and processes them in strict nonce order, building and
// broadcasting BSV claim transactions for each.
func (w *Withdrawer) ProcessFinalizedWithdrawals() error {
	nextNonce := w.bridgeUTXO.LastClaimedNonce + 1
	pendingWithdrawals, err := w.scanner.ScanPendingWithdrawals(nextNonce)
	if err != nil {
		return fmt.Errorf("failed to scan pending withdrawals: %w", err)
	}

	for _, wd := range pendingWithdrawals {
		// Verify this is the next nonce in sequence.
		if wd.Nonce != w.bridgeUTXO.LastClaimedNonce+1 {
			slog.Warn("withdrawal nonce not sequential, skipping",
				"expected", w.bridgeUTXO.LastClaimedNonce+1, "got", wd.Nonce)
			continue
		}

		// Verify sufficient balance in the bridge covenant.
		if wd.AmountSatoshis > w.bridgeUTXO.Balance {
			slog.Error("insufficient balance in bridge covenant",
				"amount", wd.AmountSatoshis, "balance", w.bridgeUTXO.Balance)
			break
		}

		// Locate the covenant-advance BSV tx containing this withdrawal.
		advanceTx, err := w.advanceFinder.FindCovenantAdvanceForBlock(wd.L2BlockNum)
		if err != nil {
			return fmt.Errorf("cannot find covenant advance for block %d: %w", wd.L2BlockNum, err)
		}

		// Extract the withdrawalRoot from the advance tx's OP_RETURN.
		var withdrawalRoot types.Hash
		for _, out := range advanceTx.Outputs {
			if len(out.Script) > 0 && out.Script[0] == 0x6a {
				root := extractWithdrawalRootFromOpReturn(out.Script)
				if root != (types.Hash{}) {
					withdrawalRoot = root
					break
				}
			}
		}

		// Build SHA256 Merkle inclusion proof for this withdrawal.
		// The proof is built from the withdrawal hashes in the batch.
		// For now we construct the claim with the data we have.
		csvDelay := CSVDelayForAmount(wd.AmountSatoshis)

		claim := &WithdrawalClaim{
			BridgeTxID:     w.bridgeUTXO.TxID,
			BridgeVout:     w.bridgeUTXO.Vout,
			BridgeSats:     w.bridgeUTXO.Balance,
			BridgeScript:   w.bridgeUTXO.Script,
			BSVAddress:     wd.BSVAddress,
			SatoshiAmount:  wd.AmountSatoshis,
			Nonce:          wd.Nonce,
			WithdrawalRoot: withdrawalRoot,
			LeafIndex:      int(wd.Nonce),
			CSVDelay:       csvDelay,
		}

		claimTx, err := BuildWithdrawalClaimTx(claim)
		if err != nil {
			return fmt.Errorf("claim tx build failed for nonce %d: %w", wd.Nonce, err)
		}

		// Broadcast to BSV.
		txid, err := w.bsvBroadcaster.Broadcast(claimTx.RawTx)
		if err != nil {
			return fmt.Errorf("claim broadcast failed for nonce %d: %w", wd.Nonce, err)
		}

		slog.Info("withdrawal claimed",
			"nonce", wd.Nonce,
			"amount", wd.AmountSatoshis,
			"bsvTx", txid.Hex(),
		)

		// Update bridge UTXO tracking.
		w.bridgeUTXO.UpdateAfterWithdrawal(txid, wd.AmountSatoshis, wd.Nonce)
	}

	return nil
}

// extractWithdrawalRootFromOpReturn extracts the withdrawal root from
// an OP_RETURN batch data script. Returns the zero hash if the script
// does not contain a valid withdrawal root.
func extractWithdrawalRootFromOpReturn(script []byte) types.Hash {
	// Skip OP_RETURN opcode(s) and extract data payload.
	if len(script) < 2 || script[0] != 0x6a {
		return types.Hash{}
	}
	data := script[1:]
	if len(data) > 0 && data[0] == 0x00 {
		data = data[1:]
	}
	if len(data) == 0 {
		return types.Hash{}
	}

	// Extract pushed data.
	var payload []byte
	pushOp := data[0]
	data = data[1:]
	switch {
	case pushOp >= 0x01 && pushOp <= 0x4b:
		n := int(pushOp)
		if len(data) < n {
			return types.Hash{}
		}
		payload = data[:n]
	case pushOp == 0x4c:
		if len(data) < 1 {
			return types.Hash{}
		}
		n := int(data[0])
		if len(data) < 1+n {
			return types.Hash{}
		}
		payload = data[1 : 1+n]
	case pushOp == 0x4d:
		if len(data) < 2 {
			return types.Hash{}
		}
		n := int(data[0]) | int(data[1])<<8
		if len(data) < 2+n {
			return types.Hash{}
		}
		payload = data[2 : 2+n]
	default:
		return types.Hash{}
	}

	// Batch data layout: the withdrawalRoot is at offset 141, length 32.
	// "BSVM\x02" (5) + preStateRoot (32) + postStateRoot (32) +
	// proofHash (32) + batchDataHash (32) + chainId (8) = 141.
	const withdrawalRootOffset = 141
	if len(payload) < withdrawalRootOffset+32 {
		return types.Hash{}
	}

	var root types.Hash
	copy(root[:], payload[withdrawalRootOffset:withdrawalRootOffset+32])
	return root
}

// WithdrawalClaim holds the data needed to construct a BSV withdrawal
// claim transaction against the bridge covenant.
type WithdrawalClaim struct {
	// BridgeUTXO is the current bridge covenant UTXO being spent.
	BridgeTxID   types.Hash
	BridgeVout   uint32
	BridgeSats   uint64
	BridgeScript []byte

	// Withdrawal details.
	BSVAddress     []byte // 20-byte address hash (RIPEMD160(SHA256(pubkey)))
	SatoshiAmount  uint64
	Nonce          uint64
	WithdrawalRoot types.Hash
	MerkleProof    []types.Hash
	LeafIndex      int

	// CSVDelay is the OP_CSV delay in BSV blocks (from tiered confirmation table).
	CSVDelay uint32
}

// WithdrawalClaimTx holds the result of building a withdrawal claim transaction.
type WithdrawalClaimTx struct {
	// RawTx is the serialized BSV transaction (unsigned).
	RawTx []byte
	// TxID is the transaction hash.
	TxID types.Hash
	// NewBalance is the bridge balance after withdrawal.
	NewBalance uint64
	// CSVDelay is the OP_CHECKSEQUENCEVERIFY delay applied to the payment output.
	CSVDelay uint32
}

// CSVDelayForAmount returns the required OP_CSV delay (in BSV blocks)
// based on the withdrawal amount tiering from spec 07.
func CSVDelayForAmount(satoshis uint64) uint32 {
	switch {
	case satoshis <= 1_000_000_000: // <= 10 BSV
		return 6
	case satoshis <= 10_000_000_000: // <= 100 BSV
		return 20
	default: // > 100 BSV
		return 100
	}
}

// BuildWithdrawalClaimTx constructs the unsigned BSV transaction that
// claims a withdrawal from the bridge covenant.
//
// The transaction structure:
//
//	Input 0: Bridge covenant UTXO (with unlock script)
//	Output 0: New bridge covenant UTXO (balance reduced)
//	Output 1: CSV-locked payment to user's BSV address
//	Output 2: OP_RETURN withdrawal receipt
func BuildWithdrawalClaimTx(claim *WithdrawalClaim) (*WithdrawalClaimTx, error) {
	if claim == nil {
		return nil, fmt.Errorf("withdrawal claim must not be nil")
	}
	if claim.SatoshiAmount == 0 {
		return nil, fmt.Errorf("withdrawal amount must be positive")
	}
	if claim.BridgeSats < claim.SatoshiAmount {
		return nil, fmt.Errorf("bridge balance %d insufficient for withdrawal %d",
			claim.BridgeSats, claim.SatoshiAmount)
	}
	if len(claim.BSVAddress) != 20 {
		return nil, fmt.Errorf("BSV address must be 20 bytes, got %d", len(claim.BSVAddress))
	}
	if len(claim.BridgeScript) == 0 {
		return nil, fmt.Errorf("bridge script must not be empty")
	}

	csvDelay := claim.CSVDelay
	if csvDelay == 0 {
		csvDelay = CSVDelayForAmount(claim.SatoshiAmount)
	}

	newBalance := claim.BridgeSats - claim.SatoshiAmount

	// Build transaction.
	tx := &bsvTx{
		version:  1,
		lockTime: 0,
	}

	// Input 0: bridge covenant UTXO.
	tx.inputs = append(tx.inputs, bsvInput{
		prevTxID: claim.BridgeTxID,
		prevVout: claim.BridgeVout,
		script:   nil, // unsigned — caller signs later
		sequence: 0xffffffff,
	})

	// Output 0: new bridge covenant UTXO with reduced balance.
	tx.outputs = append(tx.outputs, bsvOutput{
		value:  newBalance,
		script: claim.BridgeScript,
	})

	// Output 1: CSV-locked P2PKH payment to user.
	csvScript := buildCSVLockedP2PKH(csvDelay, claim.BSVAddress)
	tx.outputs = append(tx.outputs, bsvOutput{
		value:  claim.SatoshiAmount,
		script: csvScript,
	})

	// Output 2: OP_RETURN withdrawal receipt.
	receiptScript := buildWithdrawalReceipt(claim.Nonce, claim.SatoshiAmount, claim.BSVAddress)
	tx.outputs = append(tx.outputs, bsvOutput{
		value:  0,
		script: receiptScript,
	})

	rawTx := tx.serialize()
	txid := tx.txID()

	return &WithdrawalClaimTx{
		RawTx:      rawTx,
		TxID:       txid,
		NewBalance: newBalance,
		CSVDelay:   csvDelay,
	}, nil
}

// buildCSVLockedP2PKH creates a CSV-locked P2PKH script:
//
//	<csvDelay> OP_CHECKSEQUENCEVERIFY OP_DROP OP_DUP OP_HASH160 <addrHash> OP_EQUALVERIFY OP_CHECKSIG
func buildCSVLockedP2PKH(csvDelay uint32, addrHash []byte) []byte {
	script := make([]byte, 0, 30)
	script = append(script, pushScriptNumber(int64(csvDelay))...)
	script = append(script, 0xb2) // OP_CHECKSEQUENCEVERIFY
	script = append(script, 0x75) // OP_DROP
	script = append(script, 0x76) // OP_DUP
	script = append(script, 0xa9) // OP_HASH160
	script = append(script, 0x14) // PUSH20
	script = append(script, addrHash...)
	script = append(script, 0x88) // OP_EQUALVERIFY
	script = append(script, 0xac) // OP_CHECKSIG
	return script
}

// pushScriptNumber encodes an integer as a Bitcoin Script minimal push.
// This follows the BIP62 minimal encoding rules.
func pushScriptNumber(n int64) []byte {
	if n == 0 {
		return []byte{0x00} // OP_0
	}
	if n >= 1 && n <= 16 {
		return []byte{byte(0x50 + n)} // OP_1 through OP_16
	}
	if n == -1 {
		return []byte{0x4f} // OP_1NEGATE
	}

	// Encode as a script number.
	negative := n < 0
	absValue := n
	if negative {
		absValue = -n
	}

	// Build the little-endian byte representation.
	result := make([]byte, 0, 8)
	for absValue > 0 {
		result = append(result, byte(absValue&0xff))
		absValue >>= 8
	}

	// If the most significant byte has the high bit set, add a byte for sign.
	if result[len(result)-1]&0x80 != 0 {
		if negative {
			result = append(result, 0x80)
		} else {
			result = append(result, 0x00)
		}
	} else if negative {
		result[len(result)-1] |= 0x80
	}

	// Wrap as a push data: length prefix + data.
	push := make([]byte, 1+len(result))
	push[0] = byte(len(result))
	copy(push[1:], result)
	return push
}

// buildWithdrawalReceipt creates an OP_RETURN script with a withdrawal receipt.
// Format: OP_FALSE OP_RETURN <BSVM\x04 + nonce(8BE) + amount(8BE) + addrHash(20)>
func buildWithdrawalReceipt(nonce uint64, amount uint64, addrHash []byte) []byte {
	data := make([]byte, 0, 40)
	data = append(data, []byte("BSVM")...) // magic
	data = append(data, 0x04)              // message type: withdrawal receipt
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	data = append(data, buf...)
	binary.BigEndian.PutUint64(buf, amount)
	data = append(data, buf...)
	data = append(data, addrHash...)
	return buildOpReturnScript(data)
}

// ---------------------------------------------------------------------------
// BSV transaction builder (internal, bridge-local)
// ---------------------------------------------------------------------------

// bsvTx is an internal BSV transaction representation for the bridge package.
type bsvTx struct {
	version  uint32
	inputs   []bsvInput
	outputs  []bsvOutput
	lockTime uint32
}

type bsvInput struct {
	prevTxID types.Hash
	prevVout uint32
	script   []byte
	sequence uint32
}

type bsvOutput struct {
	value  uint64
	script []byte
}

// serialize serializes the transaction in BSV wire format.
func (tx *bsvTx) serialize() []byte {
	buf := make([]byte, 0, 256)

	// Version.
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, tx.version)
	buf = append(buf, v...)

	// Input count.
	buf = append(buf, bsvWriteVarInt(uint64(len(tx.inputs)))...)

	// Inputs.
	for _, in := range tx.inputs {
		buf = append(buf, in.prevTxID[:]...)
		idx := make([]byte, 4)
		binary.LittleEndian.PutUint32(idx, in.prevVout)
		buf = append(buf, idx...)
		buf = append(buf, bsvWriteVarInt(uint64(len(in.script)))...)
		buf = append(buf, in.script...)
		seq := make([]byte, 4)
		binary.LittleEndian.PutUint32(seq, in.sequence)
		buf = append(buf, seq...)
	}

	// Output count.
	buf = append(buf, bsvWriteVarInt(uint64(len(tx.outputs)))...)

	// Outputs.
	for _, out := range tx.outputs {
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, out.value)
		buf = append(buf, val...)
		buf = append(buf, bsvWriteVarInt(uint64(len(out.script)))...)
		buf = append(buf, out.script...)
	}

	// Lock time.
	lt := make([]byte, 4)
	binary.LittleEndian.PutUint32(lt, tx.lockTime)
	buf = append(buf, lt...)

	return buf
}

// txID computes the double-SHA256 hash of the serialized transaction (reversed).
func (tx *bsvTx) txID() types.Hash {
	raw := tx.serialize()
	first := sha256.Sum256(raw)
	second := sha256.Sum256(first[:])
	var txid types.Hash
	for i := 0; i < 32; i++ {
		txid[i] = second[31-i]
	}
	return txid
}

// bsvWriteVarInt encodes a uint64 as a Bitcoin variable-length integer.
func bsvWriteVarInt(v uint64) []byte {
	switch {
	case v < 0xfd:
		return []byte{byte(v)}
	case v <= 0xffff:
		buf := make([]byte, 3)
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:], uint16(v))
		return buf
	case v <= 0xffffffff:
		buf := make([]byte, 5)
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:], uint32(v))
		return buf
	default:
		buf := make([]byte, 9)
		buf[0] = 0xff
		binary.LittleEndian.PutUint64(buf[1:], v)
		return buf
	}
}

// buildOpReturnScript creates an OP_FALSE OP_RETURN script with the given data.
func buildOpReturnScript(data []byte) []byte {
	script := []byte{0x00, 0x6a}
	script = append(script, bridgePushData(data)...)
	return script
}

// bridgePushData encodes data as a Bitcoin Script push operation.
func bridgePushData(data []byte) []byte {
	l := len(data)
	switch {
	case l <= 75:
		return append([]byte{byte(l)}, data...)
	case l <= 255:
		return append([]byte{0x4c, byte(l)}, data...)
	case l <= 65535:
		buf := []byte{0x4d, 0, 0}
		binary.LittleEndian.PutUint16(buf[1:], uint16(l))
		return append(buf, data...)
	default:
		buf := []byte{0x4e, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(buf[1:], uint32(l))
		return append(buf, data...)
	}
}
