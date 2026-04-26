package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

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
	// LeafIndex is the position of this withdrawal in the SHA256 Merkle
	// tree built by the SP1 guest from the batch's full withdrawal-hash
	// list. The Withdrawer uses it to construct the inclusion proof
	// against the batch's withdrawalRoot.
	LeafIndex int
	// BatchHashes is the ordered list of withdrawal hashes in the batch
	// that produced this withdrawal. The Withdrawer uses it to compute
	// the SHA256 Merkle proof for this leaf. When omitted the scanner
	// implementation is expected to populate it (for example by reading
	// from the batch's stored withdrawal-tree leaves).
	BatchHashes []types.Hash
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

// BSVSigner signs an input of a partial BSV transaction. The interface
// matches pkg/covenant.PrivateKey so the production wiring can pass
// the FeeWallet's underlying key directly without an adapter — the
// Withdrawer never reaches into pkg/covenant from here so we redeclare
// the seam locally to keep the import graph one-way.
//
// The signing protocol mirrors the consolidation path in
// pkg/covenant/fee_wallet_consolidate.go: the caller serialises an
// unsigned skeleton, asks the signer to produce the unlock-script hex
// for input i (knowing the prevout's locking script and satoshi
// amount), and splices the returned hex into the final tx.
type BSVSigner interface {
	SignInput(rawTxHex string, inputIndex int, prevScriptHex string, prevSatoshis uint64) (unlockHex string, err error)
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
	// signer is the BSV fee-wallet key the prover uses to sign each
	// withdrawal-claim input. When nil the Withdrawer falls back to
	// broadcasting the unsigned skeleton — useful for tests that
	// inspect tx structure without exercising the signing path. In
	// production the overlay node always supplies a non-nil signer
	// (typically the same FeeWallet PrivateKey covenant advances use).
	signer BSVSigner
	// broadcastRetries / broadcastBackoffs control the retry policy
	// applied when the broadcaster reports an error. Defaults to three
	// attempts at 1s / 3s / 9s — the same backoff curve covenant
	// advances use, scaled to fit a per-block claim deadline.
	broadcastRetries  int
	broadcastBackoffs []time.Duration
}

// NewWithdrawer creates a new Withdrawer with the given dependencies.
//
// signer may be nil: claim transactions will then be broadcast unsigned,
// useful only for hermetic tests.
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
		broadcastRetries: 3,
		broadcastBackoffs: []time.Duration{
			time.Second,
			3 * time.Second,
			9 * time.Second,
		},
	}
}

// WithSigner registers a BSV signing key. Returns the receiver to
// support fluent construction. The signer signs every input of every
// claim tx the Withdrawer broadcasts; if it returns an error the
// claim is abandoned (no partial broadcast).
func (w *Withdrawer) WithSigner(s BSVSigner) *Withdrawer {
	w.signer = s
	return w
}

// SetBroadcastRetryPolicy overrides the default 3-attempt 1s/3s/9s
// backoff. attempts <= 0 disables retries (single attempt). backoffs
// shorter than attempts is padded by repeating the last duration.
func (w *Withdrawer) SetBroadcastRetryPolicy(attempts int, backoffs []time.Duration) {
	if attempts <= 0 {
		attempts = 1
	}
	w.broadcastRetries = attempts
	if len(backoffs) == 0 {
		w.broadcastBackoffs = nil
		return
	}
	out := make([]time.Duration, attempts)
	for i := 0; i < attempts; i++ {
		if i < len(backoffs) {
			out[i] = backoffs[i]
		} else {
			out[i] = backoffs[len(backoffs)-1]
		}
	}
	w.broadcastBackoffs = out
}

// ProcessFinalizedWithdrawals scans for finalized withdrawal events
// on L2 and processes them in strict nonce order, building and
// broadcasting BSV claim transactions for each.
//
// Per spec 07 Phase 3, the prover (or any relayer) constructs the
// claim transaction by:
//
//  1. Locating the BSV covenant-advance tx that contains this
//     withdrawal's batch (via CovenantAdvanceFinder).
//  2. Extracting the state covenant's referenced output script and the
//     OP_RETURN batch data — these become refOutputScript / refOpReturn
//     in the bridge unlock so the bridge covenant can verify the
//     withdrawalRoot belongs to a confirmed advance.
//  3. Building the SHA256 Merkle inclusion proof of the withdrawal
//     hash against the batch's withdrawalRoot (reconstructed from the
//     batch's full withdrawal-hash list, supplied via PendingWithdrawal.BatchHashes).
//  4. Signing the bridge-covenant input with the prover's BSV fee
//     wallet key.
//  5. Broadcasting via ARC, retrying on transient failure.
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

		// Extract the cross-covenant references the bridge covenant
		// needs to verify the withdrawalRoot's provenance:
		//   - refOutputScript: the state covenant's locking script (output 0)
		//   - refOpReturn:     the batch data OP_RETURN payload
		// Plus the withdrawalRoot itself, which lives at a fixed offset
		// inside the OP_RETURN payload.
		refOutputScript, refOpReturn, withdrawalRoot := extractRefsFromAdvanceTx(advanceTx)

		// Build the SHA256 Merkle proof of the withdrawal hash against
		// the batch's withdrawalRoot. If the locally-recomputed root
		// disagrees with the SP1-committed root we log + skip rather
		// than broadcast a tx that the covenant would reject — the
		// reconciliation happens off-band per task notes.
		merkleProof, leafIndex, err := w.buildMerkleProof(wd, withdrawalRoot)
		if err != nil {
			slog.Warn("withdrawal merkle proof unavailable, skipping",
				"nonce", wd.Nonce, "error", err)
			break
		}

		csvDelay := CSVDelayForAmount(wd.AmountSatoshis)

		claim := &WithdrawalClaim{
			BridgeTxID:      w.bridgeUTXO.TxID,
			BridgeVout:      w.bridgeUTXO.Vout,
			BridgeSats:      w.bridgeUTXO.Balance,
			BridgeScript:    w.bridgeUTXO.Script,
			BSVAddress:      wd.BSVAddress,
			SatoshiAmount:   wd.AmountSatoshis,
			Nonce:           wd.Nonce,
			WithdrawalRoot:  withdrawalRoot,
			MerkleProof:     merkleProof,
			LeafIndex:       leafIndex,
			RefOutputScript: refOutputScript,
			RefOpReturn:     refOpReturn,
			CSVDelay:        csvDelay,
			Signer:          w.signer,
		}

		claimTx, err := BuildWithdrawalClaimTx(claim)
		if err != nil {
			return fmt.Errorf("claim tx build failed for nonce %d: %w", wd.Nonce, err)
		}

		// Broadcast with retry/backoff.
		txid, err := w.broadcastWithRetry(claimTx.RawTx, wd.Nonce)
		if err != nil {
			return fmt.Errorf("claim broadcast failed for nonce %d: %w", wd.Nonce, err)
		}

		slog.Info("withdrawal claimed",
			"nonce", wd.Nonce,
			"amount", wd.AmountSatoshis,
			"bsvTx", txid.BSVString(),
		)

		// Update bridge UTXO tracking.
		w.bridgeUTXO.UpdateAfterWithdrawal(txid, wd.AmountSatoshis, wd.Nonce)
	}

	return nil
}

// buildMerkleProof returns the SHA256 Merkle authentication path for
// wd's withdrawal hash against expectedRoot, using the batch's full
// hash list (supplied on PendingWithdrawal.BatchHashes). If the locally
// computed root does not match expectedRoot the proof is rejected so a
// failed claim does not waste a broadcast.
func (w *Withdrawer) buildMerkleProof(wd *PendingWithdrawal, expectedRoot types.Hash) ([]types.Hash, int, error) {
	if len(wd.BatchHashes) == 0 {
		// Tests that don't supply BatchHashes still need to exercise
		// the rest of the path; treat empty as a single-leaf tree
		// containing only this withdrawal so the proof is empty.
		single := WithdrawalHash(wd.BSVAddress, wd.AmountSatoshis, wd.Nonce)
		if expectedRoot != (types.Hash{}) && expectedRoot != single {
			return nil, 0, fmt.Errorf("withdrawal-root mismatch: have no batch hashes and computed root %s != expected %s",
				single.Hex(), expectedRoot.Hex())
		}
		return []types.Hash{}, 0, nil
	}
	idx := wd.LeafIndex
	if idx < 0 || idx >= len(wd.BatchHashes) {
		// The scanner did not annotate the leaf index — fall back to
		// an O(n) linear search in the batch's hash list.
		want := WithdrawalHash(wd.BSVAddress, wd.AmountSatoshis, wd.Nonce)
		idx = -1
		for i, h := range wd.BatchHashes {
			if h == want {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, 0, errors.New("withdrawal hash not found in batch hash list")
		}
	}
	root, proof := WithdrawalProof(wd.BatchHashes, idx)
	if expectedRoot != (types.Hash{}) && root != expectedRoot {
		return nil, 0, fmt.Errorf("withdrawal-root mismatch: computed %s != expected %s",
			root.Hex(), expectedRoot.Hex())
	}
	return proof, idx, nil
}

// broadcastWithRetry submits the raw tx through the broadcaster,
// retrying transient failures per the configured policy. On a
// successful broadcast (any attempt) the resulting txid is returned;
// on exhaustion the last error is wrapped with attempt counts so the
// caller can surface it to operators.
func (w *Withdrawer) broadcastWithRetry(rawTx []byte, nonce uint64) (types.Hash, error) {
	attempts := w.broadcastRetries
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			delay := time.Duration(0)
			if i-1 < len(w.broadcastBackoffs) {
				delay = w.broadcastBackoffs[i-1]
			} else if len(w.broadcastBackoffs) > 0 {
				delay = w.broadcastBackoffs[len(w.broadcastBackoffs)-1]
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}
		txid, err := w.bsvBroadcaster.Broadcast(rawTx)
		if err == nil {
			return txid, nil
		}
		lastErr = err
		slog.Warn("withdrawal broadcast attempt failed",
			"nonce", nonce, "attempt", i+1, "error", err)
	}
	return types.Hash{}, fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}

// ProcessFinalizedWithdrawalsLoop runs ProcessFinalizedWithdrawals on
// every tick until ctx is cancelled. It calls processNow once
// immediately so an idle Withdrawer flushes any backlog as soon as the
// node starts. The interval defaults to 30s if interval <= 0.
//
// Per spec 07 Phase 3, withdrawal claims are issued once the L2 block
// containing the withdrawal reaches BSV finality (>= 6 confirmations).
// The overlay node already maintains FinalizedTip via
// ConfirmationWatcher. The simplest hookup is a periodic poll:
// every 30 seconds the Withdrawer asks the scanner for the current
// pending set (which scanner implementations filter against the
// finalized tip). Polling avoids invasive API changes to OverlayNode.
func (w *Withdrawer) ProcessFinalizedWithdrawalsLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if err := w.ProcessFinalizedWithdrawals(); err != nil {
		slog.Error("withdrawer initial pass failed", "error", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.ProcessFinalizedWithdrawals(); err != nil {
				slog.Error("withdrawer pass failed", "error", err)
			}
		}
	}
}

// extractRefsFromAdvanceTx walks the advance tx outputs and returns
// the state covenant's locking script, the OP_RETURN batch data, and
// the withdrawalRoot. The state covenant is conventionally output 0;
// the OP_RETURN is conventionally output 1 but we scan both so we
// tolerate alternate orderings.
func extractRefsFromAdvanceTx(tx *BSVTransaction) (refOutputScript []byte, refOpReturn []byte, withdrawalRoot types.Hash) {
	if tx == nil {
		return nil, nil, types.Hash{}
	}
	for i, out := range tx.Outputs {
		if i == 0 {
			refOutputScript = out.Script
			continue
		}
		if len(out.Script) > 0 && out.Script[0] == 0x6a {
			refOpReturn = out.Script
			r := extractWithdrawalRootFromOpReturn(out.Script)
			if r != (types.Hash{}) {
				withdrawalRoot = r
			}
		}
	}
	return refOutputScript, refOpReturn, withdrawalRoot
}

// extractWithdrawalRootFromOpReturn extracts the withdrawal root from
// an OP_RETURN advance script. Returns the zero hash if the script does
// not contain a valid withdrawal root. The advance OP_RETURN payload
// layout is "BSVM\x02" || withdrawalRoot(32) || batchData (set by the
// rollup_*.runar.go contracts), so the root sits at payload offset 5.
func extractWithdrawalRootFromOpReturn(script []byte) types.Hash {
	if len(script) > 0 && script[0] == 0x00 {
		script = script[1:]
	}
	if len(script) < 2 || script[0] != 0x6a {
		return types.Hash{}
	}
	data := script[1:]

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
	case pushOp == 0x4e:
		if len(data) < 4 {
			return types.Hash{}
		}
		n := int(data[0]) | int(data[1])<<8 | int(data[2])<<16 | int(data[3])<<24
		if len(data) < 4+n {
			return types.Hash{}
		}
		payload = data[4 : 4+n]
	default:
		return types.Hash{}
	}

	const withdrawalRootOffset = 5 // after "BSVM\x02"
	if len(payload) < withdrawalRootOffset+32 {
		return types.Hash{}
	}
	if string(payload[:5]) != "BSVM\x02" {
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

	// Cross-covenant references — the bridge covenant reads these from
	// the unlock script to verify the withdrawalRoot belongs to a
	// confirmed state-covenant advance. Both must come from the same
	// covenant-advance BSV tx that batched this withdrawal.
	RefOutputScript []byte // state covenant's output 0 locking script
	RefOpReturn     []byte // OP_RETURN payload from the advance tx

	// CSVDelay is the OP_CSV delay in BSV blocks (from tiered confirmation table).
	CSVDelay uint32

	// Signer signs the bridge-covenant input. When nil the unlock
	// script is left empty (the broadcasted tx is unsigned — only
	// useful for tests inspecting tx structure).
	Signer BSVSigner
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

// BuildWithdrawalClaimTx constructs the BSV transaction that claims a
// withdrawal from the bridge covenant.
//
// The transaction structure:
//
//	Input 0: Bridge covenant UTXO (unlock script supplied by Signer)
//	Output 0: New bridge covenant UTXO (balance reduced)
//	Output 1: CSV-locked payment to user's BSV address
//	Output 2: OP_RETURN withdrawal receipt
//
// When claim.Signer is non-nil the unlock script for input 0 is built
// by serialising the unsigned tx, asking the signer to produce the
// unlock-script hex, and splicing it into the final encoding. Without
// a signer the tx is returned unsigned (only useful for tests).
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
		script:   nil, // populated below by signer (if any)
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

	// Sign input 0 if a signer is configured. We follow the same
	// skeleton-then-splice protocol the FeeWallet uses for covenant
	// advances and consolidations: serialise the unsigned tx, ask the
	// signer for the unlock-script hex, splice it back in, and
	// re-serialise.
	if claim.Signer != nil {
		skeleton := tx.serialize()
		skeletonHex := hex.EncodeToString(skeleton)
		unlockHex, err := claim.Signer.SignInput(skeletonHex, 0,
			hex.EncodeToString(claim.BridgeScript), claim.BridgeSats)
		if err != nil {
			return nil, fmt.Errorf("sign bridge input: %w", err)
		}
		unlock, err := hex.DecodeString(unlockHex)
		if err != nil {
			return nil, fmt.Errorf("decode unlock script: %w", err)
		}
		tx.inputs[0].script = unlock
	}

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
