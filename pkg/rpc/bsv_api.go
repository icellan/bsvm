package rpc

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/overlay"
)

// WithdrawalProofData contains the Merkle proof data for a withdrawal claim.
type WithdrawalProofData struct {
	Root        [32]byte // Merkle root of the withdrawal tree
	Proof       [][]byte // Merkle siblings (auth path)
	LeafIndex   uint64   // Index of this withdrawal leaf in the tree
	BlockNumber uint64   // L2 block number where this withdrawal was proven
}

// WithdrawalStore provides access to proven withdrawal Merkle proofs.
// Implementations are responsible for persisting proof data produced by the
// SP1 prover.
type WithdrawalStore interface {
	// GetWithdrawalProof returns the Merkle proof data for a withdrawal
	// identified by its nonce. Returns nil, nil if no proof is available yet.
	GetWithdrawalProof(nonce uint64) (*WithdrawalProofData, error)
}

// feeWalletAccessor is an interface for accessing fee wallet information.
// This avoids a hard dependency on the FeeWallet being wired into the
// overlay node.
type feeWalletAccessor interface {
	Balance() uint64
	UTXOCount() int
	IsStarved() bool
	Address() string
}

// BsvAPI implements the bsv_* namespace of the JSON-RPC API. These are
// BSV-specific extensions that provide visibility into the L2's covenant
// chain, confirmation status, and shard information.
type BsvAPI struct {
	overlay         *overlay.OverlayNode
	feeWallet       feeWalletAccessor
	withdrawalStore WithdrawalStore
	bridge          BridgeSnapshotProvider
}

// NewBsvAPI creates a new BsvAPI instance.
func NewBsvAPI(overlayNode *overlay.OverlayNode) *BsvAPI {
	return &BsvAPI{overlay: overlayNode}
}

// SetFeeWallet sets the fee wallet accessor for balance queries.
func (api *BsvAPI) SetFeeWallet(fw feeWalletAccessor) {
	api.feeWallet = fw
}

// SetWithdrawalStore sets the withdrawal store for Merkle proof lookups.
// When set, BuildWithdrawalClaim can return full proof data for proven
// withdrawals instead of just "pending_proof" status.
func (api *BsvAPI) SetWithdrawalStore(store WithdrawalStore) {
	api.withdrawalStore = store
}

// ShardInfo returns basic shard information including chain tips.
// This implements bsv_shardInfo.
func (api *BsvAPI) ShardInfo() map[string]interface{} {
	cm := api.overlay.CovenantManager()
	gov := cm.GovernanceConfig()

	govInfo := map[string]interface{}{
		"mode":   gov.Mode.String(),
		"frozen": cm.CurrentState().Frozen != 0,
	}
	if gov.Mode == covenant.GovernanceMultiSig {
		govInfo["threshold"] = EncodeUint64(uint64(gov.Threshold))
		govInfo["keyCount"] = EncodeUint64(uint64(len(gov.Keys)))
	}

	return map[string]interface{}{
		"shardId":             EncodeUint64(uint64(api.overlay.Config().ChainID)),
		"chainId":             EncodeUint64(uint64(api.overlay.Config().ChainID)),
		"genesisCovenantTxId": cm.GenesisTxID().Hex(),
		"peerCount":           EncodeUint64(0), // TODO: wire in network peer count
		"executionTip":        EncodeUint64(api.overlay.ExecutionTip()),
		"provenTip":           EncodeUint64(api.overlay.ProvenTip()),
		"cachedChainLength":   EncodeUint64(uint64(api.overlay.TxCacheRef().Len())),
		"governance":          govInfo,
	}
}

// GetConfirmationStatus returns the confirmation status for a given L2 block
// number. This implements bsv_getConfirmationStatus.
func (api *BsvAPI) GetConfirmationStatus(blockNum uint64) map[string]interface{} {
	provenTip := api.overlay.ProvenTip()
	confirmedTip := api.overlay.ConfirmedTip()
	finalizedTip := api.overlay.FinalizedTip()

	// Determine BSV tx ID and confirmation count from the TxCache.
	var bsvTxID string
	var confirmations uint64
	entry := api.overlay.TxCacheRef().GetByL2Block(blockNum)
	if entry != nil {
		bsvTxID = "0x" // no BSV tx yet for unconfirmed entries
	} else {
		bsvTxID = "0x"
	}

	// Estimate confirmations based on which tip the block falls within.
	isConfirmed := confirmedTip > 0 && blockNum <= confirmedTip
	if blockNum <= finalizedTip && finalizedTip > 0 {
		confirmations = 6 // at least 6
		isConfirmed = true
	} else if isConfirmed {
		confirmations = 1 // at least 1
	}

	return map[string]interface{}{
		"l2BlockNumber": EncodeUint64(blockNum),
		"bsvTxId":       bsvTxID,
		"confirmations": EncodeUint64(confirmations),
		"confirmed":     isConfirmed,
		"safe":          blockNum <= provenTip,
		"finalized":     blockNum <= finalizedTip,
	}
}

// FeeWalletBalance returns the fee wallet balance in satoshis and the P2PKH
// address. The response matches the spec 05 FeeWalletBalanceResult.
// This implements bsv_feeWalletBalance.
func (api *BsvAPI) FeeWalletBalance() map[string]interface{} {
	if api.feeWallet == nil {
		return map[string]interface{}{
			"balance": EncodeUint64(0),
			"address": "",
		}
	}

	return map[string]interface{}{
		"balance": EncodeUint64(api.feeWallet.Balance()),
		"address": api.feeWallet.Address(),
	}
}


// GetCovenantTip returns the current covenant UTXO information including
// the BSV transaction ID, L2 block number, state root, and confirmation
// status. Field names match the spec 05 CovenantTipResult.
// This implements bsv_getCovenantTip.
func (api *BsvAPI) GetCovenantTip() map[string]interface{} {
	cm := api.overlay.CovenantManager()
	state := cm.CurrentState()

	confirmedTip := api.overlay.ConfirmedTip()
	// Block 0 (genesis) is only considered confirmed if confirmations
	// have actually been observed (confirmedTip is advanced by the BSV
	// confirmation monitor, not by default).
	confirmed := confirmedTip > 0 && state.BlockNumber <= confirmedTip
	result := map[string]interface{}{
		"bsvTxId":       cm.CurrentTxID().Hex(),
		"l2BlockNumber": EncodeUint64(state.BlockNumber),
		"stateRoot":     state.StateRoot.Hex(),
		"confirmed":     confirmed,
	}
	if confirmed {
		result["bsvBlockHeight"] = EncodeUint64(0) // actual BSV height not yet tracked
	}
	return result
}

// GetGovernanceState returns the current governance configuration including
// the governance mode, frozen status, governance keys, and multisig threshold.
// This implements bsv_getGovernanceState.
func (api *BsvAPI) GetGovernanceState() map[string]interface{} {
	cm := api.overlay.CovenantManager()
	state := cm.CurrentState()
	gov := cm.GovernanceConfig()

	// Encode keys as hex strings.
	keys := make([]string, len(gov.Keys))
	for i, key := range gov.Keys {
		keys[i] = "0x" + hex.EncodeToString(key)
	}

	return map[string]interface{}{
		"mode":      gov.Mode.String(),
		"frozen":    state.Frozen != 0,
		"keys":      keys,
		"threshold": gov.Threshold,
	}
}

// GetCachedChainLength returns the number of unconfirmed covenant
// transactions in the cache. This implements bsv_getCachedChainLength.
func (api *BsvAPI) GetCachedChainLength() string {
	return EncodeUint64(uint64(api.overlay.TxCacheRef().Len()))
}

// PeerCount returns the number of connected peers. Returns "0x0" until the
// network manager is wired in. This implements bsv_peerCount.
func (api *BsvAPI) PeerCount() string {
	return "0x0"
}

// BuildWithdrawalClaim returns the unsigned BSV transaction data and Merkle
// proof structure needed to claim a withdrawal from the bridge covenant.
// The withdrawal hash is computed as hash256(bsvAddress || amount_be || nonce_be)
// where hash256 is double-SHA256 (matching BSV's native OP_HASH256).
//
// When a WithdrawalStore is configured and the withdrawal has been proven, the
// response includes the full Merkle proof, withdrawal root, and an unsigned BSV
// transaction template. Otherwise, the status is "pending_proof".
//
// This implements bsv_buildWithdrawalClaim.
func (api *BsvAPI) BuildWithdrawalClaim(bsvAddress string, satoshiAmount uint64, nonce uint64) (interface{}, error) {
	// Decode and validate BSV address (hex-encoded, 20 bytes).
	addrBytes, err := hex.DecodeString(stripHexPrefix(bsvAddress))
	if err != nil {
		return nil, fmt.Errorf("invalid bsv address hex: %w", err)
	}
	if len(addrBytes) != 20 {
		return nil, fmt.Errorf("bsv address must be 20 bytes, got %d", len(addrBytes))
	}
	if satoshiAmount == 0 {
		return nil, fmt.Errorf("satoshi amount must be greater than zero")
	}

	// Compute withdrawal hash: hash256(bsvAddress || amount_be || nonce_be)
	// where hash256 = SHA256(SHA256(data)), matching BSV OP_HASH256.
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, satoshiAmount)
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)

	preimage := make([]byte, 0, 36)
	preimage = append(preimage, addrBytes...)
	preimage = append(preimage, amountBytes...)
	preimage = append(preimage, nonceBytes...)

	first := sha256.Sum256(preimage)
	withdrawalHash := sha256.Sum256(first[:])

	result := map[string]interface{}{
		"bsvAddress":     "0x" + hex.EncodeToString(addrBytes),
		"satoshiAmount":  EncodeUint64(satoshiAmount),
		"nonce":          EncodeUint64(nonce),
		"withdrawalHash": "0x" + hex.EncodeToString(withdrawalHash[:]),
	}

	// If no withdrawal store is configured, return pending status.
	if api.withdrawalStore == nil {
		result["status"] = "pending_proof"
		result["unsignedTx"] = nil
		result["merkleProof"] = nil
		result["withdrawalRoot"] = nil
		return result, nil
	}

	// Look up the proof for this withdrawal.
	proof, err := api.withdrawalStore.GetWithdrawalProof(nonce)
	if err != nil {
		return nil, fmt.Errorf("withdrawal store lookup failed: %w", err)
	}

	if proof == nil {
		result["status"] = "pending_proof"
		result["unsignedTx"] = nil
		result["merkleProof"] = nil
		result["withdrawalRoot"] = nil
		return result, nil
	}

	// Proof is available -- build the full response.
	result["status"] = "proven"
	result["withdrawalRoot"] = "0x" + hex.EncodeToString(proof.Root[:])
	result["blockNumber"] = EncodeUint64(proof.BlockNumber)
	result["leafIndex"] = EncodeUint64(proof.LeafIndex)

	// Encode Merkle proof siblings as hex strings.
	merkleProof := make([]string, len(proof.Proof))
	for i, sibling := range proof.Proof {
		merkleProof[i] = "0x" + hex.EncodeToString(sibling)
	}
	result["merkleProof"] = merkleProof

	// Build an unsigned BSV transaction template for the withdrawal claim.
	// The actual transaction construction requires the current covenant UTXO
	// which comes from the covenant manager. This provides the skeleton.
	cm := api.overlay.CovenantManager()
	covenantTxID := cm.CurrentTxID()
	unsignedTx := map[string]interface{}{
		"version":       1,
		"covenantTxId":  covenantTxID.Hex(),
		"covenantVout":  0,
		"recipientHash": "0x" + hex.EncodeToString(addrBytes),
		"satoshis":      EncodeUint64(satoshiAmount),
	}
	result["unsignedTx"] = unsignedTx

	return result, nil
}

// stripHexPrefix removes the "0x" or "0X" prefix from a hex string if present.
func stripHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
