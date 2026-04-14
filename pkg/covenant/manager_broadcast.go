package covenant

import (
	"context"
	"errors"
	"fmt"
)

// SetBroadcastClient attaches a broadcast client to the manager. After
// this, BroadcastAdvance can be called to push covenant advances to BSV.
func (cm *CovenantManager) SetBroadcastClient(client BroadcastClient) {
	cm.broadcastClient = client
}

// BroadcastClient returns the currently attached broadcast client, or nil.
func (cm *CovenantManager) BroadcastClient() BroadcastClient {
	return cm.broadcastClient
}

// BroadcastAdvance broadcasts a covenant advance via the configured
// BroadcastClient. It validates the new state via BuildAdvanceData,
// constructs a BroadcastRequest from the manager's current UTXO state,
// dispatches the broadcast, and on success calls ApplyAdvance to update
// the manager's tracked state.
//
// The advance proof is mode-specific and carries the batch data, public
// values, and proof blob needed by the validation step.
//
// Returns the BroadcastResult on success. The caller is responsible for
// monitoring confirmations via the BroadcastClient.
func (cm *CovenantManager) BroadcastAdvance(
	ctx context.Context,
	newState CovenantState,
	proof AdvanceProof,
) (*BroadcastResult, error) {
	if cm.broadcastClient == nil {
		return nil, fmt.Errorf("no broadcast client configured")
	}
	if proof == nil {
		return nil, errors.New("advance proof must not be nil")
	}

	batchData := proof.BatchData()
	proofBlob := proof.ProofBlob()
	publicValues := proof.PublicValues()

	if _, err := cm.BuildAdvanceData(newState, batchData, proofBlob, publicValues); err != nil {
		return nil, err
	}

	req := BroadcastRequest{
		PrevTxID: cm.currentTxID,
		PrevVout: cm.currentVout,
		PrevSats: cm.currentSats,
		NewState: newState,
		Proof:    proof,
	}

	result, err := cm.broadcastClient.BroadcastAdvance(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("broadcasting advance: %w", err)
	}

	if err := cm.ApplyAdvance(result.NewCovenantTxID, newState); err != nil {
		return nil, fmt.Errorf("applying advance after broadcast: %w", err)
	}
	cm.currentSats = result.NewCovenantSats

	return result, nil
}
