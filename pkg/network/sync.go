package network

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// SyncManager coordinates state synchronisation with peers. It handles
// block announcements, covenant advance notifications, and batch data
// requests to keep the local overlay node in sync with the network.
type SyncManager struct {
	overlay *overlay.OverlayNode
	gossip  *GossipManager
	peers   *PeerManager
}

// NewSyncManager creates a new SyncManager connected to the given overlay
// node, gossip manager, and peer manager.
func NewSyncManager(ovl *overlay.OverlayNode, gossip *GossipManager, peers *PeerManager) *SyncManager {
	return &SyncManager{
		overlay: ovl,
		gossip:  gossip,
		peers:   peers,
	}
}

// SyncWithPeer synchronises the local chain state with a peer that has
// a higher chain tip. It requests batch data for each missing block in
// sequence from the peer.
func (s *SyncManager) SyncWithPeer(ctx context.Context, peerID peer.ID) error {
	peerInfo := s.peers.GetPeer(peerID)
	if peerInfo == nil {
		return fmt.Errorf("unknown peer: %s", peerID)
	}

	localTip := s.overlay.ExecutionTip()
	peerTip := peerInfo.ChainTip

	if peerTip <= localTip {
		slog.Debug("peer is not ahead, skipping sync",
			"peer", peerID.String(),
			"localTip", localTip,
			"peerTip", peerTip,
		)
		return nil
	}

	slog.Info("syncing with peer",
		"peer", peerID.String(),
		"localTip", localTip,
		"peerTip", peerTip,
	)

	for blockNum := localTip + 1; blockNum <= peerTip; blockNum++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		batchData, err := s.gossip.RequestBatch(peerID, blockNum)
		if err != nil {
			s.peers.AdjustScore(peerID, -10)
			return fmt.Errorf("failed to fetch batch for block %d from peer %s: %w",
				blockNum, peerID, err)
		}

		if len(batchData) == 0 {
			s.peers.AdjustScore(peerID, -5)
			return fmt.Errorf("empty batch data for block %d from peer %s",
				blockNum, peerID)
		}

		slog.Debug("received batch data",
			"block", blockNum,
			"peer", peerID.String(),
			"size", len(batchData),
		)

		// Replay the batch through the overlay node.
		if err := s.overlay.ReplayBatchData(batchData); err != nil {
			s.peers.AdjustScore(peerID, -5)
			return fmt.Errorf("failed to replay batch for block %d: %w",
				blockNum, err)
		}

		// Successful batch fetch and replay: reward the peer.
		s.peers.AdjustScore(peerID, 1)
	}

	slog.Info("sync complete",
		"peer", peerID.String(),
		"newTip", peerTip,
	)
	return nil
}

// OnBlockAnnounce handles a block announcement received from a peer.
// If the announced block is ahead of the local tip, it triggers a sync
// with the announcing peer.
func (s *SyncManager) OnBlockAnnounce(peerID peer.ID, msg *BlockAnnounceMsg) error {
	if msg == nil {
		return fmt.Errorf("nil block announce message")
	}

	// Update the peer's known chain tip.
	s.peers.UpdateChainTip(peerID, msg.Number)

	localTip := s.overlay.ExecutionTip()

	slog.Debug("received block announcement",
		"peer", peerID.String(),
		"block", msg.Number,
		"stateRoot", msg.StateRoot.Hex(),
		"localTip", localTip,
	)

	if msg.Number <= localTip {
		// Already have this block or a later one.
		return nil
	}

	// The peer is ahead; initiate sync.
	ctx := context.Background()
	if err := s.SyncWithPeer(ctx, peerID); err != nil {
		slog.Warn("sync triggered by block announce failed",
			"peer", peerID.String(),
			"error", err,
		)
		return err
	}

	return nil
}

// OnCovenantAdvance handles a covenant advance announcement from a peer.
// This indicates that a BSV transaction has advanced the shard's covenant
// to a new state. The local node must verify the advance by re-executing
// the batch and comparing state roots.
func (s *SyncManager) OnCovenantAdvance(peerID peer.ID, msg *CovenantAdvanceMsg) error {
	if msg == nil {
		return fmt.Errorf("nil covenant advance message")
	}

	s.peers.UpdateChainTip(peerID, msg.L2BlockNum)

	localTip := s.overlay.ExecutionTip()

	slog.Info("received covenant advance",
		"peer", peerID.String(),
		"bsvTxID", msg.BSVTxID.Hex(),
		"l2Block", msg.L2BlockNum,
		"stateRoot", msg.StateRoot.Hex(),
		"localTip", localTip,
	)

	if msg.L2BlockNum <= localTip {
		// Check if the state root matches our local state for this block.
		header := s.overlay.ChainDB().ReadHeaderByNumber(msg.L2BlockNum)
		if header != nil && header.StateRoot != msg.StateRoot {
			slog.Warn("state root mismatch with covenant advance",
				"block", msg.L2BlockNum,
				"local", header.StateRoot.Hex(),
				"remote", msg.StateRoot.Hex(),
			)
			// This indicates we may have a different state than the
			// covenant. We need to rollback and replay the winning batch.
			if msg.L2BlockNum > 0 {
				if err := s.overlay.Rollback(msg.L2BlockNum - 1); err != nil {
					return fmt.Errorf("rollback failed during covenant advance handling: %w", err)
				}
			}
		}
		return nil
	}

	// The covenant is ahead of us; sync up.
	ctx := context.Background()
	if err := s.SyncWithPeer(ctx, peerID); err != nil {
		slog.Warn("sync triggered by covenant advance failed",
			"peer", peerID.String(),
			"error", err,
		)
		return err
	}

	return nil
}

// RegisterHandlers registers the sync manager's message handlers with
// the gossip manager so that incoming block announcements and covenant
// advances are routed to the sync manager.
func (s *SyncManager) RegisterHandlers() {
	s.gossip.RegisterHandler(MsgBlockAnnounce, func(peerID peer.ID, msg *Message) error {
		announce, err := DecodeBlockAnnounceMsg(msg.Payload)
		if err != nil {
			return err
		}
		return s.OnBlockAnnounce(peerID, announce)
	})

	s.gossip.RegisterHandler(MsgCovenantAdvance, func(peerID peer.ID, msg *Message) error {
		advance, err := DecodeCovenantAdvanceMsg(msg.Payload)
		if err != nil {
			return err
		}
		return s.OnCovenantAdvance(peerID, advance)
	})

	s.gossip.RegisterHandler(MsgHeartbeat, func(peerID peer.ID, msg *Message) error {
		hb, err := DecodeHeartbeatMsg(msg.Payload)
		if err != nil {
			return err
		}
		s.peers.UpdateChainTip(peerID, hb.ChainTip)
		return nil
	})

	s.gossip.RegisterHandler(MsgTxGossip, func(peerID peer.ID, msg *Message) error {
		// Decode the transaction and submit it to the overlay node.
		txMsg, err := DecodeTxGossipMsg(msg.Payload)
		if err != nil {
			return err
		}
		if len(txMsg.TxRLP) == 0 {
			return fmt.Errorf("empty transaction RLP")
		}

		// Decode the RLP-encoded transaction.
		tx, err := decodeGossipTx(txMsg.TxRLP)
		if err != nil {
			s.peers.AdjustScore(peerID, -5)
			return fmt.Errorf("failed to decode gossiped tx: %w", err)
		}

		// Submit to the overlay node for execution.
		if err := s.overlay.SubmitTransaction(tx); err != nil {
			slog.Debug("gossiped tx rejected by overlay",
				"hash", tx.Hash().Hex(),
				"peer", peerID.String(),
				"error", err,
			)
			// Don't penalise the peer for validation failures (nonce
			// race, duplicate, etc.) -- those are expected in a
			// multi-node environment.
			return nil
		}

		// Reward the peer for a valid gossip message.
		s.peers.AdjustScore(peerID, 1)
		return nil
	})
}

// decodeGossipTx decodes a raw RLP-encoded transaction received via gossip.
func decodeGossipTx(rlpData []byte) (*types.Transaction, error) {
	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(rlpData, tx); err != nil {
		return nil, err
	}
	return tx, nil
}
