package network

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/icellan/bsvm/pkg/types"
)

// Message type tags. Each network message is prefixed with a 1-byte
// type tag followed by a 4-byte big-endian payload length and the
// payload itself.
const (
	// MsgTxGossip carries a single RLP-encoded EVM transaction.
	MsgTxGossip byte = 0x01
	// MsgBlockAnnounce carries an L2 block header and tx hashes.
	MsgBlockAnnounce byte = 0x02
	// MsgCovenantAdvance carries a BSV txid, L2 block number, and state root.
	MsgCovenantAdvance byte = 0x03
	// MsgBatchRequest requests full batch data for an L2 block.
	MsgBatchRequest byte = 0x04
	// MsgBatchResponse carries full batch data for an L2 block.
	MsgBatchResponse byte = 0x05
	// MsgHeartbeat carries a peer liveness signal.
	MsgHeartbeat byte = 0x06
)

// Maximum payload sizes per message type. Messages exceeding these
// limits are rejected as a DoS-prevention measure.
var maxMessageSize = map[byte]int{
	MsgTxGossip:        128 * 1024, // 128KB
	MsgBlockAnnounce:   32 * 1024,  // 32KB
	MsgCovenantAdvance: 128,        // 128B
	MsgBatchRequest:    40,         // 40B
	MsgBatchResponse:   512 * 1024, // 512KB
	MsgHeartbeat:       64,         // 64B
}

// ProtocolID returns the libp2p protocol ID string for a given chain ID.
// Format: /bsvm/shard/<chain_id>/1.0.0
func ProtocolID(chainID int64) string {
	return "/bsvm/shard/" + strconv.FormatInt(chainID, 10) + "/1.0.0"
}

// Message is a network message with a type tag and payload.
type Message struct {
	// Type is the 1-byte message type tag.
	Type byte
	// Payload is the encoded message body.
	Payload []byte
}

// Encode serialises a Message into the wire format: 1-byte type tag +
// 4-byte big-endian length + payload.
func (m *Message) Encode() ([]byte, error) {
	if limit, ok := maxMessageSize[m.Type]; ok {
		if len(m.Payload) > limit {
			return nil, fmt.Errorf("payload size %d exceeds limit %d for message type 0x%02x",
				len(m.Payload), limit, m.Type)
		}
	}
	buf := make([]byte, 5+len(m.Payload))
	buf[0] = m.Type
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(m.Payload)))
	copy(buf[5:], m.Payload)
	return buf, nil
}

// DecodeMessage deserialises a Message from the wire format.
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("message too short: need at least 5 bytes, got %d", len(data))
	}
	msgType := data[0]
	payloadLen := binary.BigEndian.Uint32(data[1:5])
	if uint32(len(data)-5) < payloadLen {
		return nil, fmt.Errorf("message truncated: expected %d payload bytes, got %d",
			payloadLen, len(data)-5)
	}

	payload := data[5 : 5+payloadLen]

	// Validate size limit.
	if limit, ok := maxMessageSize[msgType]; ok {
		if int(payloadLen) > limit {
			return nil, fmt.Errorf("payload size %d exceeds limit %d for message type 0x%02x",
				payloadLen, limit, msgType)
		}
	}

	return &Message{
		Type:    msgType,
		Payload: payload,
	}, nil
}

// MaxMessageSize returns the maximum payload size for the given message type.
// Returns 0 if the message type is unknown.
func MaxMessageSize(msgType byte) int {
	return maxMessageSize[msgType]
}

// TxGossipMsg carries a single RLP-encoded EVM transaction.
type TxGossipMsg struct {
	// TxRLP is the RLP-encoded transaction bytes.
	TxRLP []byte `json:"txRlp"`
}

// Encode serialises a TxGossipMsg into a wire Message.
func (m *TxGossipMsg) Encode() (*Message, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode tx gossip message: %w", err)
	}
	return &Message{Type: MsgTxGossip, Payload: payload}, nil
}

// DecodeTxGossipMsg deserialises a TxGossipMsg from a payload.
func DecodeTxGossipMsg(payload []byte) (*TxGossipMsg, error) {
	var msg TxGossipMsg
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("failed to decode tx gossip message: %w", err)
	}
	return &msg, nil
}

// BlockAnnounceMsg carries an L2 block header summary and transaction hashes.
type BlockAnnounceMsg struct {
	// ParentHash is the hash of the parent block.
	ParentHash types.Hash `json:"parentHash"`
	// StateRoot is the post-execution state root.
	StateRoot types.Hash `json:"stateRoot"`
	// TxRoot is the transaction trie root.
	TxRoot types.Hash `json:"txRoot"`
	// Number is the L2 block number.
	Number uint64 `json:"number"`
	// GasUsed is the total gas used in this block.
	GasUsed uint64 `json:"gasUsed"`
	// Timestamp is the block timestamp.
	Timestamp uint64 `json:"timestamp"`
	// TxHashes contains the hashes of all transactions in the block.
	TxHashes []types.Hash `json:"txHashes"`
}

// Encode serialises a BlockAnnounceMsg into a wire Message.
func (m *BlockAnnounceMsg) Encode() (*Message, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode block announce message: %w", err)
	}
	return &Message{Type: MsgBlockAnnounce, Payload: payload}, nil
}

// DecodeBlockAnnounceMsg deserialises a BlockAnnounceMsg from a payload.
func DecodeBlockAnnounceMsg(payload []byte) (*BlockAnnounceMsg, error) {
	var msg BlockAnnounceMsg
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("failed to decode block announce message: %w", err)
	}
	return &msg, nil
}

// CovenantAdvanceMsg carries a BSV covenant advance announcement.
// It uses compact binary encoding (32 + 8 + 32 = 72 bytes) to fit
// within the 128-byte spec limit.
type CovenantAdvanceMsg struct {
	// BSVTxID is the BSV transaction ID that advanced the covenant.
	BSVTxID types.Hash
	// L2BlockNum is the L2 block number this advance commits.
	L2BlockNum uint64
	// StateRoot is the post-execution state root for this advance.
	StateRoot types.Hash
}

// Encode serialises a CovenantAdvanceMsg into a wire Message using
// compact binary format: BSVTxID (32) + L2BlockNum (8) + StateRoot (32).
func (m *CovenantAdvanceMsg) Encode() (*Message, error) {
	payload := make([]byte, 72)
	copy(payload[0:32], m.BSVTxID[:])
	binary.BigEndian.PutUint64(payload[32:40], m.L2BlockNum)
	copy(payload[40:72], m.StateRoot[:])
	return &Message{Type: MsgCovenantAdvance, Payload: payload}, nil
}

// DecodeCovenantAdvanceMsg deserialises a CovenantAdvanceMsg from a
// compact binary payload.
func DecodeCovenantAdvanceMsg(payload []byte) (*CovenantAdvanceMsg, error) {
	if len(payload) < 72 {
		return nil, fmt.Errorf("covenant advance payload too short: need 72 bytes, got %d", len(payload))
	}
	var msg CovenantAdvanceMsg
	copy(msg.BSVTxID[:], payload[0:32])
	msg.L2BlockNum = binary.BigEndian.Uint64(payload[32:40])
	copy(msg.StateRoot[:], payload[40:72])
	return &msg, nil
}

// BatchRequestMsg requests the full batch data for an L2 block.
type BatchRequestMsg struct {
	// L2BlockNum is the L2 block number to request batch data for.
	L2BlockNum uint64 `json:"l2BlockNum"`
}

// Encode serialises a BatchRequestMsg into a wire Message.
func (m *BatchRequestMsg) Encode() (*Message, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode batch request message: %w", err)
	}
	return &Message{Type: MsgBatchRequest, Payload: payload}, nil
}

// DecodeBatchRequestMsg deserialises a BatchRequestMsg from a payload.
func DecodeBatchRequestMsg(payload []byte) (*BatchRequestMsg, error) {
	var msg BatchRequestMsg
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("failed to decode batch request message: %w", err)
	}
	return &msg, nil
}

// BatchResponseMsg carries the full batch data for an L2 block.
type BatchResponseMsg struct {
	// L2BlockNum is the L2 block number this batch data is for.
	L2BlockNum uint64 `json:"l2BlockNum"`
	// BatchData is the complete batch payload (encoded transactions + context).
	BatchData []byte `json:"batchData"`
}

// Encode serialises a BatchResponseMsg into a wire Message.
func (m *BatchResponseMsg) Encode() (*Message, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode batch response message: %w", err)
	}
	return &Message{Type: MsgBatchResponse, Payload: payload}, nil
}

// DecodeBatchResponseMsg deserialises a BatchResponseMsg from a payload.
func DecodeBatchResponseMsg(payload []byte) (*BatchResponseMsg, error) {
	var msg BatchResponseMsg
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("failed to decode batch response message: %w", err)
	}
	return &msg, nil
}

// HeartbeatMsg carries a peer liveness signal with the peer's chain tip.
// It uses compact binary encoding to fit within the 64-byte spec limit:
// PeerIDLen (1) + PeerID (variable, up to 47) + ChainTip (8) + Timestamp (8).
type HeartbeatMsg struct {
	// PeerID is the string representation of the sending peer's ID.
	PeerID string
	// ChainTip is the latest L2 block number known to the sending peer.
	ChainTip uint64
	// Timestamp is the unix timestamp when the heartbeat was created.
	Timestamp uint64
}

// Encode serialises a HeartbeatMsg into a wire Message using compact
// binary format.
func (m *HeartbeatMsg) Encode() (*Message, error) {
	pidBytes := []byte(m.PeerID)
	if len(pidBytes) > 47 {
		pidBytes = pidBytes[:47]
	}
	payload := make([]byte, 1+len(pidBytes)+16)
	payload[0] = byte(len(pidBytes))
	copy(payload[1:1+len(pidBytes)], pidBytes)
	binary.BigEndian.PutUint64(payload[1+len(pidBytes):], m.ChainTip)
	binary.BigEndian.PutUint64(payload[1+len(pidBytes)+8:], m.Timestamp)
	return &Message{Type: MsgHeartbeat, Payload: payload}, nil
}

// DecodeHeartbeatMsg deserialises a HeartbeatMsg from a compact binary
// payload.
func DecodeHeartbeatMsg(payload []byte) (*HeartbeatMsg, error) {
	if len(payload) < 17 {
		return nil, fmt.Errorf("heartbeat payload too short: need at least 17 bytes, got %d", len(payload))
	}
	pidLen := int(payload[0])
	if len(payload) < 1+pidLen+16 {
		return nil, fmt.Errorf("heartbeat payload too short for peer ID length %d", pidLen)
	}
	return &HeartbeatMsg{
		PeerID:    string(payload[1 : 1+pidLen]),
		ChainTip:  binary.BigEndian.Uint64(payload[1+pidLen:]),
		Timestamp: binary.BigEndian.Uint64(payload[1+pidLen+8:]),
	}, nil
}
