package rpc

import (
	"fmt"
	"strconv"
)

// PeerCounter provides the current peer count. Implementations include
// the network layer's PeerManager. When nil, PeerCount returns "0x0".
type PeerCounter interface {
	PeerCount() int
}

// NetAPI implements the net_* namespace of the JSON-RPC API.
type NetAPI struct {
	chainID int64
	peers   PeerCounter
}

// NewNetAPI creates a new NetAPI with the given chain ID.
func NewNetAPI(chainID int64) *NetAPI {
	return &NetAPI{chainID: chainID}
}

// SetPeerCounter wires the network layer's peer counter so that
// net_peerCount returns the actual connected peer count.
func (api *NetAPI) SetPeerCounter(pc PeerCounter) {
	api.peers = pc
}

// Version returns the network identifier (chain ID) as a decimal string.
// This implements net_version.
func (api *NetAPI) Version() string {
	return strconv.FormatInt(api.chainID, 10)
}

// Listening returns true to indicate the node is listening for connections.
// This implements net_listening.
func (api *NetAPI) Listening() bool {
	return true
}

// PeerCount returns the number of connected peers as a hex string.
// When no PeerCounter is set (single-node mode), returns "0x0".
// This implements net_peerCount.
func (api *NetAPI) PeerCount() string {
	if api.peers == nil {
		return "0x0"
	}
	return fmt.Sprintf("0x%x", api.peers.PeerCount())
}
