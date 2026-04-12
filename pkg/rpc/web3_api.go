package rpc

import (
	"fmt"
	"runtime"

	"github.com/icellan/bsvm/pkg/crypto"
)

// clientVersion is the version string returned by web3_clientVersion.
const clientVersion = "BSVM/v0.1.0"

// Web3API implements the web3_* namespace of the JSON-RPC API.
type Web3API struct{}

// NewWeb3API creates a new Web3API instance.
func NewWeb3API() *Web3API {
	return &Web3API{}
}

// ClientVersion returns the current client version string.
// This implements web3_clientVersion.
func (api *Web3API) ClientVersion() string {
	return fmt.Sprintf("%s/%s-%s/%s", clientVersion, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// Sha3 returns the Keccak-256 hash of the given data.
// This implements web3_sha3.
func (api *Web3API) Sha3(data []byte) string {
	hash := crypto.Keccak256(data)
	return EncodeBytes(hash)
}
