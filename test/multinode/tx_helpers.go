//go:build multinode

package multinode

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"

	"github.com/holiman/uint256"
)

// testPrivateKeyHex is a well-known test private key. The corresponding
// address 0x96216849c49358B10257cb55b28eA603c874b05E is funded with
// 1000 ETH in the Docker cluster genesis via --alloc.
const testPrivateKeyHex = "4c0883a69102937d6231471b5dbb6204fe512961708279f3ae2e8e53d5f2e16a"

// testChainID matches the --chain-id used in the docker-compose init command.
const testChainID = 8453111

// TestKey returns the test private key and its address.
func TestKey() (*ecdsa.PrivateKey, types.Address) {
	keyBytes, _ := hex.DecodeString(testPrivateKeyHex)
	key, _ := crypto.ToECDSA(keyBytes)
	addr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	return key, addr
}

// SignAndEncode signs a LegacyTx and returns its RLP-encoded hex string
// suitable for eth_sendRawTransaction.
func SignAndEncode(key *ecdsa.PrivateKey, nonce uint64, to types.Address, value *uint256.Int) (string, types.Hash) {
	signer := types.LatestSignerForChainID(big.NewInt(testChainID))
	tx := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &to,
		Value:    value,
	})
	var buf bytesWriter
	tx.EncodeRLP(&buf)
	return "0x" + hex.EncodeToString(buf.Bytes()), tx.Hash()
}

type bytesWriter struct{ buf []byte }

func (w *bytesWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}
func (w *bytesWriter) Bytes() []byte { return w.buf }

// GetTransactionByHash calls eth_getTransactionByHash. Returns nil map if not found.
func GetTransactionByHash(ctx context.Context, url string, hash types.Hash) (map[string]interface{}, error) {
	result, err := rpcCall(ctx, url, "eth_getTransactionByHash", hash.Hex())
	if err != nil {
		return nil, err
	}
	if string(result) == "null" {
		return nil, nil
	}
	var tx map[string]interface{}
	if err := json.Unmarshal(result, &tx); err != nil {
		return nil, fmt.Errorf("unmarshal tx: %w", err)
	}
	return tx, nil
}

// GetTransactionReceipt calls eth_getTransactionReceipt. Returns nil map if not found.
func GetTransactionReceipt(ctx context.Context, url string, hash types.Hash) (map[string]interface{}, error) {
	result, err := rpcCall(ctx, url, "eth_getTransactionReceipt", hash.Hex())
	if err != nil {
		return nil, err
	}
	if string(result) == "null" {
		return nil, nil
	}
	var receipt map[string]interface{}
	if err := json.Unmarshal(result, &receipt); err != nil {
		return nil, fmt.Errorf("unmarshal receipt: %w", err)
	}
	return receipt, nil
}
