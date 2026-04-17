package rpc

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

// otherChainID is a chainID that must never be accepted by a shard running
// with chainID = testChainID.
const otherChainID = testChainID + 1

// encodeTx RLP-encodes tx into its wire format for eth_sendRawTransaction.
func encodeTx(t *testing.T, tx *types.Transaction) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP: %v", err)
	}
	return buf.Bytes()
}

// TestSendRawTransactionChainIDReplay covers the eth_sendRawTransaction
// replay-protection contract: the RPC must reject any transaction whose
// chainID does not match the shard's chainID, across all three modern
// envelope types (legacy EIP-155, EIP-2930 access list, EIP-1559 dynamic
// fee), and must not enqueue the rejected transaction into the batcher.
// Pre-EIP-155 legacy transactions (v = 27 / 28) carry no replay protection
// and must also be rejected on a shard with a configured chainID.
func TestSendRawTransactionChainIDReplay(t *testing.T) {
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	gasPrice := big.NewInt(1_000_000_000)
	gasTip := big.NewInt(1_000_000_000)
	gasFee := big.NewInt(2_000_000_000)

	t.Run("legacy EIP-155 matching chainID is accepted", func(t *testing.T) {
		ts := newTestSetup(t)
		defer ts.node.Stop()

		tx := types.MustSignNewTx(ts.key, ts.signer, &types.LegacyTx{
			Nonce:    0,
			GasPrice: gasPrice,
			Gas:      21000,
			To:       &recipient,
			Value:    uint256.NewInt(1000),
		})

		hash, err := ts.server.EthAPI().SendRawTransaction(encodeTx(t, tx))
		if err != nil {
			t.Fatalf("expected EIP-155 legacy tx with matching chainID to be accepted, got error: %v", err)
		}
		if hash != tx.Hash().Hex() {
			t.Errorf("returned hash mismatch: got %s want %s", hash, tx.Hash().Hex())
		}
	})

	// Helper: each rejection case shares identical assertions.
	type rejectCase struct {
		name string
		// makeTx must produce a signed transaction whose chainID does NOT
		// match the shard. It takes the setup so the caller can use the
		// shard's test key but sign under a different-chainID signer.
		makeTx func(ts *testSetup) *types.Transaction
	}

	cases := []rejectCase{
		{
			name: "EIP-155 legacy with wrong chainID is rejected",
			makeTx: func(ts *testSetup) *types.Transaction {
				wrongSigner := types.NewEIP155Signer(big.NewInt(otherChainID))
				return types.MustSignNewTx(ts.key, wrongSigner, &types.LegacyTx{
					Nonce:    0,
					GasPrice: gasPrice,
					Gas:      21000,
					To:       &recipient,
					Value:    uint256.NewInt(1000),
				})
			},
		},
		{
			name: "EIP-2930 access list with wrong chainID is rejected",
			makeTx: func(ts *testSetup) *types.Transaction {
				wrongSigner := types.NewEIP2930Signer(big.NewInt(otherChainID))
				return types.MustSignNewTx(ts.key, wrongSigner, &types.AccessListTx{
					ChainID:  big.NewInt(otherChainID),
					Nonce:    0,
					GasPrice: gasPrice,
					Gas:      21000,
					To:       &recipient,
					Value:    uint256.NewInt(1000),
					AccessList: types.AccessList{
						{Address: recipient, StorageKeys: []types.Hash{{}}},
					},
				})
			},
		},
		{
			name: "EIP-1559 dynamic fee with wrong chainID is rejected",
			makeTx: func(ts *testSetup) *types.Transaction {
				wrongSigner := types.NewLondonSigner(big.NewInt(otherChainID))
				return types.MustSignNewTx(ts.key, wrongSigner, &types.DynamicFeeTx{
					ChainID:   big.NewInt(otherChainID),
					Nonce:     0,
					GasTipCap: gasTip,
					GasFeeCap: gasFee,
					Gas:       21000,
					To:        &recipient,
					Value:     uint256.NewInt(1000),
				})
			},
		},
		{
			name: "pre-EIP-155 legacy (v=27/28) is rejected",
			makeTx: func(ts *testSetup) *types.Transaction {
				// HomesteadSigner produces a legacy tx with v = 27 + recovery_id
				// and chainID = 0 (no replay protection).
				return types.MustSignNewTx(ts.key, types.HomesteadSigner{}, &types.LegacyTx{
					Nonce:    0,
					GasPrice: gasPrice,
					Gas:      21000,
					To:       &recipient,
					Value:    uint256.NewInt(1000),
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestSetup(t)
			defer ts.node.Stop()

			tx := tc.makeTx(ts)
			hash, err := ts.server.EthAPI().SendRawTransaction(encodeTx(t, tx))
			if err == nil {
				t.Fatalf("expected wrong-chain transaction to be rejected, but SendRawTransaction returned hash %s", hash)
			}

			// The error must clearly mention chainID — callers (ethers.js,
			// Hardhat, etc.) rely on this text to present a useful error.
			msg := strings.ToLower(err.Error())
			if !(strings.Contains(msg, "chain id") || strings.Contains(msg, "chainid")) {
				t.Errorf("rejection error must mention chain id, got: %v", err)
			}

			// Rejected transactions must never reach the batcher. Because
			// the RPC rejects before calling Batcher().Add, no tx could
			// have been enqueued regardless of the flush timer state.
			if got := ts.node.Batcher().PendingCount(); got != 0 {
				t.Errorf("rejected tx leaked into batcher: pending=%d", got)
			}
		})
	}
}
