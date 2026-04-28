package rpc

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

// TestEthSendRawTransaction_PreservesSignatureV is a regression guard for a
// bug where the eth_sendRawTransaction decode path round-tripped V through
// nil for signatures whose recovery id is zero.
//
// RLP encodes a *big.Int with value 0 as the empty string (0x80), which the
// decoder maps back to a nil pointer. For typed (EIP-2930 / EIP-1559)
// transactions the recovery id IS the V value (no chainID offset like
// EIP-155), so V == 0 is the common case. If the decode path leaves V nil,
// the signer's Sender() call returns "missing signature values" and every
// nonce-0 typed tx with even-y signatures (~50% of all such txs) fails to
// validate.
//
// The RPC layer no longer carries its own decoders — pkg/rpc/eth_api.go's
// decodeRawTransaction now delegates to the canonical
// types.Transaction.UnmarshalBinary entrypoint (via pkg/types.DecodeTx),
// which is the single source of truth for V/R/S handling. This test
// exercises that canonical path end-to-end so any future regression in
// pkg/types — or any reintroduction of an RPC-side decoder that drifts
// from it — is caught here.
//
// The test exercises both halves of the failure mode:
//
//  1. Round-trip a signed tx through eth_sendRawTransaction → decode →
//     assert V/R/S survived. This catches the immediate bug.
//  2. Run Sender() against the decoded tx — the actual downstream consumer
//     that surfaced the original "missing signature values" error.
//
// Three envelopes are exercised so a regression in any of the typed-tx
// branches inside Transaction.UnmarshalBinary / DecodeTx is caught: legacy
// EIP-155, EIP-2930 access list, EIP-1559 dynamic fee.
func TestEthSendRawTransaction_PreservesSignatureV(t *testing.T) {
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	gasPrice := big.NewInt(1_000_000_000)
	gasTip := big.NewInt(1_000_000_000)
	gasFee := big.NewInt(2_000_000_000)
	value := uint256.NewInt(1000)

	// Build one signed tx per envelope, all using the test setup's key so
	// the signer / chainID match what the RPC server expects.
	cases := []struct {
		name   string
		makeTx func(ts *testSetup) *types.Transaction
	}{
		{
			name: "legacy_EIP-155",
			makeTx: func(ts *testSetup) *types.Transaction {
				return types.MustSignNewTx(ts.key, ts.signer, &types.LegacyTx{
					Nonce:    0,
					GasPrice: gasPrice,
					Gas:      21000,
					To:       &recipient,
					Value:    value,
				})
			},
		},
		{
			name: "EIP-2930_access_list",
			makeTx: func(ts *testSetup) *types.Transaction {
				return types.MustSignNewTx(ts.key, ts.signer, &types.AccessListTx{
					ChainID:  big.NewInt(testChainID),
					Nonce:    0,
					GasPrice: gasPrice,
					Gas:      21000,
					To:       &recipient,
					Value:    value,
					AccessList: types.AccessList{
						{Address: recipient, StorageKeys: []types.Hash{{}}},
					},
				})
			},
		},
		{
			name: "EIP-1559_dynamic_fee",
			makeTx: func(ts *testSetup) *types.Transaction {
				return types.MustSignNewTx(ts.key, ts.signer, &types.DynamicFeeTx{
					ChainID:   big.NewInt(testChainID),
					Nonce:     0,
					GasTipCap: gasTip,
					GasFeeCap: gasFee,
					Gas:       21000,
					To:        &recipient,
					Value:     value,
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestSetup(t)
			defer ts.node.Stop()

			tx := tc.makeTx(ts)
			origV, origR, origS := tx.RawSignatureValues()
			if origV == nil || origR == nil || origS == nil {
				t.Fatalf("test bug: signing produced nil V/R/S (V=%v R=%v S=%v)",
					origV, origR, origS)
			}

			// Round-trip through the public RPC decode path. This is what
			// eth_sendRawTransaction calls internally.
			raw := encodeTx(t, tx)
			decoded, err := decodeRawTransaction(raw)
			if err != nil {
				t.Fatalf("decodeRawTransaction failed: %v", err)
			}

			gotV, gotR, gotS := decoded.RawSignatureValues()
			if gotV == nil {
				t.Fatalf("V was lost in decode (decoded as nil); regression: typed-tx V=0 round-trips through nil")
			}
			if gotR == nil {
				t.Fatalf("R was lost in decode (decoded as nil)")
			}
			if gotS == nil {
				t.Fatalf("S was lost in decode (decoded as nil)")
			}
			if gotV.Cmp(origV) != 0 {
				t.Errorf("V mismatch after RLP round-trip: got %s, want %s",
					gotV.String(), origV.String())
			}
			if gotR.Cmp(origR) != 0 {
				t.Errorf("R mismatch after RLP round-trip: got %s, want %s",
					gotR.String(), origR.String())
			}
			if gotS.Cmp(origS) != 0 {
				t.Errorf("S mismatch after RLP round-trip: got %s, want %s",
					gotS.String(), origS.String())
			}

			// And: the actual user-visible bug was that Sender() returned
			// "missing signature values". Verify that's fixed end-to-end.
			from, err := types.Sender(ts.signer, decoded)
			if err != nil {
				t.Fatalf("Sender() on decoded tx failed: %v", err)
			}
			if from != ts.addr {
				t.Errorf("recovered sender mismatch: got %s, want %s",
					from.Hex(), ts.addr.Hex())
			}

			// Finally, drive the full eth_sendRawTransaction entrypoint so
			// any future change that adds another layer between hex-decode
			// and the actual decoder is caught here too.
			gotHash, err := ts.server.EthAPI().SendRawTransaction(raw)
			if err != nil {
				t.Fatalf("SendRawTransaction failed: %v", err)
			}
			if gotHash != tx.Hash().Hex() {
				t.Errorf("returned hash mismatch: got %s, want %s",
					gotHash, tx.Hash().Hex())
			}
		})
	}
}
