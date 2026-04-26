// Regtest-only fee-wallet bootstrap. On a fresh devnet node the
// persisted fee wallet starts empty, so the covenant-advance broadcast
// path has no UTXOs to spend. This file seeds the wallet from the
// local bsv-regtest node via a small sequence of JSON-RPC calls —
// importaddress (watch-only), sendtoaddress (primary fund), and
// generatetoaddress (to mature the funding tx) — then ingests every
// resulting UTXO into the persistent fee wallet.
//
// The bootstrap is idempotent: if the wallet already holds at least
// MinBalanceSats the function returns immediately. It is also
// network-gated: on testnet/mainnet it is a no-op, which lets the same
// production binary run unchanged against those networks.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
	runar "github.com/icellan/runar/packages/runar-go"
)

// defaultMinBalanceSats is the minimum balance we want the fee wallet
// to hold before we consider it "funded". 5 BSV is plenty for hundreds
// of covenant advances on regtest at 1 sat/KB fees.
const defaultMinBalanceSats uint64 = 500_000_000

// defaultFundBTC is the amount of BSV we ask the regtest node to send
// to the fee-wallet address on first boot. Expressed in whole BSV
// (float) because bitcoind's sendtoaddress takes BTC-denominated
// amounts, not satoshis.
const defaultFundBTC float64 = 5.0

// utxoPollInterval is how often we re-query listunspent while waiting
// for the fund+mine combo to surface a spendable UTXO.
const utxoPollInterval = 1 * time.Second

// utxoPollBudget is the total time budget for the listunspent poll
// loop. 30 seconds is generous given the miner service runs on a 10s
// interval and our generatetoaddress call mines a block directly.
const utxoPollBudget = 30 * time.Second

// BootstrapOpts carries every input BootstrapFeeWallet needs.
// MinBalanceSats and FundBTC default to sensible values if zero.
type BootstrapOpts struct {
	// Provider is the BSV-node JSON-RPC client. Typed as the union
	// interface so callers can pass either a single-endpoint
	// *bsvclient.RPCProvider or the W6-11 failover wrapper
	// *bsvclient.MultiRPCProvider — the bootstrap path only needs
	// Call(...) + GetUtxos(string).
	Provider       BSVProviderClient
	FeeWallet      *overlay.FeeWallet
	Address        string  // BSV P2PKH for the fee-wallet key
	Network        string  // "regtest" only — others return (0, nil)
	MinBalanceSats uint64  // default 500_000_000 (5 BSV) if zero
	FundBTC        float64 // default 5.0 if zero
}

// BootstrapFeeWallet seeds the fee wallet from a BSV regtest node on
// first boot. Idempotent: returns (0, nil) immediately if the wallet
// already has at least MinBalanceSats, or if the configured network is
// not regtest.
//
// Behaviour on a regtest fresh-start (Balance < MinBalanceSats):
//  1. rpc.Call("importaddress", addr, "", false)   — watch-only add
//  2. rpc.Call("sendtoaddress", addr, btcAmount)   — primary fund
//  3. rpc.Call("generatetoaddress", 1, addr)       — mine the funding tx
//  4. Poll provider.GetUtxos(addr) every 1s for ≤30s until ≥1 UTXO
//  5. For each returned UTXO, feeWallet.AddUTXO(...)
//
// Returns the number of UTXOs ingested into the fee wallet.
func BootstrapFeeWallet(ctx context.Context, opts BootstrapOpts) (int, error) {
	if opts.Provider == nil {
		return 0, fmt.Errorf("bootstrap: Provider is required")
	}
	if opts.FeeWallet == nil {
		return 0, fmt.Errorf("bootstrap: FeeWallet is required")
	}
	if opts.Address == "" {
		return 0, fmt.Errorf("bootstrap: Address is required")
	}

	// Network gate — no-op on anything other than regtest.
	if opts.Network != "regtest" {
		slog.Warn("fee-wallet bootstrap skipped: non-regtest network",
			"network", opts.Network)
		return 0, nil
	}

	minBalance := opts.MinBalanceSats
	if minBalance == 0 {
		minBalance = defaultMinBalanceSats
	}
	fundBTC := opts.FundBTC
	if fundBTC == 0 {
		fundBTC = defaultFundBTC
	}

	// Idempotency check: already funded?
	if bal := opts.FeeWallet.Balance(); bal >= minBalance {
		slog.Debug("fee-wallet bootstrap: already funded, no-op",
			"balance_sats", bal, "min_balance_sats", minBalance)
		return 0, nil
	}

	slog.Info("fee-wallet bootstrap starting",
		"address", opts.Address,
		"current_balance_sats", opts.FeeWallet.Balance(),
		"target_balance_sats", minBalance,
		"fund_btc", fundBTC)

	// Step 1 — importaddress (watch-only, no rescan).
	// Treat "already imported" errors as success. bitcoind returns
	// RPC error -4 with message containing "already" when the address
	// is already in the wallet.
	if _, err := opts.Provider.Call("importaddress", opts.Address, "", false); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "already") {
			slog.Debug("fee-wallet bootstrap: importaddress idempotent hit",
				"address", opts.Address)
		} else {
			return 0, fmt.Errorf("bootstrap importaddress: %w", err)
		}
	} else {
		slog.Info("fee-wallet bootstrap: importaddress ok", "address", opts.Address)
	}

	// Step 2 — sendtoaddress. bitcoind accepts float BTC amounts.
	if _, err := opts.Provider.Call("sendtoaddress", opts.Address, fundBTC); err != nil {
		return 0, fmt.Errorf("bootstrap sendtoaddress: %w", err)
	}
	slog.Info("fee-wallet bootstrap: sendtoaddress ok", "amount_btc", fundBTC)

	// Step 3 — generatetoaddress to mine the funding tx. Mining to the
	// fee-wallet address itself is fine; the coinbase is unspendable
	// until 100 confirmations but the regtest miner service keeps the
	// tip moving fast enough for the primer UTXOs from sendtoaddress
	// to become listunspent-visible immediately.
	if _, err := opts.Provider.Call("generatetoaddress", 1, opts.Address); err != nil {
		return 0, fmt.Errorf("bootstrap generatetoaddress: %w", err)
	}
	slog.Info("fee-wallet bootstrap: generatetoaddress ok", "blocks", 1)

	// Step 4 — poll listunspent until the UTXO shows up. Bounded both
	// by the caller's ctx and by our internal utxoPollBudget so a
	// hung node can't stall node startup indefinitely.
	pollCtx, cancel := context.WithTimeout(ctx, utxoPollBudget)
	defer cancel()

	var utxos []runar.UTXO
	ticker := time.NewTicker(utxoPollInterval)
	defer ticker.Stop()

	// Try once immediately before falling into the ticker loop so the
	// (common) fast case doesn't wait a full tick.
	if found, err := opts.Provider.GetUtxos(opts.Address); err == nil && len(found) > 0 {
		utxos = found
	}

pollLoop:
	for len(utxos) == 0 {
		select {
		case <-pollCtx.Done():
			return 0, fmt.Errorf("bootstrap: timed out waiting for UTXOs to appear at %s", opts.Address)
		case <-ticker.C:
			found, err := opts.Provider.GetUtxos(opts.Address)
			if err != nil {
				slog.Debug("fee-wallet bootstrap: listunspent error, retrying", "err", err)
				continue
			}
			if len(found) > 0 {
				utxos = found
				break pollLoop
			}
		}
	}

	slog.Info("fee-wallet bootstrap: UTXOs surfaced", "count", len(utxos))

	// Step 5 — ingest every returned UTXO into the FeeWallet. The
	// shape difference:
	//   runar.UTXO        → { Txid string, OutputIndex int, Satoshis int64, Script string (hex) }
	//   overlay.FeeUTXO   → { TxID types.Hash, Vout uint32, Satoshis uint64, ScriptPubKey []byte }
	// The hex txid is converted via types.HexToHash (left-pads to 32
	// bytes). Signed→unsigned width conversions are guarded against
	// negative values defensively — listunspent never returns negatives
	// in practice but the static types allow them.
	ingested := 0
	for _, u := range utxos {
		if u.Satoshis < 0 {
			slog.Warn("fee-wallet bootstrap: skipping utxo with negative satoshis",
				"txid", u.Txid, "vout", u.OutputIndex, "satoshis", u.Satoshis)
			continue
		}
		if u.OutputIndex < 0 {
			slog.Warn("fee-wallet bootstrap: skipping utxo with negative output index",
				"txid", u.Txid, "vout", u.OutputIndex)
			continue
		}
		scriptBytes, err := hex.DecodeString(u.Script)
		if err != nil {
			slog.Warn("fee-wallet bootstrap: skipping utxo with un-decodable script",
				"txid", u.Txid, "vout", u.OutputIndex, "err", err)
			continue
		}
		feeUTXO := &overlay.FeeUTXO{
			// u.Txid is a BSV txid (big-endian display form from
			// listunspent) — reverse into chainhash little-endian bytes.
			TxID:         types.BSVHashFromHex(u.Txid),
			Vout:         uint32(u.OutputIndex),
			Satoshis:     uint64(u.Satoshis),
			ScriptPubKey: scriptBytes,
			// listunspent by definition returns spendable UTXOs, so we
			// mark them confirmed. That aligns with how the rest of
			// the FeeWallet uses the Confirmed flag (it gates spending,
			// not broadcast).
			Confirmed: true,
		}
		if err := opts.FeeWallet.AddUTXO(feeUTXO); err != nil {
			return ingested, fmt.Errorf("bootstrap AddUTXO %s:%d: %w", u.Txid, u.OutputIndex, err)
		}
		ingested++
	}

	slog.Info("fee-wallet bootstrap: complete",
		"ingested_utxos", ingested,
		"balance_sats", opts.FeeWallet.Balance())
	return ingested, nil
}
