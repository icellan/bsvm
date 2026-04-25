package rpc

import (
	"github.com/icellan/bsvm/pkg/bridge"
)

// This file holds the bsv_* JSON-RPC methods added by spec 15 for the
// explorer / admin UI. Kept separate from bsv_api.go so the core of
// BsvAPI stays focused on the subset the shard contract needs.

// BridgeSnapshotProvider is the minimal interface BsvAPI needs to
// answer bsv_bridgeStatus, bsv_getDeposits, and bsv_getWithdrawals.
// Matches the contract the bridge Monitor exposes; real wiring lands
// when the bridge is attached to the overlay node.
type BridgeSnapshotProvider interface {
	// TotalLockedSatoshis returns the sum of BSV currently locked
	// across every sub-covenant UTXO. Zero if no bridge is configured.
	TotalLockedSatoshis() uint64
	// SubCovenantCount returns the number of active sub-covenant UTXOs
	// tracked by the monitor.
	SubCovenantCount() int
	// Deposits returns processed deposits between BSV block heights
	// fromBlock (inclusive) and toBlock (inclusive). Zero toBlock means
	// "no upper bound".
	Deposits(fromBlock, toBlock uint64) []*bridge.Deposit
	// Withdrawals returns the recent withdrawal entries in the half-open
	// range of L2 nonces [fromNonce, toNonce).
	Withdrawals(fromNonce, toNonce uint64) []WithdrawalSummary
}

// WithdrawalSummary is the lightweight view used by bsv_getWithdrawals.
// Kept free of BSV SDK types so the RPC package does not grow heavy
// imports.
type WithdrawalSummary struct {
	Nonce        uint64
	AmountWei    string // decimal
	BsvAddress   string // hex
	L2TxHash     string // 0x-prefixed
	Claimed      bool
	ClaimBsvTxid string // hex, empty if not yet claimed
	CsvRemaining uint64
}

// SetBridgeProvider attaches the bridge snapshot source. When unset
// (the default until the bridge is wired to OverlayNode), the spec 15
// bsv_* methods return empty / zero responses rather than erroring so
// explorer UIs can still load.
func (api *BsvAPI) SetBridgeProvider(p BridgeSnapshotProvider) {
	api.bridge = p
}

// BridgeStatus implements bsv_bridgeStatus — a summary of L2 wBSV
// supply vs L1 BSV locked. Spec 15 uses it for the dashboard bridge
// card.
func (api *BsvAPI) BridgeStatus() map[string]interface{} {
	totalLockedSats := uint64(0)
	subCovenants := 0
	if api.bridge != nil {
		totalLockedSats = api.bridge.TotalLockedSatoshis()
		subCovenants = api.bridge.SubCovenantCount()
	}
	// wBSV total supply is pegged 1:1 to locked BSV (in wei: sats × 10^10).
	totalLockedWei := satoshisToWeiDecimal(totalLockedSats)
	return map[string]interface{}{
		"totalLockedSatoshis": EncodeUint64(totalLockedSats),
		"totalLockedWei":      totalLockedWei,
		"totalSupplyWei":      totalLockedWei, // 1:1 peg
		"subCovenantCount":    EncodeUint64(uint64(subCovenants)),
	}
}

// GetDeposits implements bsv_getDeposits — list processed deposits in
// the BSV block-height range (inclusive). Returns an empty slice when
// the bridge is not configured.
func (api *BsvAPI) GetDeposits(fromBlock, toBlock uint64) []map[string]interface{} {
	if api.bridge == nil {
		return []map[string]interface{}{}
	}
	deposits := api.bridge.Deposits(fromBlock, toBlock)
	out := make([]map[string]interface{}, 0, len(deposits))
	for _, d := range deposits {
		if d == nil {
			continue
		}
		l2Wei := ""
		if d.L2WeiAmount != nil {
			l2Wei = d.L2WeiAmount.Dec()
		}
		out = append(out, map[string]interface{}{
			"bsvTxId":        bsvTxIDHex(d.BSVTxID),
			"vout":           EncodeUint64(uint64(d.Vout)),
			"bsvBlockHeight": EncodeUint64(d.BSVBlockHeight),
			"l2Address":      d.L2Address.Hex(),
			"satoshiAmount":  EncodeUint64(d.SatoshiAmount),
			"l2WeiAmount":    l2Wei,
			"confirmed":      d.Confirmed,
		})
	}
	return out
}

// GetWithdrawals implements bsv_getWithdrawals — list recent
// withdrawals in the half-open nonce range [fromNonce, toNonce).
// Returns empty when the bridge is not configured.
func (api *BsvAPI) GetWithdrawals(fromNonce, toNonce uint64) []map[string]interface{} {
	if api.bridge == nil {
		return []map[string]interface{}{}
	}
	ws := api.bridge.Withdrawals(fromNonce, toNonce)
	out := make([]map[string]interface{}, 0, len(ws))
	for _, w := range ws {
		out = append(out, map[string]interface{}{
			"nonce":        EncodeUint64(w.Nonce),
			"amountWei":    w.AmountWei,
			"bsvAddress":   w.BsvAddress,
			"l2TxHash":     w.L2TxHash,
			"claimed":      w.Claimed,
			"claimBsvTxid": w.ClaimBsvTxid,
			"csvRemaining": EncodeUint64(w.CsvRemaining),
		})
	}
	return out
}

// NetworkHealth implements bsv_networkHealth — peer / proving / BSV
// settlement stats in one RPC response. Primary data source for the
// explorer "Network" page.
func (api *BsvAPI) NetworkHealth() map[string]interface{} {
	exec := api.overlay.ExecutionTip()
	proven := api.overlay.ProvenTip()
	confirmed := api.overlay.ConfirmedTip()
	finalized := api.overlay.FinalizedTip()

	specDepth := uint64(api.overlay.TxCacheRef().SpeculativeDepth())

	result := map[string]interface{}{
		"peerCount":           EncodeUint64(uint64(api.peerCount())),
		"executionTip":        EncodeUint64(exec),
		"provenTip":           EncodeUint64(proven),
		"confirmedTip":        EncodeUint64(confirmed),
		"finalizedTip":        EncodeUint64(finalized),
		"speculativeDepth":    EncodeUint64(specDepth),
		"maxSpeculativeDepth": EncodeUint64(uint64(api.overlay.Config().MaxSpeculativeDepth)),
	}

	// Fold in prover telemetry where available so the single RPC
	// response covers everything the /network UI page needs.
	if pp := api.overlay.ParallelProverRef(); pp != nil {
		m := pp.Metrics()
		result["proverMode"] = m.Mode
		result["proverInFlight"] = EncodeUint64(uint64(m.InFlight))
		result["proverQueueDepth"] = EncodeUint64(uint64(m.QueueDepth))
		result["proofsSucceeded"] = EncodeUint64(m.ProofsSucceeded)
		result["proofsFailed"] = EncodeUint64(m.ProofsFailed)
		result["averageProveTimeMs"] = EncodeUint64(m.AvgProveTimeMs)
	}

	return result
}

// ProvingStatus implements bsv_provingStatus — a focused prover view
// complementing NetworkHealth. Separated out so clients that only need
// prover telemetry don't pay for the wider snapshot.
func (api *BsvAPI) ProvingStatus() map[string]interface{} {
	pp := api.overlay.ParallelProverRef()
	if pp == nil {
		return map[string]interface{}{
			"mode":            "disabled",
			"workers":         EncodeUint64(0),
			"inFlight":        EncodeUint64(0),
			"queueDepth":      EncodeUint64(0),
			"proofsStarted":   EncodeUint64(0),
			"proofsSucceeded": EncodeUint64(0),
			"proofsFailed":    EncodeUint64(0),
			"averageTimeMs":   EncodeUint64(0),
		}
	}
	m := pp.Metrics()

	// Batcher snapshot to round out the "what's the prover doing"
	// question with "what's waiting upstream".
	pending := 0
	paused := false
	if b := api.overlay.Batcher(); b != nil {
		pending = b.PendingCount()
		paused = b.IsPaused()
	}

	return map[string]interface{}{
		"mode":            m.Mode,
		"workers":         EncodeUint64(uint64(m.Workers)),
		"inFlight":        EncodeUint64(uint64(m.InFlight)),
		"queueDepth":      EncodeUint64(uint64(m.QueueDepth)),
		"proofsStarted":   EncodeUint64(m.ProofsStarted),
		"proofsSucceeded": EncodeUint64(m.ProofsSucceeded),
		"proofsFailed":    EncodeUint64(m.ProofsFailed),
		"averageTimeMs":   EncodeUint64(m.AvgProveTimeMs),
		"pendingTxs":      EncodeUint64(uint64(pending)),
		"batcherPaused":   paused,
	}
}

// satoshisToWeiDecimal converts satoshis → wei as a decimal string.
// 1 satoshi = 10^10 wei, so the wei representation is simply the sats
// value followed by ten zeroes.
func satoshisToWeiDecimal(sats uint64) string {
	if sats == 0 {
		return "0"
	}
	return uint64ToDecimal(sats) + "0000000000"
}

// uint64ToDecimal renders a uint64 as a decimal string without the
// default "+" or leading zeroes.
func uint64ToDecimal(n uint64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
