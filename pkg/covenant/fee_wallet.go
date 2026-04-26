// Package covenant: FeeWallet — provers maintain this BSV wallet to pay
// miner fees on covenant-advance transactions. It is NOT a sequencer
// key. The covenant has no signature check on its advance path; the
// fee wallet only signs its own funding inputs. If the wallet runs
// dry the prover keeps executing locally and continues to gossip
// transactions; only on-chain advances are skipped until float
// recovers.
//
// The wallet exposes three concurrency-safe operations that race in
// production:
//
//   - SelectUTXOs reserves a non-overlapping set of UTXOs for one
//     advance. Two parallel advance attempts are guaranteed to receive
//     disjoint inputs.
//   - Release returns previously-reserved UTXOs to the available pool
//     when an advance is abandoned before broadcast.
//   - MarkSpent permanently removes UTXOs after the advance broadcasts,
//     even if the BSV node briefly still reports them as unspent on
//     listunspent (mempool propagation lag).
//
// Reservation, release, and consolidation all share a single mutex so
// no UTXO can be selected twice and consolidation never races with a
// live advance.
package covenant

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/icellan/bsvm/pkg/bsv"
	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/types"
)

// ErrFeeWalletEmpty is returned by SelectUTXOs when the wallet's
// available pool sums to less than the requested fee.
var ErrFeeWalletEmpty = errors.New("fee wallet: insufficient funds")

// UTXO is the fee-wallet UTXO type. Re-uses pkg/bsv.UTXO so that the
// rest of the BSV transaction-building code can consume the same shape
// without an extra adapter step. The alias is exported so callers
// outside this package can reference the type via covenant.UTXO.
type UTXO = bsv.UTXO

// BSVClient is the minimal subset of a BSV node client the FeeWallet
// needs. The production binary supplies pkg/bsvclient.RPCProvider; tests
// supply an in-memory stub. Keeping the interface narrow lets us avoid
// pulling pkg/bsvclient or runar.Provider into pkg/covenant.
//
// ListUTXOs returns the wallet's currently-spendable outputs at the
// given P2PKH address (or wallet identifier — the implementation
// chooses the discriminator). BroadcastTx submits a fully-signed BSV
// raw transaction in hex form and returns the resulting txid hex.
type BSVClient interface {
	ListUTXOs(ctx context.Context, address string) ([]UTXO, error)
	BroadcastTx(ctx context.Context, rawTxHex string) (string, error)
}

// PrivateKey is the minimal signing seam the FeeWallet uses to author
// consolidation transactions. The production binary plugs in the BSV
// SDK's *ec.PrivateKey behind this interface (or a hardware-wallet
// adapter); tests use a stub. Address returns the canonical P2PKH
// address that ListUTXOs is queried against and that consolidation
// outputs pay back to. SignInput signs the i-th input of a partial
// transaction encoded as raw hex and returns the unlocking script
// hex (sig+pubkey) the caller will splice into the transaction.
type PrivateKey interface {
	Address() string
	SignInput(rawTxHex string, inputIndex int, prevScriptHex string, prevSatoshis uint64) (unlockHex string, err error)
}

// utxoKey is the in-memory map key for a UTXO: BSV-canonical txid hex
// (big-endian) plus colon plus decimal vout. Matches the format used
// by the older pkg/overlay.FeeWallet so a future merge of the two
// implementations does not have to rewrite stored references.
func utxoKey(txid types.Hash, vout uint32) string {
	return fmt.Sprintf("%s:%d", txid.BSVString(), vout)
}

// FeeWallet manages the BSV UTXO float that pays miner fees on
// covenant-advance transactions. See the package doc comment for
// concurrency model.
type FeeWallet struct {
	client           BSVClient
	key              PrivateKey
	minFloatSatoshis uint64

	mu        sync.Mutex
	available map[string]UTXO // pool callers may reserve from
	reserved  map[string]UTXO // returned by SelectUTXOs, not yet broadcast
	spent     map[string]struct{}

	// Consolidation tunables. The defaults match spec 10 §"Fee Wallet
	// Bootstrap" — consolidate when >= 50 UTXOs are tracked.
	consolidateThreshold int

	// Metrics hooks. Each is optional; a nil hook is a no-op.
	onBalanceChange   func(balance uint64, utxoCount int)
	onStarvationEvent func()
}

// NewFeeWallet constructs a fee wallet that can sign with key and
// observe / spend through client. minFloatSatoshis is the threshold
// FloatHealth uses to flag the wallet as starved; pass 0 to disable
// the check (FloatHealth then always reports ok=true, useful in
// tests). The wallet starts empty — the caller is responsible for
// loading the available pool via Refresh before SelectUTXOs returns
// non-empty results.
func NewFeeWallet(client BSVClient, key PrivateKey, minFloatSatoshis uint64) *FeeWallet {
	return &FeeWallet{
		client:               client,
		key:                  key,
		minFloatSatoshis:     minFloatSatoshis,
		available:            make(map[string]UTXO),
		reserved:             make(map[string]UTXO),
		spent:                make(map[string]struct{}),
		consolidateThreshold: 50,
	}
}

// SetConsolidationThreshold overrides the default 50-UTXO consolidation
// gate. A non-positive value resets to the default.
func (fw *FeeWallet) SetConsolidationThreshold(n int) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if n <= 0 {
		n = 50
	}
	fw.consolidateThreshold = n
}

// SetMetricsHooks registers optional callbacks invoked when wallet
// state changes. balanceChange fires after any add/remove that
// changes the available balance; starvation fires once per
// SelectUTXOs call that returns ErrFeeWalletEmpty. Pass nil for
// either to disable that hook.
func (fw *FeeWallet) SetMetricsHooks(balanceChange func(balance uint64, utxoCount int), starvation func()) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.onBalanceChange = balanceChange
	fw.onStarvationEvent = starvation
}

// RegisterMetrics wires the fee wallet's hooks into the supplied
// Prometheus registry under the bsvm_fee_wallet_* namespace:
//
//   - bsvm_fee_wallet_balance_satoshis (gauge): available pool balance.
//   - bsvm_fee_wallet_utxo_count (gauge): available pool size.
//   - bsvm_fee_wallet_starvation_total (counter): SelectUTXOs calls
//     that returned ErrFeeWalletEmpty.
//
// Passing a nil registry disables Prometheus exposition while still
// resetting any previously-installed hooks.
func (fw *FeeWallet) RegisterMetrics(registry *metrics.Registry) {
	if registry == nil {
		fw.SetMetricsHooks(nil, nil)
		return
	}
	balanceGauge := registry.Gauge(
		"bsvm_fee_wallet_balance_satoshis",
		"Spendable BSV satoshis currently available in the fee wallet (excludes reserved UTXOs).",
	)
	utxoGauge := registry.Gauge(
		"bsvm_fee_wallet_utxo_count",
		"Number of unreserved UTXOs in the fee wallet's available pool.",
	)
	starvationCounter := registry.Counter(
		"bsvm_fee_wallet_starvation_total",
		"Cumulative count of SelectUTXOs calls that returned ErrFeeWalletEmpty.",
	)
	fw.SetMetricsHooks(
		func(balance uint64, utxoCount int) {
			balanceGauge.Set(float64(balance))
			utxoGauge.Set(float64(utxoCount))
		},
		func() {
			starvationCounter.Inc()
		},
	)
	// Emit an initial sample so /metrics shows zero rather than missing
	// series before the first add/remove event.
	balanceGauge.Set(float64(fw.Balance()))
	utxoGauge.Set(float64(fw.UTXOCount()))
}

// Address returns the BSV P2PKH address the fee wallet pays from.
// Empty when no key was configured (defensive — should not happen in
// production).
func (fw *FeeWallet) Address() string {
	if fw.key == nil {
		return ""
	}
	return fw.key.Address()
}

// AddUTXO inserts a single UTXO into the available pool. Idempotent:
// adding the same outpoint twice is a no-op. Used by the bootstrap
// path and by tests; production code that wants to merge from
// listunspent should use Refresh.
func (fw *FeeWallet) AddUTXO(u UTXO) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	k := utxoKey(u.TxID, u.Vout)
	if _, ok := fw.spent[k]; ok {
		return
	}
	if _, ok := fw.reserved[k]; ok {
		return
	}
	if _, ok := fw.available[k]; ok {
		return
	}
	fw.available[k] = u
	fw.notifyBalanceChangeLocked()
}

// Refresh reconciles the local pool with the BSV node's view of the
// wallet's UTXO set. UTXOs the node reports that are not yet tracked
// (and not already reserved or spent) are added to the available
// pool; UTXOs in the available pool that the node no longer reports
// are removed. Reserved and spent sets are left untouched.
//
// The implementation calls ListUTXOs under a short read window, then
// merges under the wallet mutex.
func (fw *FeeWallet) Refresh(ctx context.Context) error {
	if fw.client == nil {
		return errors.New("fee wallet: nil client")
	}
	utxos, err := fw.client.ListUTXOs(ctx, fw.Address())
	if err != nil {
		return fmt.Errorf("fee wallet: list utxos: %w", err)
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	seen := make(map[string]struct{}, len(utxos))
	for _, u := range utxos {
		k := utxoKey(u.TxID, u.Vout)
		seen[k] = struct{}{}
		if _, ok := fw.spent[k]; ok {
			continue
		}
		if _, ok := fw.reserved[k]; ok {
			continue
		}
		fw.available[k] = u
	}
	for k := range fw.available {
		if _, ok := seen[k]; !ok {
			delete(fw.available, k)
		}
	}
	fw.notifyBalanceChangeLocked()
	return nil
}

// SelectUTXOs reserves the fewest UTXOs whose total satoshis cover
// feeSatoshis. The reservation is exclusive — concurrent SelectUTXOs
// calls cannot pick the same outpoints. Returns ErrFeeWalletEmpty
// when the available pool sums to less than feeSatoshis.
//
// Selection is deterministic: UTXOs are sorted (Satoshis desc, then
// canonical txid:vout asc as the tiebreaker) before greedy
// accumulation. Two nodes seeing the same available pool will return
// the same reservation set.
func (fw *FeeWallet) SelectUTXOs(ctx context.Context, feeSatoshis uint64) ([]UTXO, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if feeSatoshis == 0 {
		return nil, fmt.Errorf("fee wallet: feeSatoshis must be > 0")
	}

	var total uint64
	for _, u := range fw.available {
		total += u.Satoshis
	}
	if total < feeSatoshis {
		if fw.onStarvationEvent != nil {
			fw.onStarvationEvent()
		}
		return nil, ErrFeeWalletEmpty
	}

	pool := make([]UTXO, 0, len(fw.available))
	for _, u := range fw.available {
		pool = append(pool, u)
	}
	sort.Slice(pool, func(i, j int) bool {
		if pool[i].Satoshis != pool[j].Satoshis {
			return pool[i].Satoshis > pool[j].Satoshis
		}
		return utxoKey(pool[i].TxID, pool[i].Vout) < utxoKey(pool[j].TxID, pool[j].Vout)
	})

	selected := make([]UTXO, 0, 4)
	var acc uint64
	for _, u := range pool {
		selected = append(selected, u)
		acc += u.Satoshis
		if acc >= feeSatoshis {
			break
		}
	}
	if acc < feeSatoshis {
		// Shouldn't happen — total covered the request — but be defensive.
		if fw.onStarvationEvent != nil {
			fw.onStarvationEvent()
		}
		return nil, ErrFeeWalletEmpty
	}

	for _, u := range selected {
		k := utxoKey(u.TxID, u.Vout)
		delete(fw.available, k)
		fw.reserved[k] = u
	}
	fw.notifyBalanceChangeLocked()
	return selected, nil
}

// Release returns previously-reserved UTXOs to the available pool.
// Call this when a broadcast is abandoned before the transaction hits
// the BSV node. UTXOs that were never reserved (or have already been
// MarkSpent) are silently skipped — Release is idempotent so the
// caller can defer it without tracking partial-commit state.
func (fw *FeeWallet) Release(utxos []UTXO) {
	if len(utxos) == 0 {
		return
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	for _, u := range utxos {
		k := utxoKey(u.TxID, u.Vout)
		if _, isSpent := fw.spent[k]; isSpent {
			continue
		}
		if _, ok := fw.reserved[k]; !ok {
			continue
		}
		delete(fw.reserved, k)
		fw.available[k] = u
	}
	fw.notifyBalanceChangeLocked()
}

// MarkSpent records that the given UTXOs were broadcast as inputs in
// a covenant advance. They are removed from both reserved and
// available pools and added to the spent set, which prevents them
// from reappearing in the pool the next time Refresh runs while the
// BSV node mempool still reports them as unspent.
func (fw *FeeWallet) MarkSpent(utxos []UTXO) {
	if len(utxos) == 0 {
		return
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	for _, u := range utxos {
		k := utxoKey(u.TxID, u.Vout)
		delete(fw.reserved, k)
		delete(fw.available, k)
		fw.spent[k] = struct{}{}
	}
	fw.notifyBalanceChangeLocked()
}

// Balance returns the total satoshis in the available pool. Reserved
// UTXOs are not counted — they are committed to an in-flight advance.
func (fw *FeeWallet) Balance() uint64 {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	var total uint64
	for _, u := range fw.available {
		total += u.Satoshis
	}
	return total
}

// UTXOCount returns the number of UTXOs currently in the available
// pool. Used by metrics surfaces.
func (fw *FeeWallet) UTXOCount() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return len(fw.available)
}

// IsStarved reports whether the available balance is below the
// configured minimum float. Equivalent to !ok from FloatHealth, exposed
// separately so RPC callers do not have to discard the balance/min
// values just to check the boolean.
func (fw *FeeWallet) IsStarved() bool {
	ok, _, _ := fw.FloatHealth()
	return !ok
}

// FloatHealth reports whether the available balance is at or above the
// configured minimum float. Returns (ok, balance, minFloat). When
// minFloat is zero the check is disabled and ok is always true.
//
// Starvation is informational — the overlay node treats the boolean as
// a signal to skip BroadcastAdvance, not as an error to propagate.
// Local execution and gossip continue regardless.
func (fw *FeeWallet) FloatHealth() (ok bool, balance, minFloat uint64) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	for _, u := range fw.available {
		balance += u.Satoshis
	}
	minFloat = fw.minFloatSatoshis
	if minFloat == 0 {
		return true, balance, 0
	}
	return balance >= minFloat, balance, minFloat
}

// Consolidate merges every available UTXO into a single self-spend
// transaction, reducing future SelectUTXOs work. Only runs when the
// available pool size is at or above the consolidation threshold;
// otherwise returns nil with no error so the caller can call this on
// a timer without checking the count itself.
//
// Holds the wallet mutex for the duration of the call so no
// SelectUTXOs / Release / MarkSpent can interleave. The signed
// transaction is broadcast through the BSVClient; on success the
// inputs are moved to the spent set and the new output is added to
// the available pool. On broadcast failure no state mutation occurs
// (the inputs stay in the available pool) so retry is safe.
//
// The transaction-building path is intentionally minimal: a single
// input per UTXO, a single P2PKH output back to the wallet's address,
// and a 1 sat/byte fee estimate. Production callers that want a
// richer fee policy should adapt the helper after broadcast lands.
func (fw *FeeWallet) Consolidate(ctx context.Context) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if len(fw.available) < fw.consolidateThreshold {
		return nil
	}
	if fw.client == nil || fw.key == nil {
		return errors.New("fee wallet: client and key required for consolidation")
	}

	inputs := make([]UTXO, 0, len(fw.available))
	var totalSats uint64
	for _, u := range fw.available {
		inputs = append(inputs, u)
		totalSats += u.Satoshis
	}
	sort.Slice(inputs, func(i, j int) bool {
		return utxoKey(inputs[i].TxID, inputs[i].Vout) < utxoKey(inputs[j].TxID, inputs[j].Vout)
	})

	rawHex, fee, err := buildConsolidationTx(inputs, fw.key)
	if err != nil {
		return fmt.Errorf("fee wallet: build consolidation: %w", err)
	}
	if fee >= totalSats {
		return fmt.Errorf("fee wallet: consolidation fee %d exceeds total %d", fee, totalSats)
	}

	txidStr, err := fw.client.BroadcastTx(ctx, rawHex)
	if err != nil {
		return fmt.Errorf("fee wallet: broadcast consolidation: %w", err)
	}
	newTxID, err := parseTxIDHex(txidStr)
	if err != nil {
		return fmt.Errorf("fee wallet: parse consolidation txid: %w", err)
	}

	for _, u := range inputs {
		k := utxoKey(u.TxID, u.Vout)
		delete(fw.available, k)
		fw.spent[k] = struct{}{}
	}
	out := UTXO{
		TxID:     newTxID,
		Vout:     0,
		Satoshis: totalSats - fee,
		Script:   bsv.BuildP2PKH(make([]byte, 20)), // placeholder; the real spend rebuilds from key
	}
	fw.available[utxoKey(out.TxID, out.Vout)] = out
	fw.notifyBalanceChangeLocked()
	return nil
}

// notifyBalanceChangeLocked invokes the balance-change hook with the
// current available balance and UTXO count. Caller must hold fw.mu.
func (fw *FeeWallet) notifyBalanceChangeLocked() {
	if fw.onBalanceChange == nil {
		return
	}
	var bal uint64
	for _, u := range fw.available {
		bal += u.Satoshis
	}
	fw.onBalanceChange(bal, len(fw.available))
}
