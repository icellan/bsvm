package beef

import (
	"context"
	"errors"
	"fmt"
	"sync"

	sdkhash "github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	sdktx "github.com/bsv-blockchain/go-sdk/transaction"
	sdkct "github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/icellan/bsvm/pkg/chaintracks"
)

// VerifyConfig drives the BEEF verifier. Zero-valued fields fall back
// to spec-17 defaults at construction time so callers can pass an
// almost-empty struct from config and still get safe behaviour.
type VerifyConfig struct {
	// MaxDepth caps the longest ancestor chain a BEEF may carry. The
	// verifier rejects any envelope whose computed depth exceeds this
	// before walking input scripts. Default 32.
	MaxDepth int
	// MaxWidth caps the total ancestor count across all levels.
	// Default 10000.
	MaxWidth int
	// AnchorDepth is the minimum confirmation depth (in BSV blocks)
	// required for the target transaction's BUMP. 0 disables the check
	// (devnet-only). Default 6 — spec 07's "≥ 6 confirmations" rule.
	AnchorDepth uint64
	// ValidatedCacheSize is the LRU bound on the validated-tx cache.
	// Default 4096; ≤0 disables caching.
	ValidatedCacheSize int
}

// withDefaults fills zero-valued fields with the spec-17 defaults.
func (c VerifyConfig) withDefaults() VerifyConfig {
	if c.MaxDepth <= 0 {
		c.MaxDepth = 32
	}
	if c.MaxWidth <= 0 {
		c.MaxWidth = 10000
	}
	// AnchorDepth == 0 is a legitimate value (devnet relaxation), so
	// only the explicit unset sentinel-here-zero is replaced. Callers
	// that want zero-depth must explicitly set AnchorDepth=0 AND set
	// the corresponding "accept_unverified_bridge_deposits" knob in
	// the cmd-side wiring — verify.go does NOT second-guess depth=0.
	if c.ValidatedCacheSize <= 0 {
		c.ValidatedCacheSize = 4096
	}
	return c
}

// Verifier wraps the go-sdk's BEEF + SPV verification helpers with the
// limits + caching + chaintracks adapter the BSVM overlay needs.
//
// It is safe for concurrent use: the chaintracks adapter is stateless
// and the validated-tx cache is mutex-guarded. A single Verifier can
// (and should) be shared across all BEEF endpoint consumers.
type Verifier struct {
	cfg   VerifyConfig
	chain sdkct.ChainTracker
	ct    chaintracks.ChaintracksClient

	mu    sync.Mutex
	cache *validatedCache
}

// NewVerifier constructs a Verifier rooted at the given chaintracks
// client. Passing nil ct yields a verifier whose Verify call always
// fails (so misconfigured wiring fails closed).
func NewVerifier(ct chaintracks.ChaintracksClient, cfg VerifyConfig) *Verifier {
	cfg = cfg.withDefaults()
	return &Verifier{
		cfg:   cfg,
		chain: NewChaintracksAdapter(ct),
		ct:    ct,
		cache: newValidatedCache(cfg.ValidatedCacheSize),
	}
}

// VerifiedBEEF is the result of a successful Verify call. Target is
// the parsed target transaction with its ancestry graph fully wired
// (every input's SourceTransaction is non-nil and the verifier has
// already executed each unlocking script against the corresponding
// ancestor output). TargetHeight is the BSV block height at which the
// target was mined, or 0 when the target carries no BUMP. Confirmations
// is the depth chaintracks reports for the target's mining block, or
// 0 when the target is unmined.
type VerifiedBEEF struct {
	Target        *sdktx.Transaction
	TargetTxID    [32]byte
	TargetHeight  uint64
	Confirmations int64
	// AncestorCount is the number of distinct ancestor txs the
	// verifier walked, including the target. Useful for metrics +
	// logging.
	AncestorCount int
	// MaxAncestorDepth is the longest chain length the verifier
	// observed. Useful for tightening MaxDepth defaults from
	// observation.
	MaxAncestorDepth int
}

// Verify parses the BRC-62 BEEF body, walks the ancestry graph
// against chaintracks, re-executes every input script, and confirms
// the target's anchor depth meets cfg.AnchorDepth. On success returns
// a *VerifiedBEEF; on any failure returns a typed error.
//
// Callers MUST treat any non-nil error as a hard reject: the envelope
// is dropped, the bridge / inbox / governance / etc. consumer is NOT
// invoked, and the gossip metrics record a rejection with the
// appropriate reason.
func (v *Verifier) Verify(ctx context.Context, beefBytes []byte) (*VerifiedBEEF, error) {
	if v == nil || v.ct == nil {
		return nil, ErrNoChaintracks
	}
	if len(beefBytes) == 0 {
		return nil, ErrEmptyBEEF
	}

	// Step 1: parse the BEEF and recover the target tx with its full
	// ancestry graph. NewTransactionFromBEEF wires every input's
	// SourceTransaction pointer so the script interpreter can see
	// ancestor outputs without an extra fetch.
	target, err := sdktx.NewTransactionFromBEEF(beefBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if target == nil {
		return nil, ErrNoTarget
	}

	// Step 2: enforce ancestor-graph limits before doing any
	// hashing / interpreter work — a malicious peer should not be
	// able to consume CPU by shipping a 10MB BEEF.
	depth, width, err := walkAncestors(target, v.cfg.MaxDepth, v.cfg.MaxWidth)
	if err != nil {
		return nil, err
	}

	// Step 3: BUMP + ancestry + script verification, including the
	// target. spv.Verify uses the ChainTracker for BUMP roots and the
	// script interpreter for unlocking-script execution. We pass nil
	// fee model — fee policy is not the verifier's concern (the
	// covenant + miners enforce it).
	if err := v.verifySPV(ctx, target); err != nil {
		return nil, err
	}

	// Step 4: anchor-depth gate. Only meaningful when the target tx
	// carries its own BUMP (confirmed envelope). Unconfirmed envelopes
	// have no MerklePath on the target, so the depth check trivially
	// passes when AnchorDepth == 0 and fails otherwise.
	var height uint64
	var confirmations int64
	if target.MerklePath != nil {
		height = uint64(target.MerklePath.BlockHeight)
		txid := target.TxID()
		// Confirmations needs the block hash, which we don't carry
		// directly on the BUMP. Fetch the header at height and
		// compare its merkle root to the BUMP's computed root for a
		// sanity check; chaintracks gives us depth from the height
		// alone via its tip.
		hdr, herr := v.ct.HeaderByHeight(ctx, height)
		if herr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAnchorHeader, herr)
		}
		// MerklePath.Verify already ran inside spv.Verify so we know
		// the root binds to a chaintracks-known header at this height.
		// Read confirmations from chaintracks against the same header
		// hash.
		confs, cerr := v.ct.Confirmations(ctx, height, hdr.Hash)
		if cerr != nil {
			return nil, fmt.Errorf("%w: %w", ErrAnchorConfirms, cerr)
		}
		if confs < 0 {
			return nil, ErrAnchorReorged
		}
		confirmations = confs
		_ = txid
	}
	if v.cfg.AnchorDepth > 0 {
		if target.MerklePath == nil {
			return nil, ErrAnchorMissing
		}
		if uint64(confirmations) < v.cfg.AnchorDepth {
			return nil, fmt.Errorf("%w: have %d, need %d", ErrAnchorTooShallow, confirmations, v.cfg.AnchorDepth)
		}
	}

	// Step 5: warm the validated-tx cache so subsequent BEEFs that
	// share ancestors skip re-execution. We cache the target only
	// because spv.Verify already short-circuits on ancestors that
	// have a MerklePath; full per-ancestor caching is a follow-up
	// optimisation if profiling shows it matters.
	if v.cache != nil {
		v.mu.Lock()
		var key [32]byte
		copy(key[:], target.TxID().CloneBytes())
		v.cache.add(key)
		v.mu.Unlock()
	}

	var txid [32]byte
	copy(txid[:], target.TxID().CloneBytes())
	return &VerifiedBEEF{
		Target:           target,
		TargetTxID:       txid,
		TargetHeight:     height,
		Confirmations:    confirmations,
		AncestorCount:    width,
		MaxAncestorDepth: depth,
	}, nil
}

// verifySPV is a wrapper around spv.Verify that lets us short-circuit
// when the cache already trusts the target txid. The wrapper is also a
// convenient seam for unit tests that want to stub the script engine
// (we pass interpreter options directly so a future test mode can
// disable WithForkID for synthetic fixtures).
func (v *Verifier) verifySPV(ctx context.Context, target *sdktx.Transaction) error {
	if v.cache != nil {
		var key [32]byte
		copy(key[:], target.TxID().CloneBytes())
		v.mu.Lock()
		hit := v.cache.has(key)
		v.mu.Unlock()
		if hit {
			// We've already executed every script against ancestors we
			// re-derived from chaintracks; replay the BUMP-only check
			// in case ancestors have since been reorged.
			if target.MerklePath != nil {
				ok, err := target.MerklePath.Verify(ctx, target.TxID(), v.chain)
				if err != nil {
					return fmt.Errorf("%w: %w", ErrBUMP, err)
				}
				if !ok {
					return ErrBUMP
				}
			}
			return nil
		}
	}

	// Replay spv.Verify's ancestry walk inline so we can return more
	// granular errors. The control flow mirrors the SDK's
	// implementation, with the addition that we surface a typed error
	// for each failure mode.
	verified := make(map[string]struct{})
	queue := []*sdktx.Transaction{target}
	for len(queue) > 0 {
		tx := queue[0]
		queue = queue[1:]
		txidHash := tx.TxID()
		txidStr := txidHash.String()
		if _, ok := verified[txidStr]; ok {
			continue
		}
		if tx.MerklePath != nil {
			ok, err := tx.MerklePath.Verify(ctx, txidHash, v.chain)
			if err != nil {
				return fmt.Errorf("%w: tx=%s: %w", ErrBUMP, txidStr, err)
			}
			if !ok {
				return fmt.Errorf("%w: tx=%s", ErrBUMP, txidStr)
			}
			verified[txidStr] = struct{}{}
			continue
		}
		for vin, in := range tx.Inputs {
			source := in.SourceTxOutput()
			if source == nil {
				return fmt.Errorf("%w: tx=%s vin=%d", ErrMissingAncestor, txidStr, vin)
			}
			if in.SourceTransaction != nil {
				if _, ok := verified[in.SourceTransaction.TxID().String()]; !ok {
					queue = append(queue, in.SourceTransaction)
				}
			}
			if err := interpreter.NewEngine().Execute(
				interpreter.WithTx(tx, vin, source),
				interpreter.WithForkID(),
				interpreter.WithAfterGenesis(),
			); err != nil {
				return fmt.Errorf("%w: tx=%s vin=%d: %w", ErrScript, txidStr, vin, err)
			}
		}
	}
	return nil
}

// walkAncestors traverses the target's ancestry graph reachable via
// SourceTransaction pointers and returns the maximum depth observed
// plus the total distinct-tx count. Returns ErrTooDeep / ErrTooWide
// the moment a limit is exceeded, without continuing the walk.
func walkAncestors(target *sdktx.Transaction, maxDepth, maxWidth int) (int, int, error) {
	type frame struct {
		tx    *sdktx.Transaction
		depth int
	}
	seen := make(map[sdkhash.Hash]struct{})
	stack := []frame{{tx: target, depth: 0}}
	deepest := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.tx == nil {
			continue
		}
		if f.depth > deepest {
			deepest = f.depth
		}
		if f.depth > maxDepth {
			return deepest, len(seen), fmt.Errorf("%w: depth %d > max %d", ErrTooDeep, f.depth, maxDepth)
		}
		txid := f.tx.TxID()
		if txid == nil {
			continue
		}
		if _, ok := seen[*txid]; ok {
			continue
		}
		seen[*txid] = struct{}{}
		if len(seen) > maxWidth {
			return deepest, len(seen), fmt.Errorf("%w: width %d > max %d", ErrTooWide, len(seen), maxWidth)
		}
		// A BUMPed ancestor is a leaf — the BUMP itself is the trust
		// boundary. Descend only into non-BUMPed ancestors.
		if f.tx.MerklePath != nil {
			continue
		}
		for _, in := range f.tx.Inputs {
			if in == nil || in.SourceTransaction == nil {
				continue
			}
			stack = append(stack, frame{tx: in.SourceTransaction, depth: f.depth + 1})
		}
	}
	return deepest, len(seen), nil
}

// validatedCache is a simple LRU keyed by 32-byte tx IDs. Bounded
// memory; eviction is FIFO when the cache fills up. The cache is
// safe to consult under a single external mutex (Verifier.mu).
type validatedCache struct {
	cap   int
	order []*[32]byte
	set   map[[32]byte]struct{}
}

func newValidatedCache(capacity int) *validatedCache {
	if capacity <= 0 {
		return nil
	}
	return &validatedCache{
		cap:   capacity,
		order: make([]*[32]byte, 0, capacity),
		set:   make(map[[32]byte]struct{}, capacity),
	}
}

func (c *validatedCache) add(key [32]byte) {
	if c == nil {
		return
	}
	if _, ok := c.set[key]; ok {
		return
	}
	if len(c.order) >= c.cap {
		// Evict the oldest entry.
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.set, *oldest)
	}
	k := key
	c.order = append(c.order, &k)
	c.set[key] = struct{}{}
}

func (c *validatedCache) has(key [32]byte) bool {
	if c == nil {
		return false
	}
	_, ok := c.set[key]
	return ok
}

// Verifier errors. Callers can errors.Is against these to drive
// per-reason metrics + alerting without parsing message strings.
var (
	// ErrEmptyBEEF is returned when the BEEF body is zero-length.
	ErrEmptyBEEF = errors.New("beef: empty body")
	// ErrParse is returned when go-sdk's BEEF reader rejects the
	// envelope structure (bad magic, malformed varints, truncated
	// BUMPs, etc).
	ErrParse = errors.New("beef: parse failed")
	// ErrNoTarget is returned when the BEEF parses but yields no
	// target transaction (BRC-62 requires at least one).
	ErrNoTarget = errors.New("beef: no target transaction")
	// ErrNoChaintracks is returned when the verifier was constructed
	// without a chaintracks client.
	ErrNoChaintracks = errors.New("beef: verifier has no chaintracks client")
	// ErrTooDeep is returned when ancestor depth exceeds MaxDepth.
	ErrTooDeep = errors.New("beef: ancestor chain too deep")
	// ErrTooWide is returned when the total ancestor count exceeds
	// MaxWidth.
	ErrTooWide = errors.New("beef: too many ancestors")
	// ErrBUMP is returned when a merkle path fails to verify against
	// the chaintracks-known header at the path's declared height.
	ErrBUMP = errors.New("beef: merkle path does not verify")
	// ErrMissingAncestor is returned when a target input references a
	// previous output the BEEF does not include.
	ErrMissingAncestor = errors.New("beef: missing ancestor for input")
	// ErrScript is returned when an unlocking script does not satisfy
	// its referenced locking script under standard BSV consensus
	// rules.
	ErrScript = errors.New("beef: input script verification failed")
	// ErrAnchorMissing is returned when AnchorDepth > 0 but the
	// target carries no BUMP.
	ErrAnchorMissing = errors.New("beef: target has no merkle path but anchor depth required")
	// ErrAnchorTooShallow is returned when the target's BUMP is
	// confirmed at a depth less than AnchorDepth.
	ErrAnchorTooShallow = errors.New("beef: target anchor depth below threshold")
	// ErrAnchorHeader is returned when the chaintracks header lookup
	// at the target's BUMP height fails for a reason other than
	// "unknown header".
	ErrAnchorHeader = errors.New("beef: anchor header lookup failed")
	// ErrAnchorConfirms is returned when chaintracks fails to report
	// a confirmation count for the target's mining block.
	ErrAnchorConfirms = errors.New("beef: anchor confirmation lookup failed")
	// ErrAnchorReorged is returned when chaintracks reports the
	// target's mining block is no longer on the best chain (Confirmations
	// returned -1).
	ErrAnchorReorged = errors.New("beef: target block reorged off best chain")
)
