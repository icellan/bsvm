package sim

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/sim/contracts"
	"github.com/icellan/bsvm/pkg/types"
)

// MultisigWorkload runs the full submit → confirm → execute ceremony
// against the deployed multisig. One round = three internal txs (one
// per signer), so the workload counts one "success" per completed
// ceremony, not per raw tx.
//
// The owner set is fixed at deploy time: the first five sim users.
type MultisigWorkload struct {
	baseStats
	pool     *UserPool
	reg      *Registry
	addr     types.Address
	required int
	ownerSet []types.Address
	rng      *rand.Rand

	rounds atomic.Uint64
	// serialise rounds so two ceremonies never compete for the same
	// owner mutex in conflicting orders — if they did, each would grab
	// a different subset and could deadlock if the ordering inverts.
	roundMu sync.Mutex
}

func NewMultisigWorkload(pool *UserPool, reg *Registry, addr types.Address, required int, owners []types.Address, initialRate int) *MultisigWorkload {
	w := &MultisigWorkload{
		pool:     pool,
		reg:      reg,
		addr:     addr,
		required: required,
		ownerSet: owners,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano() ^ 0x99)),
	}
	initBaseStats(&w.baseStats, KindMultisig, initialRate, 16)
	return w
}

func (w *MultisigWorkload) Kind() WorkloadKind   { return KindMultisig }
func (w *MultisigWorkload) SetRate(tps int)      { w.rate.Store(int32(tps)) }
func (w *MultisigWorkload) Stats() WorkloadStats { return w.baseStats.snapshot() }

func (w *MultisigWorkload) Run(ctx context.Context) {
	for {
		if !waitTick(ctx, &w.baseStats) {
			return
		}
		w.roundMu.Lock()
		err := w.doRound(ctx)
		w.roundMu.Unlock()
		w.submitted.Add(1)
		if err != nil {
			w.recordFailure(err)
		} else {
			w.recordSuccess(0)
		}
		w.reg.notify(w.Stats())
	}
}

func (w *MultisigWorkload) doRound(ctx context.Context) error {
	if len(w.ownerSet) == 0 {
		return errors.New("no owners")
	}
	// Pick submitter from the first owner pool. They all share the
	// workflow: submit, then every other owner confirms.
	submitterAddr := w.ownerSet[w.rng.Intn(len(w.ownerSet))]
	submitter := w.userByAddress(submitterAddr)
	if submitter == nil {
		return fmt.Errorf("owner %s missing from pool", submitterAddr.Hex())
	}
	// Trivial payload: call txCount() on the multisig itself. The
	// multisig's receive() accepts any call so this always succeeds.
	data := contracts.EncodeMultisigSubmit(w.addr, uint256.NewInt(0), contracts.EncodeMultisigTxCount())
	if err := w.submit(ctx, submitter, data); err != nil {
		return fmt.Errorf("submit: %w", err)
	}

	// Query txCount on the submitter's sticky node so we see the chain
	// state that includes our submit(). Other nodes may lag.
	id, err := w.currentTxIDOn(ctx, submitter)
	if err != nil {
		return fmt.Errorf("txCount: %w", err)
	}

	// Confirm with (required-1) other owners. (The submitter already
	// counts as one confirmation via submit().)
	pending := 0
	for _, o := range w.ownerSet {
		if o == submitterAddr || pending >= w.required-1 {
			continue
		}
		u := w.userByAddress(o)
		if u == nil {
			continue
		}
		if err := w.confirm(ctx, u, id); err != nil {
			return fmt.Errorf("confirm owner %s: %w", o.Hex(), err)
		}
		pending++
	}

	// Execute — anyone can call. Use the submitter.
	if err := w.execute(ctx, submitter, id); err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	w.rounds.Add(1)
	return nil
}

func (w *MultisigWorkload) submit(ctx context.Context, u *User, data []byte) error {
	return w.sendOwnerCall(ctx, u, data, 500_000)
}

func (w *MultisigWorkload) confirm(ctx context.Context, u *User, id *uint256.Int) error {
	return w.sendOwnerCall(ctx, u, contracts.EncodeMultisigConfirm(id), 120_000)
}

func (w *MultisigWorkload) execute(ctx context.Context, u *User, id *uint256.Int) error {
	return w.sendOwnerCall(ctx, u, contracts.EncodeMultisigExecute(id), 300_000)
}

func (w *MultisigWorkload) sendOwnerCall(ctx context.Context, u *User, data []byte, gas uint64) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		user, nonce, release, err := w.pool.Borrow(ctx, u.ID)
		if err != nil {
			return err
		}
		gp, err := w.pool.MultiClient().ForWrite(user.ID).GasPrice(ctx)
		if err != nil || gp == nil || gp.Sign() == 0 {
			gp = big.NewInt(1)
		}
		to := w.addr
		_, err = w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gp,
			Gas:      gas,
			To:       &to,
			Value:    uint256.NewInt(0),
			Data:     data,
		})
		if err == nil {
			release(true)
			return nil
		}
		release(false)
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return lastErr
}

func (w *MultisigWorkload) userByAddress(addr types.Address) *User {
	for _, u := range w.pool.Users() {
		if u.Address == addr {
			return u
		}
	}
	return nil
}

func (w *MultisigWorkload) currentTxIDOn(ctx context.Context, u *User) (*uint256.Int, error) {
	c := w.pool.MultiClient().ForWrite(u.ID)
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		ret, err := c.EthCall(ctx, w.pool.Faucet().Address, w.addr, contracts.EncodeMultisigTxCount())
		if err != nil {
			lastErr = err
		} else if len(ret) >= 32 {
			count := contracts.DecodeUint256(ret, 0)
			if !count.IsZero() {
				return new(uint256.Int).Sub(count, uint256.NewInt(1)), nil
			}
			lastErr = errors.New("no txs yet")
		} else {
			lastErr = fmt.Errorf("short return: %d bytes", len(ret))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil, lastErr
}

func (w *MultisigWorkload) currentTxID(ctx context.Context) (*uint256.Int, error) {
	// Multi-node state diverges in this devnet — query the highest-height
	// node so we see a chain view that includes our submit() tx.
	clients := w.pool.MultiClient().All()
	heights := make([]uint64, len(clients))
	for i, c := range clients {
		h, err := c.BlockNumber(ctx)
		if err == nil {
			heights[i] = h
		}
	}
	c := w.pool.MultiClient().Highest(heights)
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		ret, err := c.EthCall(ctx, w.pool.Faucet().Address, w.addr, contracts.EncodeMultisigTxCount())
		if err != nil {
			lastErr = err
		} else if len(ret) >= 32 {
			count := contracts.DecodeUint256(ret, 0)
			if !count.IsZero() {
				return new(uint256.Int).Sub(count, uint256.NewInt(1)), nil
			}
			lastErr = errors.New("no txs yet")
		} else {
			lastErr = fmt.Errorf("short txCount return: %d bytes", len(ret))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil, lastErr
}
