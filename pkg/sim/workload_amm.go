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

// AMMWorkload drives swaps on the SimpleAMM pair. On first run it seeds
// liquidity from the faucet, then workers pick random users to swap in
// random directions.
//
// Each user is approved once (lazily) for both tokens to avoid burning
// nonces on approvals every round.
type AMMWorkload struct {
	baseStats
	pool    *UserPool
	reg     *Registry
	token0  types.Address
	token1  types.Address
	amm     types.Address
	rng     *rand.Rand
	seeded  atomic.Bool
	approved sync.Map // types.Address -> struct{}
}

func NewAMMWorkload(pool *UserPool, reg *Registry, token0, token1, amm types.Address, initialRate int) *AMMWorkload {
	w := &AMMWorkload{
		pool:   pool,
		reg:    reg,
		token0: token0,
		token1: token1,
		amm:    amm,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano() ^ 0x88)),
	}
	initBaseStats(&w.baseStats, KindAMMSwap, initialRate, 32)
	return w
}

func (w *AMMWorkload) Kind() WorkloadKind { return KindAMMSwap }
func (w *AMMWorkload) SetRate(tps int)    { w.rate.Store(int32(tps)) }
func (w *AMMWorkload) Stats() WorkloadStats { return w.baseStats.snapshot() }

// SeedLiquidity seeds liquidity from the faucet. Must be called once
// before the workload starts. The faucet must hold both tokens (the
// Deploy path mints the full supply to the faucet by default).
func (w *AMMWorkload) SeedLiquidity(ctx context.Context, amount0, amount1 *uint256.Int) error {
	if !w.seeded.CompareAndSwap(false, true) {
		return nil
	}
	// Transfer the reserves from the faucet into the AMM, then call addLiquidity.
	if _, err := w.pool.FaucetCall(ctx, w.token0, 0, contracts.EncodeERC20Transfer(w.amm, amount0)); err != nil {
		return fmt.Errorf("seed token0 to amm: %w", err)
	}
	if _, err := w.pool.FaucetCall(ctx, w.token1, 0, contracts.EncodeERC20Transfer(w.amm, amount1)); err != nil {
		return fmt.Errorf("seed token1 to amm: %w", err)
	}
	// addLiquidity expects uint112 arguments; cap at 2^112-1.
	cap112 := new(uint256.Int).Sub(new(uint256.Int).Lsh(uint256.NewInt(1), 112), uint256.NewInt(1))
	a0 := amount0
	a1 := amount1
	if a0.Cmp(cap112) > 0 {
		a0 = cap112
	}
	if a1.Cmp(cap112) > 0 {
		a1 = cap112
	}
	if _, err := w.pool.FaucetCall(ctx, w.amm, 0, contracts.EncodeAMMAddLiquidity(a0, a1)); err != nil {
		return fmt.Errorf("seed addLiquidity: %w", err)
	}
	return nil
}

func (w *AMMWorkload) Run(ctx context.Context) {
	for {
		if !waitTick(ctx, &w.baseStats) {
			return
		}
		w.step(ctx)
	}
}

func (w *AMMWorkload) step(ctx context.Context) {
	if !w.seeded.Load() {
		w.recordFailure(errors.New("amm not seeded"))
		w.reg.notify(w.Stats())
		return
	}
	users := w.pool.Users()
	if len(users) == 0 {
		return
	}
	from := users[w.rng.Intn(len(users))]

	// First: make sure the user is approved to spend both tokens. One
	// approval each (max uint256). Approval burns 2 nonces per user
	// the first time we see them.
	if _, approved := w.approved.Load(from.Address); !approved {
		if err := w.approveAll(ctx, from); err != nil {
			w.recordFailure(err)
			w.reg.notify(w.Stats())
			return
		}
		w.approved.Store(from.Address, struct{}{})
	}

	// Decide direction + amount.
	zeroForOne := w.rng.Intn(2) == 0
	tokenIn := w.token0
	if !zeroForOne {
		tokenIn = w.token1
	}
	// Tokens have 1 wei granularity in the MinimalERC20 — swap 10-10000
	// units per round so the AMM's reserves don't get drained.
	amountIn := uint256.NewInt(uint64(w.rng.Int63n(9990) + 10))
	data := contracts.EncodeAMMSwap(tokenIn, amountIn, uint256.NewInt(0))

	user, nonce, release, err := w.pool.Borrow(ctx, from.ID)
	if err != nil {
		w.recordFailure(err)
		w.reg.notify(w.Stats())
		return
	}
	w.submitted.Add(1)

	gp, err := w.pool.MultiClient().ForWrite(user.ID).GasPrice(ctx)
	if err != nil || gp == nil || gp.Sign() == 0 {
		gp = big.NewInt(1)
	}
	ammAddr := w.amm
	start := time.Now()
	_, err = w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      250_000,
		To:       &ammAddr,
		Value:    uint256.NewInt(0),
		Data:     data,
	})
	if err != nil {
		release(false)
		w.recordFailure(err)
		w.reg.notify(w.Stats())
		return
	}
	release(true)
	w.recordSuccess(time.Since(start))
	w.reg.notify(w.Stats())
}

func (w *AMMWorkload) approveAll(ctx context.Context, u *User) error {
	maxUint := new(uint256.Int).Not(uint256.NewInt(0))
	for _, token := range []types.Address{w.token0, w.token1} {
		if err := w.approveOne(ctx, u, token, maxUint); err != nil {
			return fmt.Errorf("approve %s: %w", token.Hex(), err)
		}
	}
	return nil
}

func (w *AMMWorkload) approveOne(ctx context.Context, u *User, token types.Address, amount *uint256.Int) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		user, nonce, release, err := w.pool.Borrow(ctx, u.ID)
		if err != nil {
			return fmt.Errorf("borrow: %w", err)
		}
		gp, err := w.pool.MultiClient().ForWrite(user.ID).GasPrice(ctx)
		if err != nil || gp == nil || gp.Sign() == 0 {
			gp = big.NewInt(1)
		}
		tokenAddr := token
		data := contracts.EncodeERC20Approve(w.amm, amount)
		_, err = w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gp,
			Gas:      80_000,
			To:       &tokenAddr,
			Value:    uint256.NewInt(0),
			Data:     data,
		})
		if err == nil {
			release(true)
			return nil
		}
		release(false)
		lastErr = err
		// On nonce drift, the user is marked dirty inside SignAndSubmit;
		// give the next Borrow a beat to reconcile from the node.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return lastErr
}

// Need sync import for sync.Map used above.
var _ = errors.New
