package sim

import (
	"context"
	"math/big"
	"math/rand"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/sim/contracts"
	"github.com/icellan/bsvm/pkg/types"
)

// ERC20Workload drives token transfers against one of the deployed
// ERC20s. The faucet starts with the full supply; on workload start
// it seeds each user with enough tokens to keep transfers flowing.
type ERC20Workload struct {
	baseStats
	pool     *UserPool
	reg      *Registry
	token    types.Address
	rng      *rand.Rand
	seeded   bool
	seedOnce chan struct{}
}

func NewERC20Workload(pool *UserPool, reg *Registry, token types.Address, initialRate int) *ERC20Workload {
	w := &ERC20Workload{
		pool:     pool,
		reg:      reg,
		token:    token,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano() ^ 0x20)),
		seedOnce: make(chan struct{}),
	}
	initBaseStats(&w.baseStats, KindERC20Transfer, initialRate, 32)
	return w
}

func (w *ERC20Workload) Kind() WorkloadKind   { return KindERC20Transfer }
func (w *ERC20Workload) SetRate(tps int)      { w.rate.Store(int32(tps)) }
func (w *ERC20Workload) Stats() WorkloadStats { return w.baseStats.snapshot() }

// SeedFromFaucet distributes `perUser` tokens to every sim user from
// the faucet. Safe to call multiple times — the first call wins.
func (w *ERC20Workload) SeedFromFaucet(ctx context.Context, perUser *uint256.Int) error {
	select {
	case <-w.seedOnce:
		return nil
	default:
	}
	for _, u := range w.pool.Users() {
		data := contracts.EncodeERC20Transfer(u.Address, perUser)
		if _, err := w.pool.FaucetCall(ctx, w.token, 0, data); err != nil {
			return err
		}
	}
	close(w.seedOnce)
	w.seeded = true
	return nil
}

func (w *ERC20Workload) Run(ctx context.Context) {
	for {
		if !waitTick(ctx, &w.baseStats) {
			return
		}
		w.step(ctx)
	}
}

func (w *ERC20Workload) step(ctx context.Context) {
	users := w.pool.Users()
	if len(users) < 2 {
		return
	}
	from := users[w.rng.Intn(len(users))]
	to := users[w.rng.Intn(len(users))]
	for to.ID == from.ID {
		to = users[w.rng.Intn(len(users))]
	}
	amount := uint256.NewInt(uint64(w.rng.Int63n(1000) + 1))
	data := contracts.EncodeERC20Transfer(to.Address, amount)

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
	tokenAddr := w.token
	start := time.Now()
	_, err = w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      100_000,
		To:       &tokenAddr,
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
