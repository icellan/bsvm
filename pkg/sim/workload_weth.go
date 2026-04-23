package sim

import (
	"context"
	"math/big"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/sim/contracts"
	"github.com/icellan/bsvm/pkg/types"
)

// WETHWorkload alternates deposit / transfer / withdraw on the WETH
// contract. Each step picks a random user and runs one of the three
// actions weighted toward deposit + transfer (50/40/10).
type WETHWorkload struct {
	baseStats
	pool *UserPool
	reg  *Registry
	weth types.Address
	rng  *rand.Rand
	// per-user cached wrapped balance tracker (atomic to avoid locks).
	wrapped sync.Map // types.Address -> *atomic.Uint64
}

func NewWETHWorkload(pool *UserPool, reg *Registry, weth types.Address, initialRate int) *WETHWorkload {
	w := &WETHWorkload{
		pool: pool,
		reg:  reg,
		weth: weth,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano() ^ 0x73)),
	}
	initBaseStats(&w.baseStats, KindWETHCycle, initialRate, 32)
	return w
}

func (w *WETHWorkload) Kind() WorkloadKind { return KindWETHCycle }
func (w *WETHWorkload) SetRate(tps int)    { w.rate.Store(int32(tps)) }
func (w *WETHWorkload) Stats() WorkloadStats { return w.baseStats.snapshot() }

func (w *WETHWorkload) Run(ctx context.Context) {
	for {
		if !waitTick(ctx, &w.baseStats) {
			return
		}
		w.step(ctx)
	}
}

func (w *WETHWorkload) step(ctx context.Context) {
	users := w.pool.Users()
	if len(users) < 2 {
		return
	}
	from := users[w.rng.Intn(len(users))]
	to := users[w.rng.Intn(len(users))]

	action := w.pickAction(from.Address)
	var data []byte
	var value *uint256.Int

	switch action {
	case wethDeposit:
		value = uint256.NewInt(uint64(w.rng.Int63n(1e14) + 1e12))
		data = contracts.EncodeWETHDeposit()
	case wethTransfer:
		amt := uint256.NewInt(uint64(w.rng.Int63n(1e11) + 1))
		data = contracts.EncodeWETHTransfer(to.Address, amt)
		value = uint256.NewInt(0)
	case wethWithdraw:
		amt := uint256.NewInt(uint64(w.rng.Int63n(1e11) + 1))
		data = contracts.EncodeWETHWithdraw(amt)
		value = uint256.NewInt(0)
	}

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
	wethAddr := w.weth
	start := time.Now()
	_, err = w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      100_000,
		To:       &wethAddr,
		Value:    value,
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

type wethAction int

const (
	wethDeposit wethAction = iota
	wethTransfer
	wethWithdraw
)

// pickAction weights deposits higher early on (so users have wrapped
// balances to transfer / withdraw later) and relaxes once the user has
// submitted a few deposits.
func (w *WETHWorkload) pickAction(addr types.Address) wethAction {
	val, _ := w.wrapped.LoadOrStore(addr, new(atomic.Uint64))
	counter := val.(*atomic.Uint64)
	deposits := counter.Load()
	if deposits < 3 {
		counter.Add(1)
		return wethDeposit
	}
	// Roll 0-99: 30 deposit, 60 transfer, 10 withdraw.
	r := w.rng.Intn(100)
	switch {
	case r < 30:
		return wethDeposit
	case r < 90:
		return wethTransfer
	default:
		return wethWithdraw
	}
}
