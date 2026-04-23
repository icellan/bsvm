package sim

import (
	"context"
	"math/big"
	"math/rand"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

// TransferWorkload drives plain native-value transfers between random
// user pairs. No contract involved.
type TransferWorkload struct {
	baseStats
	pool *UserPool
	reg  *Registry
	rng  *rand.Rand
}

func NewTransferWorkload(pool *UserPool, reg *Registry, initialRate int) *TransferWorkload {
	w := &TransferWorkload{
		pool: pool,
		reg:  reg,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	initBaseStats(&w.baseStats, KindValueTransfer, initialRate, 32)
	return w
}

func (w *TransferWorkload) Kind() WorkloadKind { return KindValueTransfer }
func (w *TransferWorkload) SetRate(tps int)    { w.rate.Store(int32(tps)) }
func (w *TransferWorkload) Stats() WorkloadStats {
	s := w.baseStats.snapshot()
	return s
}

func (w *TransferWorkload) Run(ctx context.Context) {
	for {
		if !waitTick(ctx, &w.baseStats) {
			return
		}
		w.step(ctx)
	}
}

func (w *TransferWorkload) step(ctx context.Context) {
	users := w.pool.Users()
	if len(users) < 2 {
		return
	}
	from := users[w.rng.Intn(len(users))]
	to := users[w.rng.Intn(len(users))]
	for to.ID == from.ID {
		to = users[w.rng.Intn(len(users))]
	}
	amount := uint256.NewInt(uint64(w.rng.Int63n(int64(1e15)) + 1))

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
	toAddr := to.Address
	start := time.Now()
	hash, err := w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      21000,
		To:       &toAddr,
		Value:    amount,
	})
	if err != nil {
		release(false)
		w.recordFailure(err)
		w.reg.notify(w.Stats())
		return
	}
	release(true)
	_ = hash

	// Success is "submitted cleanly" — receipt confirmation happens
	// asynchronously; polling on every tx would bottleneck throughput.
	w.recordSuccess(time.Since(start))
	w.reg.notify(w.Stats())
}
