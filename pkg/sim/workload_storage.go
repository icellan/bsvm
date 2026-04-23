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

// StorageWorkload writes random (key, value) pairs into the Storage
// contract. Each tx claims a fresh slot, so it exercises MPT insertion.
type StorageWorkload struct {
	baseStats
	pool *UserPool
	reg  *Registry
	addr types.Address
	rng  *rand.Rand
}

func NewStorageWorkload(pool *UserPool, reg *Registry, storage types.Address, initialRate int) *StorageWorkload {
	w := &StorageWorkload{
		pool: pool,
		reg:  reg,
		addr: storage,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano() ^ 0x11)),
	}
	initBaseStats(&w.baseStats, KindStorageSet, initialRate, 32)
	return w
}

func (w *StorageWorkload) Kind() WorkloadKind { return KindStorageSet }
func (w *StorageWorkload) SetRate(tps int)    { w.rate.Store(int32(tps)) }
func (w *StorageWorkload) Stats() WorkloadStats { return w.baseStats.snapshot() }

func (w *StorageWorkload) Run(ctx context.Context) {
	for {
		if !waitTick(ctx, &w.baseStats) {
			return
		}
		w.step(ctx)
	}
}

func (w *StorageWorkload) step(ctx context.Context) {
	users := w.pool.Users()
	if len(users) == 0 {
		return
	}
	from := users[w.rng.Intn(len(users))]
	key := uint256.NewInt(uint64(w.rng.Int63()))
	value := uint256.NewInt(uint64(w.rng.Int63()))
	data := contracts.EncodeStorageSet(key, value)

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
	toAddr := w.addr
	start := time.Now()
	_, err = w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      70_000,
		To:       &toAddr,
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
