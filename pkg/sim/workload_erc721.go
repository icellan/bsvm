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

// ERC721Workload drives NFT mint + transfer. Mint targets the caller so
// we never need to track approval state across rounds.
type ERC721Workload struct {
	baseStats
	pool *UserPool
	reg  *Registry
	nft  types.Address
	rng  *rand.Rand
}

func NewERC721Workload(pool *UserPool, reg *Registry, nft types.Address, initialRate int) *ERC721Workload {
	w := &ERC721Workload{
		pool: pool,
		reg:  reg,
		nft:  nft,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano() ^ 0x42)),
	}
	initBaseStats(&w.baseStats, KindERC721Mint, initialRate, 32)
	return w
}

func (w *ERC721Workload) Kind() WorkloadKind { return KindERC721Mint }
func (w *ERC721Workload) SetRate(tps int)    { w.rate.Store(int32(tps)) }
func (w *ERC721Workload) Stats() WorkloadStats { return w.baseStats.snapshot() }

func (w *ERC721Workload) Run(ctx context.Context) {
	for {
		if !waitTick(ctx, &w.baseStats) {
			return
		}
		w.step(ctx)
	}
}

func (w *ERC721Workload) step(ctx context.Context) {
	users := w.pool.Users()
	if len(users) == 0 {
		return
	}
	from := users[w.rng.Intn(len(users))]
	data := contracts.EncodeERC721Mint(from.Address)

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
	to := w.nft
	start := time.Now()
	_, err = w.pool.SignAndSubmit(ctx, user, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      200_000,
		To:       &to,
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
