package sim

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/sim/contracts"
	"github.com/icellan/bsvm/pkg/sim/rpc"
	"github.com/icellan/bsvm/pkg/types"
)

// Deployments holds the addresses of the simulator's contract suite.
type Deployments struct {
	ERC20A   types.Address
	ERC20B   types.Address
	ERC721   types.Address
	WETH     types.Address
	AMM      types.Address
	Multisig types.Address
	Storage  types.Address
}

// Deploy sends creation transactions for the full contract set using the
// faucet and returns the resulting addresses. Deploys are done
// sequentially so CREATE-address computation stays predictable.
//
// Multisig owners defaults to the first 5 simulator users (or fewer
// if the pool is smaller); required = min(3, len(owners)).
func Deploy(ctx context.Context, pool *UserPool) (*Deployments, error) {
	mc := pool.MultiClient()
	if mc.Len() == 0 {
		return nil, errors.New("no nodes")
	}
	faucet := pool.Faucet()
	c := mc.ForWrite(faucet.ID)

	dep := &Deployments{}

	supply := new(uint256.Int).Lsh(uint256.NewInt(1), 64) // 2^64 of each token
	addr, err := deployAndWait(ctx, pool, c, contracts.EncodeERC20Deploy(supply))
	if err != nil {
		return nil, fmt.Errorf("deploy ERC20A: %w", err)
	}
	dep.ERC20A = addr

	addr, err = deployAndWait(ctx, pool, c, contracts.EncodeERC20Deploy(supply))
	if err != nil {
		return nil, fmt.Errorf("deploy ERC20B: %w", err)
	}
	dep.ERC20B = addr

	addr, err = deployAndWait(ctx, pool, c, contracts.EncodeERC721Deploy())
	if err != nil {
		return nil, fmt.Errorf("deploy ERC721: %w", err)
	}
	dep.ERC721 = addr

	addr, err = deployAndWait(ctx, pool, c, contracts.EncodeWETHDeploy())
	if err != nil {
		return nil, fmt.Errorf("deploy WETH: %w", err)
	}
	dep.WETH = addr

	addr, err = deployAndWait(ctx, pool, c, contracts.EncodeAMMDeploy(dep.ERC20A, dep.ERC20B))
	if err != nil {
		return nil, fmt.Errorf("deploy AMM: %w", err)
	}
	dep.AMM = addr

	addr, err = deployAndWait(ctx, pool, c, contracts.EncodeStorageDeploy())
	if err != nil {
		return nil, fmt.Errorf("deploy Storage: %w", err)
	}
	dep.Storage = addr

	owners := pickOwners(pool, 5)
	required := uint64(3)
	if uint64(len(owners)) < required {
		required = uint64(len(owners))
	}
	addr, err = deployAndWait(ctx, pool, c, contracts.EncodeMultisigDeploy(owners, required))
	if err != nil {
		return nil, fmt.Errorf("deploy Multisig: %w", err)
	}
	dep.Multisig = addr

	return dep, nil
}

func deployAndWait(ctx context.Context, pool *UserPool, _ any, code []byte) (types.Address, error) {
	faucet := pool.Faucet()
	faucet.mu.Lock()
	defer faucet.mu.Unlock()

	c := pool.faucetClient(ctx)

	var (
		nonce uint64
		hash  types.Hash
		err   error
	)
	for attempt := 0; attempt < 20; attempt++ {
		if faucet.nonce == 0 || faucet.dirty.Load() {
			n, nerr := c.Nonce(ctx, faucet.Address)
			if nerr != nil {
				return types.Address{}, fmt.Errorf("faucet nonce: %w", nerr)
			}
			faucet.nonce = n
			faucet.dirty.Store(false)
		}
		nonce = faucet.nonce

		gp, gerr := c.GasPrice(ctx)
		if gerr != nil || gp == nil || gp.Sign() == 0 {
			gp = big.NewInt(1)
		}

		tx := types.MustSignNewTx(faucet.Key, pool.Signer(), &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gp,
			Gas:      3_500_000,
			Data:     code,
			Value:    uint256.NewInt(0),
		})
		raw, encErr := encodeTx(tx)
		if encErr != nil {
			return types.Address{}, encErr
		}
		hash, err = c.SendRawTx(ctx, raw)
		if err == nil {
			faucet.nonce++
			break
		}
		if isSpeculativeDepthErr(err) {
			// Mempool is full — wait for a block to drain, then retry.
			select {
			case <-ctx.Done():
				return types.Address{}, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			faucet.dirty.Store(true)
			continue
		}
		faucet.dirty.Store(true)
		return types.Address{}, fmt.Errorf("submit: %w", err)
	}
	if err != nil {
		return types.Address{}, fmt.Errorf("submit (after retries): %w", err)
	}

	wctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// Poll on the submission node (the highest-height one) — it's the
	// most likely to include the tx soonest. Other nodes may be
	// syncing and give deadlines.
	receipt, rerr := c.WaitReceipt(wctx, hash, 250*time.Millisecond)
	if rerr != nil {
		return types.Address{}, fmt.Errorf("receipt: %w", rerr)
	}
	if receipt == nil {
		return types.Address{}, fmt.Errorf("receipt: no result")
	}
	_ = rpc.ErrNotFound // keep the import in use if future refactors drop it
	if receipt.Status != 1 {
		return types.Address{}, fmt.Errorf("deploy failed (status=0, nonce=%d)", nonce)
	}
	if receipt.ContractAddress != nil && *receipt.ContractAddress != (types.Address{}) {
		return *receipt.ContractAddress, nil
	}
	// Fallback: CREATE-address from sender + nonce.
	return types.Address(crypto.CreateAddress(faucet.Address, nonce)), nil
}

func isSpeculativeDepthErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "speculative depth") || contains(s, "mempool full") || contains(s, "known transaction")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	// Loop in place of strings.Contains to keep deploy.go's imports minimal.
	n := len(sub)
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return i
		}
	}
	return -1
}

func pickOwners(pool *UserPool, n int) []types.Address {
	users := pool.Users()
	if n > len(users) {
		n = len(users)
	}
	out := make([]types.Address, n)
	for i := 0; i < n; i++ {
		out[i] = users[i].Address
	}
	return out
}
