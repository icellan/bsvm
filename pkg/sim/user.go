package sim

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/shard"
	"github.com/icellan/bsvm/pkg/sim/rpc"
	"github.com/icellan/bsvm/pkg/types"
)

// User is one keypair driving traffic. All nonce access MUST go through
// UserPool.Borrow — User.nonce is intentionally unexported.
type User struct {
	ID      string
	Name    string
	Address types.Address
	Key     *ecdsa.PrivateKey

	mu    sync.Mutex
	nonce uint64
	dirty atomic.Bool
}

// MarkDirty flags the user's nonce for reconciliation on the next borrow.
func (u *User) MarkDirty() { u.dirty.Store(true) }

// UserPool owns the set of simulator users and serialises per-user
// nonce access. Borrow returns the locked user and a release closure.
type UserPool struct {
	chainID *big.Int
	mc      *rpc.MultiClient
	faucet  *User
	signer  types.Signer

	mu     sync.RWMutex
	users  map[string]*User
	order  []string
	nextID int
}

// NewUserPool seeds the pool from the Hardhat default accounts, reserving
// account #0 as the faucet (also the dev-key governance signer).
func NewUserPool(chainID uint64, mc *rpc.MultiClient) (*UserPool, error) {
	accts := shard.HardhatDefaultAccounts()
	if len(accts) < 2 {
		return nil, errors.New("hardhat accounts missing")
	}
	faucetKey, err := privFromHex(accts[0].PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("faucet key: %w", err)
	}
	p := &UserPool{
		chainID: new(big.Int).SetUint64(chainID),
		mc:      mc,
		signer:  types.LatestSignerForChainID(new(big.Int).SetUint64(chainID)),
		users:   make(map[string]*User),
	}
	p.faucet = &User{
		ID:      "faucet",
		Name:    "faucet",
		Address: accts[0].Address,
		Key:     faucetKey,
	}
	for _, a := range accts[1:] {
		k, err := privFromHex(a.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("seed user %s: %w", a.Address.Hex(), err)
		}
		p.addUserLocked(&User{
			ID:      p.allocID(),
			Name:    defaultUserName(p.nextID - 1),
			Address: a.Address,
			Key:     k,
		})
	}
	return p, nil
}

// Faucet returns the reserved account #0. Never borrow the faucet via
// Borrow — use FaucetSend to serialise faucet writes through the pool.
func (p *UserPool) Faucet() *User { return p.faucet }

// Signer is the tx signer bound to the pool's chain id.
func (p *UserPool) Signer() types.Signer { return p.signer }

// ChainID returns the pool's chain id.
func (p *UserPool) ChainID() *big.Int { return new(big.Int).Set(p.chainID) }

// Users returns a snapshot of the current user list in insertion order.
func (p *UserPool) Users() []*User {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*User, 0, len(p.order))
	for _, id := range p.order {
		out = append(out, p.users[id])
	}
	return out
}

// Count returns the number of active users (excluding the faucet).
func (p *UserPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.order)
}

// Get returns the user by ID or nil.
func (p *UserPool) Get(id string) *User {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.users[id]
}

// Borrow locks the user and returns their next nonce. The caller must
// always invoke release() — typically with defer. Passing consumed=false
// in release rolls the nonce back (use if the tx was never submitted).
// The user's nonce is reconciled from the node if dirty.
func (p *UserPool) Borrow(ctx context.Context, id string) (*User, uint64, func(consumed bool), error) {
	u := p.Get(id)
	if u == nil {
		return nil, 0, nil, fmt.Errorf("no user %q", id)
	}
	u.mu.Lock()
	if u.dirty.Load() {
		c := p.mc.ForWrite(u.ID)
		n, err := c.Nonce(ctx, u.Address)
		if err != nil {
			u.mu.Unlock()
			return nil, 0, nil, fmt.Errorf("reconcile nonce %s: %w", u.Address.Hex(), err)
		}
		u.nonce = n
		u.dirty.Store(false)
	}
	assigned := u.nonce
	u.nonce++
	release := func(consumed bool) {
		if !consumed {
			u.nonce--
		}
		u.mu.Unlock()
	}
	return u, assigned, release, nil
}

// AddUser generates a fresh keypair and funds it from the faucet.
func (p *UserPool) AddUser(ctx context.Context, fundWei *uint256.Int) (*User, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	addr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	u := &User{
		ID:      p.allocID(),
		Address: addr,
		Key:     key,
	}
	u.Name = defaultUserName(parseIDIndex(u.ID))
	if fundWei != nil && fundWei.Sign() > 0 {
		if _, err := p.FaucetSend(ctx, addr, fundWei); err != nil {
			return nil, fmt.Errorf("fund new user %s: %w", addr.Hex(), err)
		}
	}
	p.mu.Lock()
	p.addUserLocked(u)
	p.mu.Unlock()
	return u, nil
}

// RemoveUser removes a user. In-flight borrows complete first (the user's
// mutex serialises access). Residual balance is NOT swept here — callers
// wanting dust recovery should call SweepToFaucet explicitly.
func (p *UserPool) RemoveUser(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.users[id]; !ok {
		return false
	}
	delete(p.users, id)
	for i, o := range p.order {
		if o == id {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	return true
}

// FaucetCall submits a contract call from the faucet (to = contract,
// data = calldata, value = attached wBSV). Serialises on the faucet
// mutex so concurrent callers don't race on the faucet nonce.
func (p *UserPool) FaucetCall(ctx context.Context, to types.Address, value uint64, data []byte) (types.Hash, error) {
	return p.faucetTx(ctx, &to, uint256.NewInt(value), data, 300_000)
}

// FaucetSend submits a funding transfer from the faucet to `to`. It
// serialises on the faucet mutex so concurrent callers don't race on
// the faucet nonce.
func (p *UserPool) FaucetSend(ctx context.Context, to types.Address, amount *uint256.Int) (types.Hash, error) {
	p.faucet.mu.Lock()
	defer p.faucet.mu.Unlock()

	c := p.mc.ForWrite(p.faucet.ID)
	if p.faucet.nonce == 0 || p.faucet.dirty.Load() {
		n, err := c.Nonce(ctx, p.faucet.Address)
		if err != nil {
			return types.Hash{}, fmt.Errorf("faucet nonce: %w", err)
		}
		p.faucet.nonce = n
		p.faucet.dirty.Store(false)
	}
	nonce := p.faucet.nonce

	gp, err := c.GasPrice(ctx)
	if err != nil || gp == nil || gp.Sign() == 0 {
		gp = big.NewInt(1)
	}

	tx := types.MustSignNewTx(p.faucet.Key, p.signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      21000,
		To:       &to,
		Value:    amount,
	})
	raw, err := encodeTx(tx)
	if err != nil {
		return types.Hash{}, err
	}
	hash, err := c.SendRawTx(ctx, raw)
	if err != nil {
		p.faucet.dirty.Store(true)
		p.mc.RecordResult(c, err)
		return types.Hash{}, fmt.Errorf("faucet send: %w", err)
	}
	p.faucet.nonce++
	p.mc.RecordResult(c, nil)
	return hash, nil
}

// faucetClient picks the client with the highest observed block. In a
// devnet where prover nodes advance ahead of followers, this keeps
// faucet writes away from a lagging mempool (which mistakenly sees the
// faucet's nonce as 0 and fills its speculative depth cap).
func (p *UserPool) faucetClient(ctx context.Context) *rpc.Client {
	clients := p.mc.All()
	heights := make([]uint64, len(clients))
	for i, c := range clients {
		h, err := c.BlockNumber(ctx)
		if err == nil {
			heights[i] = h
		}
	}
	return p.mc.Highest(heights)
}

func (p *UserPool) faucetTx(ctx context.Context, to *types.Address, value *uint256.Int, data []byte, gas uint64) (types.Hash, error) {
	p.faucet.mu.Lock()
	defer p.faucet.mu.Unlock()

	c := p.faucetClient(ctx)
	if p.faucet.nonce == 0 || p.faucet.dirty.Load() {
		n, err := c.Nonce(ctx, p.faucet.Address)
		if err != nil {
			return types.Hash{}, fmt.Errorf("faucet nonce: %w", err)
		}
		p.faucet.nonce = n
		p.faucet.dirty.Store(false)
	}
	nonce := p.faucet.nonce

	gp, err := c.GasPrice(ctx)
	if err != nil || gp == nil || gp.Sign() == 0 {
		gp = big.NewInt(1)
	}

	tx := types.MustSignNewTx(p.faucet.Key, p.signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gp,
		Gas:      gas,
		To:       to,
		Value:    value,
		Data:     data,
	})
	raw, err := encodeTx(tx)
	if err != nil {
		return types.Hash{}, err
	}
	hash, err := c.SendRawTx(ctx, raw)
	if err != nil {
		p.faucet.dirty.Store(true)
		p.mc.RecordResult(c, err)
		return types.Hash{}, fmt.Errorf("faucet tx: %w", err)
	}
	p.faucet.nonce++
	p.mc.RecordResult(c, nil)
	return hash, nil
}

// SignAndSubmit signs txData on behalf of `user` using the supplied
// nonce and submits to the user's sticky node. On submission failure,
// the user is marked dirty so the next Borrow refetches nonce.
func (p *UserPool) SignAndSubmit(ctx context.Context, user *User, txData types.TxData) (types.Hash, error) {
	c := p.mc.ForWrite(user.ID)
	tx, err := types.SignNewTx(user.Key, p.signer, txData)
	if err != nil {
		return types.Hash{}, fmt.Errorf("sign: %w", err)
	}
	raw, err := encodeTx(tx)
	if err != nil {
		return types.Hash{}, err
	}
	hash, err := c.SendRawTx(ctx, raw)
	if err != nil {
		user.dirty.Store(true)
		p.mc.RecordResult(c, err)
		return types.Hash{}, err
	}
	p.mc.RecordResult(c, nil)
	return hash, nil
}

// MultiClient exposes the underlying multi-node client.
func (p *UserPool) MultiClient() *rpc.MultiClient { return p.mc }

func (p *UserPool) addUserLocked(u *User) {
	p.users[u.ID] = u
	p.order = append(p.order, u.ID)
}

func (p *UserPool) allocID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := fmt.Sprintf("u%d", p.nextID)
	p.nextID++
	return id
}

func parseIDIndex(id string) int {
	if len(id) < 2 {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(id[1:], "%d", &n)
	return n
}

func defaultUserName(idx int) string {
	names := []string{"alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "ivan", "judy"}
	if idx >= 0 && idx < len(names) {
		return names[idx]
	}
	return fmt.Sprintf("user-%d", idx)
}

func privFromHex(s string) (*ecdsa.PrivateKey, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return crypto.ToECDSA(raw)
}

func encodeTx(tx *types.Transaction) (string, error) {
	buf := &rlpBuf{}
	if err := tx.EncodeRLP(buf); err != nil {
		return "", fmt.Errorf("encode tx: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

type rlpBuf struct{ b []byte }

func (w *rlpBuf) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *rlpBuf) Bytes() []byte               { return w.b }

// EncodeArgs rlp-encodes arbitrary args — reserved for future use by
// workload helpers that need to pack structured payloads.
func EncodeArgs(args ...any) ([]byte, error) {
	var buf rlpBuf
	for _, a := range args {
		if err := rlp.Encode(&buf, a); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
