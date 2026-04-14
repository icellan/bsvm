package covenant

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// ErrUnknownTx is returned by FakeBroadcastClient.GetConfirmations when
// queried for a txid that has not been broadcast through this client.
var ErrUnknownTx = errors.New("unknown tx")

// ErrBroadcastRejected is returned by FakeBroadcastClient.BroadcastAdvance
// when the client is configured to reject broadcasts.
var ErrBroadcastRejected = errors.New("broadcast rejected")

// FakeBroadcastClient is an in-memory implementation of BroadcastClient
// for hermetic tests. It records every broadcast in an internal ledger
// and tracks per-txid confirmation counts that tests can drive directly.
type FakeBroadcastClient struct {
	mu sync.Mutex

	// RejectBroadcast, when true, causes BroadcastAdvance to return
	// ErrBroadcastRejected without recording the request.
	RejectBroadcast bool

	seq    uint64
	ledger []BroadcastRequest
	confs  map[types.Hash]uint32
}

// NewFakeBroadcastClient returns a ready-to-use fake broadcast client.
func NewFakeBroadcastClient() *FakeBroadcastClient {
	return &FakeBroadcastClient{
		confs: make(map[types.Hash]uint32),
	}
}

// BroadcastAdvance records the request and returns a synthetic deterministic
// txid derived from the request sequence number and block number.
func (f *FakeBroadcastClient) BroadcastAdvance(_ context.Context, req BroadcastRequest) (*BroadcastResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.RejectBroadcast {
		return nil, ErrBroadcastRejected
	}

	f.seq++
	txid := f.syntheticTxID(req, f.seq)

	f.ledger = append(f.ledger, req)
	f.confs[txid] = 0

	return &BroadcastResult{
		TxID:            txid,
		NewCovenantTxID: txid,
		NewCovenantVout: 0,
		NewCovenantSats: req.PrevSats,
		BroadcastAt:     time.Now(),
	}, nil
}

// GetConfirmations returns the recorded confirmation count or ErrUnknownTx.
func (f *FakeBroadcastClient) GetConfirmations(_ context.Context, txid types.Hash) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	n, ok := f.confs[txid]
	if !ok {
		return 0, ErrUnknownTx
	}
	return n, nil
}

// Close is a no-op for the fake.
func (f *FakeBroadcastClient) Close() error {
	return nil
}

// AdvanceConfirmations bumps every outstanding tx's confirmation count by n.
func (f *FakeBroadcastClient) AdvanceConfirmations(n uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for txid := range f.confs {
		f.confs[txid] += n
	}
}

// SetConfirmations sets the confirmation count for a specific txid. If the
// txid is not known, it is registered so subsequent GetConfirmations
// calls succeed.
func (f *FakeBroadcastClient) SetConfirmations(txid types.Hash, n uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confs[txid] = n
}

// Broadcasts returns a copy of all recorded broadcast requests.
func (f *FakeBroadcastClient) Broadcasts() []BroadcastRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]BroadcastRequest, len(f.ledger))
	copy(out, f.ledger)
	return out
}

// Outstanding returns the number of txids currently tracked by the client.
func (f *FakeBroadcastClient) Outstanding() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.confs)
}

// syntheticTxID returns a deterministic 32-byte txid derived from the
// request's block number, prev txid, mode discriminator, and the client-local
// sequence. Hashing in the mode makes the synthetic txid distinguishable
// across modes in tests that drive more than one mode through the same fake.
func (f *FakeBroadcastClient) syntheticTxID(req BroadcastRequest, seq uint64) types.Hash {
	var buf [65]byte
	copy(buf[0:32], req.PrevTxID[:])
	binary.LittleEndian.PutUint64(buf[32:40], req.NewState.BlockNumber)
	binary.LittleEndian.PutUint64(buf[40:48], seq)
	if req.Proof != nil {
		buf[48] = byte(req.Proof.Mode())
	}
	return types.BytesToHash(crypto.Keccak256(buf[:]))
}
