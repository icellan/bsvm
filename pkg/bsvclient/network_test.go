package bsvclient

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/whatsonchain"
)

type fakeARC struct {
	pingErr  error
	bcastErr error
	last     []byte
}

func (f *fakeARC) Broadcast(ctx context.Context, body []byte) (*arc.BroadcastResponse, error) {
	if f.bcastErr != nil {
		return nil, f.bcastErr
	}
	f.last = append([]byte(nil), body...)
	return &arc.BroadcastResponse{Status: arc.StatusSeenOnNetwork}, nil
}
func (f *fakeARC) Status(ctx context.Context, txid [32]byte) (*arc.TxStatus, error) {
	return &arc.TxStatus{TxID: txid, Status: arc.StatusUnknown}, nil
}
func (f *fakeARC) Ping(ctx context.Context) error { return f.pingErr }

type fakeWoC struct {
	tx  []byte
	err error
}

func (f *fakeWoC) GetTx(ctx context.Context, txid [32]byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tx, nil
}
func (f *fakeWoC) GetUTXOs(ctx context.Context, addr string) ([]whatsonchain.UTXO, error) {
	return nil, nil
}
func (f *fakeWoC) ChainInfo(ctx context.Context) (*whatsonchain.ChainInfo, error) { return nil, nil }
func (f *fakeWoC) Ping(ctx context.Context) error                                 { return nil }

func TestNetworkClientBroadcastFromARC(t *testing.T) {
	a := &fakeARC{}
	n := NewNetworkClient(NetworkConfig{ARC: a})
	resp, err := n.Broadcast(context.Background(), []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if resp.Status != arc.StatusSeenOnNetwork {
		t.Fatalf("status %s", resp.Status)
	}
	if len(a.last) != 2 {
		t.Fatalf("not forwarded")
	}
}

func TestNetworkClientBroadcastDisabled(t *testing.T) {
	n := NewNetworkClient(NetworkConfig{})
	_, err := n.Broadcast(context.Background(), nil)
	if !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("expected ErrProviderDisabled, got %v", err)
	}
}

func TestNetworkClientChainTip(t *testing.T) {
	ct := chaintracks.NewInMemoryClient()
	ct.PutHeader(&chaintracks.BlockHeader{Height: 99, Hash: [32]byte{0x01}, Work: big.NewInt(1)})
	n := NewNetworkClient(NetworkConfig{Chaintracks: ct})
	h, hash, err := n.ChainTip(context.Background())
	if err != nil {
		t.Fatalf("ChainTip: %v", err)
	}
	if h != 99 || hash[0] != 0x01 {
		t.Fatalf("bad tip %d %x", h, hash)
	}
}

func TestFetchAncestorFromWoC(t *testing.T) {
	n := NewNetworkClient(NetworkConfig{
		WhatsOnChain: &fakeWoC{tx: []byte{0x77, 0x88}},
	})
	var txid [32]byte
	raw, err := n.FetchAncestor(context.Background(), txid)
	if err != nil {
		t.Fatalf("FetchAncestor: %v", err)
	}
	if len(raw) != 2 || raw[0] != 0x77 {
		t.Fatalf("bad bytes")
	}
}

func TestFetchAncestorNotFound(t *testing.T) {
	n := NewNetworkClient(NetworkConfig{
		WhatsOnChain: &fakeWoC{err: whatsonchain.ErrNotFound},
		BEEFStore:    beef.NewMemoryStore(),
	})
	var txid [32]byte
	_, err := n.FetchAncestor(context.Background(), txid)
	if !errors.Is(err, ErrAncestorNotFound) {
		t.Fatalf("expected ErrAncestorNotFound, got %v", err)
	}
}

func TestHealthStatus(t *testing.T) {
	n := NewNetworkClient(NetworkConfig{
		ARC:         &fakeARC{},
		Chaintracks: chaintracks.NewInMemoryClient(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	h := n.HealthStatus(ctx)
	if !h.ARC.Reachable {
		t.Fatalf("arc unreachable")
	}
	if !h.Chaintracks.Reachable {
		t.Fatalf("chaintracks unreachable")
	}
}
