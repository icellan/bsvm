package sim

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/sim/rpc"
)

// TestDeploy_AgainstDevnet exercises the full contract suite against a
// live devnet. It is skipped unless BSVM_SIM_TEST_NODES is set so the
// regular `go test` run stays hermetic.
//
// Run with: BSVM_SIM_TEST_NODES=http://localhost:8545,http://localhost:8546 \
//           go test -run TestDeploy_AgainstDevnet -count=1 ./pkg/sim
func TestDeploy_AgainstDevnet(t *testing.T) {
	raw := os.Getenv("BSVM_SIM_TEST_NODES")
	if raw == "" {
		t.Skip("BSVM_SIM_TEST_NODES not set")
	}
	urls := strings.Split(raw, ",")
	for i, u := range urls {
		urls[i] = strings.TrimSpace(u)
	}
	mc := rpc.NewMultiClient(urls)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	chainID, err := mc.At(0).ChainID(ctx)
	if err != nil {
		t.Fatalf("chain id: %v", err)
	}
	pool, err := NewUserPool(chainID, mc)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}

	dep, err := Deploy(ctx, pool)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	for name, a := range map[string][20]byte{
		"ERC20A":   [20]byte(dep.ERC20A),
		"ERC20B":   [20]byte(dep.ERC20B),
		"ERC721":   [20]byte(dep.ERC721),
		"WETH":     [20]byte(dep.WETH),
		"AMM":      [20]byte(dep.AMM),
		"Multisig": [20]byte(dep.Multisig),
		"Storage":  [20]byte(dep.Storage),
	} {
		if isZero(a[:]) {
			t.Errorf("%s deployed at zero address", name)
		} else {
			t.Logf("%s deployed at 0x%s", name, hex.EncodeToString(a[:]))
		}
	}
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
