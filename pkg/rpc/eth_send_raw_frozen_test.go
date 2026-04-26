package rpc

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
)

// TestEthSendRawTransaction_FrozenShard exercises the JSON-RPC contract
// for a frozen shard:
//
//   - eth_sendRawTransaction must return a JSON-RPC error with code
//     -32000 ("server error") and a message containing "shard frozen".
//   - The transaction must NOT be enqueued in the batcher.
//
// We drive the freeze through the public covenant + overlay seam
// (CovenantManager.ApplyAdvance + GovernanceFreezeWatcher.SyncOnce) so
// the test exercises the same path a production node takes when a
// freeze advance lands on BSV.
func TestEthSendRawTransaction_FrozenShard(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	overlay.ClearGovernanceMonitor(ts.node)

	w := overlay.EnableGovernanceFreezeWatcher(ts.node, 0)
	if w == nil {
		t.Fatal("EnableGovernanceFreezeWatcher returned nil")
	}
	defer w.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	// Trigger a freeze advance on the covenant before any tx hits
	// the batcher. ValidateTransaction must still pass for this
	// nonce-0 tx so the test reaches the paused-batcher path; the
	// freeze does NOT block validation, only the batcher.Add call.
	cm := ts.node.CovenantManager()
	cur := cm.CurrentState()
	if err := cm.ApplyAdvance(types.Hash{1, 2, 3}, covenant.CovenantState{
		StateRoot:   cur.StateRoot,
		BlockNumber: cur.BlockNumber + 1,
		Frozen:      1,
	}); err != nil {
		t.Fatalf("ApplyAdvance(frozen) failed: %v", err)
	}
	w.SyncOnce()
	if !ts.node.Batcher().IsPaused() {
		t.Fatal("batcher should be paused after freeze")
	}

	// Build a valid transaction (nonce 0, sufficient balance) and
	// submit it through the dispatch path so the test exercises
	// handleEthSendRawTransaction — that's where the -32000 mapping
	// happens, not in the bare EthAPI helper.
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	hexTx := "0x" + hex.EncodeToString(encodeTx(t, tx))
	params, err := json.Marshal([]interface{}{hexTx})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	pendingBefore := ts.node.Batcher().PendingCount()
	result, err := ts.server.dispatch("eth_sendRawTransaction", params)
	if err == nil {
		t.Fatalf("expected error from frozen shard, got result %v", result)
	}
	rpcErr, ok := err.(*rpcError)
	if !ok {
		t.Fatalf("error %T %q is not *rpcError", err, err.Error())
	}
	if rpcErr.code != errCodeServerError {
		t.Fatalf("rpc error code = %d, want %d (-32000)", rpcErr.code, errCodeServerError)
	}
	if !strings.Contains(rpcErr.message, "shard frozen") {
		t.Fatalf("rpc error message = %q, want substring \"shard frozen\"", rpcErr.message)
	}

	// The frozen tx must not have entered the pending batch.
	if got := ts.node.Batcher().PendingCount(); got != pendingBefore {
		t.Fatalf("batcher PendingCount = %d, want unchanged %d (rejected tx leaked)", got, pendingBefore)
	}
}
