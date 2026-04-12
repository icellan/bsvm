package rpc

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/event"
	"github.com/icellan/bsvm/pkg/types"
)

// wsTestSetup holds a running test server with WebSocket support.
type wsTestSetup struct {
	ts        *testSetup
	server    *httptest.Server
	wsManager *WSManager
	wsURL     string
}

// newWSTestSetup creates a test setup with an httptest server configured for
// WebSocket. The test server listens on a random port and the wsURL is the
// WebSocket endpoint.
func newWSTestSetup(t *testing.T) *wsTestSetup {
	t.Helper()
	ts := newTestSetup(t)

	wsm := NewWSManager(ts.server, ts.node.EventFeed())
	wsm.Start()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsm.HandleWebSocket)
	mux.HandleFunc("/", ts.server.handleHTTP)

	httpServer := httptest.NewServer(mux)

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws"

	return &wsTestSetup{
		ts:        ts,
		server:    httpServer,
		wsManager: wsm,
		wsURL:     wsURL,
	}
}

// close shuts down the test server.
func (wts *wsTestSetup) close() {
	wts.wsManager.Stop()
	wts.server.Close()
}

// dial creates a WebSocket connection to the test server.
func (wts *wsTestSetup) dial(t *testing.T) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wts.wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	return conn
}

// sendJSON writes a JSON message to the WebSocket connection.
func sendJSON(t *testing.T, conn *websocket.Conn, v interface{}) {
	t.Helper()
	if err := conn.WriteJSON(v); err != nil {
		t.Fatalf("failed to send json: %v", err)
	}
}

// readJSON reads a JSON message from the WebSocket connection with a timeout.
func readJSON(t *testing.T, conn *websocket.Conn, v interface{}) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}
	if err := json.Unmarshal(msg, v); err != nil {
		t.Fatalf("failed to unmarshal message: %v (raw: %s)", err, string(msg))
	}
}

// TestWSManager_SubscribeNewHeads verifies that subscribing to newHeads
// results in receiving a notification when a new block is processed.
func TestWSManager_SubscribeNewHeads(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	// Subscribe to newHeads.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []string{"newHeads"},
	})

	// Read subscription response.
	var subResp wsResponse
	readJSON(t, conn, &subResp)

	if subResp.Error != nil {
		t.Fatalf("unexpected error: %v", subResp.Error.Message)
	}
	subID, ok := subResp.Result.(string)
	if !ok {
		t.Fatalf("expected string subscription id, got %T", subResp.Result)
	}
	if !strings.HasPrefix(subID, "0x") {
		t.Fatalf("expected hex subscription id, got %q", subID)
	}

	// Process a transaction to trigger a new head event.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := wts.ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := wts.ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Read the notification.
	var notification struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Subscription string                 `json:"subscription"`
			Result       map[string]interface{} `json:"result"`
		} `json:"params"`
	}
	readJSON(t, conn, &notification)

	if notification.Method != "eth_subscription" {
		t.Errorf("expected method eth_subscription, got %q", notification.Method)
	}
	if notification.Params.Subscription != subID {
		t.Errorf("expected subscription id %q, got %q", subID, notification.Params.Subscription)
	}

	// Verify the result contains expected header fields.
	result := notification.Params.Result
	if result["number"] == nil {
		t.Error("expected number in header result")
	}
	if result["hash"] == nil {
		t.Error("expected hash in header result")
	}
	if result["stateRoot"] == nil {
		t.Error("expected stateRoot in header result")
	}
	if result["parentHash"] == nil {
		t.Error("expected parentHash in header result")
	}
	if result["gasUsed"] == nil {
		t.Error("expected gasUsed in header result")
	}
	if result["timestamp"] == nil {
		t.Error("expected timestamp in header result")
	}
}

// TestWSManager_SubscribeLogs verifies that subscribing to logs with an
// address filter only delivers matching logs.
func TestWSManager_SubscribeLogs(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	// Subscribe to logs with no filter (all logs).
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []interface{}{"logs", map[string]interface{}{}},
	})

	var subResp wsResponse
	readJSON(t, conn, &subResp)

	if subResp.Error != nil {
		t.Fatalf("unexpected error: %v", subResp.Error.Message)
	}
	subID, ok := subResp.Result.(string)
	if !ok {
		t.Fatalf("expected string subscription id, got %T", subResp.Result)
	}

	// Directly notify some test logs.
	testAddr := types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	testLogs := []*types.Log{
		{
			Address:     testAddr,
			Topics:      []types.Hash{types.HexToHash("0x1111")},
			Data:        []byte{0x01, 0x02},
			BlockNumber: 1,
			TxHash:      types.HexToHash("0xaabb"),
			BlockHash:   types.HexToHash("0xccdd"),
		},
	}
	wts.wsManager.NotifyLogs(testLogs)

	// Read the notification.
	var notification struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Subscription string     `json:"subscription"`
			Result       *logResult `json:"result"`
		} `json:"params"`
	}
	readJSON(t, conn, &notification)

	if notification.Method != "eth_subscription" {
		t.Errorf("expected method eth_subscription, got %q", notification.Method)
	}
	if notification.Params.Subscription != subID {
		t.Errorf("expected subscription %q, got %q", subID, notification.Params.Subscription)
	}
	if notification.Params.Result == nil {
		t.Fatal("expected log result, got nil")
	}
}

// TestWSManager_LogsAddressFilter verifies that log subscriptions with an
// address filter only receive logs from the matching address.
func TestWSManager_LogsAddressFilter(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	matchAddr := types.HexToAddress("0x1111111111111111111111111111111111111111")

	// Subscribe to logs only from matchAddr.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []interface{}{"logs", map[string]interface{}{"address": matchAddr.Hex()}},
	})

	var subResp wsResponse
	readJSON(t, conn, &subResp)
	if subResp.Error != nil {
		t.Fatalf("unexpected error: %v", subResp.Error.Message)
	}

	// Send a log that does NOT match.
	otherAddr := types.HexToAddress("0x2222222222222222222222222222222222222222")
	wts.wsManager.NotifyLogs([]*types.Log{
		{Address: otherAddr, BlockNumber: 1},
	})

	// Send a log that DOES match.
	wts.wsManager.NotifyLogs([]*types.Log{
		{Address: matchAddr, BlockNumber: 2, Topics: []types.Hash{types.HexToHash("0xabcd")}},
	})

	// We should only receive the matching log.
	var notification struct {
		Params struct {
			Result *logResult `json:"result"`
		} `json:"params"`
	}
	readJSON(t, conn, &notification)

	if notification.Params.Result == nil {
		t.Fatal("expected log result")
	}
	// The block number should be 2 (the matching log), not 1 (the non-matching log).
	if notification.Params.Result.BlockNumber != EncodeUint64(2) {
		t.Errorf("expected block number %s, got %s", EncodeUint64(2), notification.Params.Result.BlockNumber)
	}
}

// TestWSManager_Unsubscribe verifies that after unsubscribing, no further
// notifications are received.
func TestWSManager_Unsubscribe(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	// Subscribe.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []string{"newHeads"},
	})

	var subResp wsResponse
	readJSON(t, conn, &subResp)
	subID := subResp.Result.(string)

	// Unsubscribe.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "eth_unsubscribe",
		"params":  []string{subID},
	})

	var unsubResp wsResponse
	readJSON(t, conn, &unsubResp)

	if unsubResp.Error != nil {
		t.Fatalf("unexpected error: %v", unsubResp.Error.Message)
	}
	result, ok := unsubResp.Result.(bool)
	if !ok || !result {
		t.Fatalf("expected unsubscribe to return true, got %v", unsubResp.Result)
	}

	// Now create a block — we should NOT receive a notification.
	// We test this by setting a short read deadline; if we receive anything
	// it's a failure.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := wts.ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	wts.ts.node.ProcessBatch([]*types.Transaction{tx})

	// Give a small window for any notification to arrive.
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Error("expected no message after unsubscribe, but received one")
	}
}

// TestWSManager_MultipleSubscriptions verifies that multiple clients can
// subscribe and all receive notifications.
func TestWSManager_MultipleSubscriptions(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn1 := wts.dial(t)
	defer conn1.Close()
	conn2 := wts.dial(t)
	defer conn2.Close()

	// Both subscribe to newHeads.
	for i, conn := range []*websocket.Conn{conn1, conn2} {
		sendJSON(t, conn, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      i + 1,
			"method":  "eth_subscribe",
			"params":  []string{"newHeads"},
		})
		var resp wsResponse
		readJSON(t, conn, &resp)
		if resp.Error != nil {
			t.Fatalf("conn%d: unexpected error: %v", i+1, resp.Error.Message)
		}
	}

	// Process a transaction.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := wts.ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := wts.ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Both connections should receive a notification.
	for i, conn := range []*websocket.Conn{conn1, conn2} {
		var notification struct {
			Method string `json:"method"`
		}
		readJSON(t, conn, &notification)
		if notification.Method != "eth_subscription" {
			t.Errorf("conn%d: expected eth_subscription, got %q", i+1, notification.Method)
		}
	}
}

// TestWSManager_InvalidSubscriptionType verifies that subscribing to an
// unknown type returns an error.
func TestWSManager_InvalidSubscriptionType(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []string{"nonExistentType"},
	})

	var resp wsResponse
	readJSON(t, conn, &resp)

	if resp.Error == nil {
		t.Fatal("expected error for unsupported subscription type")
	}
	if !strings.Contains(resp.Error.Message, "unsupported subscription type") {
		t.Errorf("expected unsupported subscription type error, got %q", resp.Error.Message)
	}
}

// TestWSManager_InvalidMethod verifies that sending an unknown method over
// WebSocket returns a method not found error.
func TestWSManager_InvalidMethod(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_nonExistentMethod",
		"params":  []interface{}{},
	})

	var resp wsResponse
	readJSON(t, conn, &resp)

	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != errCodeMethodNotFound {
		t.Errorf("expected error code %d, got %d", errCodeMethodNotFound, resp.Error.Code)
	}
}

// TestWSManager_RegularRPCOverWS verifies that regular JSON-RPC methods
// work over WebSocket (e.g., eth_blockNumber).
func TestWSManager_RegularRPCOverWS(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_blockNumber",
		"params":  []interface{}{},
	})

	var resp wsResponse
	readJSON(t, conn, &resp)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error.Message)
	}
	result, ok := resp.Result.(string)
	if !ok {
		t.Fatalf("expected string result, got %T", resp.Result)
	}
	if result != "0x0" {
		t.Errorf("expected block number 0x0, got %q", result)
	}
}

// TestWSManager_NotifyNewHeadDirect tests the NotifyNewHead method directly
// without going through the event feed.
func TestWSManager_NotifyNewHeadDirect(t *testing.T) {
	feed := &event.Feed{}
	wsm := NewWSManager(nil, feed)

	// Create a test block.
	header := &block.L2Header{
		Number:    big.NewInt(42),
		GasLimit:  30_000_000,
		Timestamp: 1234567890,
		BaseFee:   big.NewInt(0),
	}
	blk := block.NewBlockWithHeader(header)

	result := formatBlockHeader(blk)

	if result["number"] != EncodeUint64(42) {
		t.Errorf("expected number 0x2a, got %v", result["number"])
	}
	if result["gasLimit"] != EncodeUint64(30_000_000) {
		t.Errorf("expected gasLimit, got %v", result["gasLimit"])
	}
	if result["timestamp"] != EncodeUint64(1234567890) {
		t.Errorf("expected timestamp, got %v", result["timestamp"])
	}

	// Ensure no panic when calling NotifyNewHead with no subscribers.
	wsm.NotifyNewHead(blk)
	wsm.NotifyNewHead(nil)
	wsm.Stop()
}

// TestWSManager_MaxSubsPerConn verifies that the per-connection subscription
// limit is enforced.
func TestWSManager_MaxSubsPerConn(t *testing.T) {
	ts := newTestSetup(t)
	feed := ts.node.EventFeed()

	// Create a WSManager with a very low subscription limit.
	wsm := NewWSManagerWithLimits(ts.server, feed, 1000, 3, 1000, 30*time.Second)
	wsm.Start()
	defer wsm.Stop()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsm.HandleWebSocket)
	mux.HandleFunc("/", ts.server.handleHTTP)

	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer conn.Close()

	// Subscribe 3 times (should succeed).
	for i := 0; i < 3; i++ {
		sendJSON(t, conn, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      i + 1,
			"method":  "eth_subscribe",
			"params":  []string{"newHeads"},
		})
		var resp wsResponse
		readJSON(t, conn, &resp)
		if resp.Error != nil {
			t.Fatalf("subscription %d: unexpected error: %v", i+1, resp.Error.Message)
		}
	}

	// Fourth subscription should fail.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "eth_subscribe",
		"params":  []string{"newHeads"},
	})
	var resp wsResponse
	readJSON(t, conn, &resp)
	if resp.Error == nil {
		t.Fatal("expected error when exceeding subscription limit")
	}
	if !strings.Contains(resp.Error.Message, "max subscriptions per connection reached") {
		t.Errorf("unexpected error message: %s", resp.Error.Message)
	}
}

// TestWSManager_ConnectionLimit verifies that the global connection limit is
// enforced.
func TestWSManager_ConnectionLimit(t *testing.T) {
	ts := newTestSetup(t)
	feed := ts.node.EventFeed()

	// Create a WSManager with a very low connection limit.
	wsm := NewWSManagerWithLimits(ts.server, feed, 2, 100, 1000, 30*time.Second)
	wsm.Start()
	defer wsm.Stop()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsm.HandleWebSocket)

	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws"

	// First two connections should succeed.
	conn1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("conn1: failed to dial: %v", err)
	}
	defer conn1.Close()

	conn2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("conn2: failed to dial: %v", err)
	}
	defer conn2.Close()

	// Third connection should be rejected.
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected third connection to be rejected")
	}
	// The server should return 503 Service Unavailable.
	if resp != nil && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", resp.StatusCode)
	}
}

// TestWSManager_BSVConfirmationSubscribe verifies that subscribing to
// bsvConfirmation returns a valid subscription ID.
func TestWSManager_BSVConfirmationSubscribe(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	// Subscribe to bsvConfirmation.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []string{"bsvConfirmation"},
	})

	var subResp wsResponse
	readJSON(t, conn, &subResp)

	if subResp.Error != nil {
		t.Fatalf("unexpected error: %v", subResp.Error.Message)
	}
	subID, ok := subResp.Result.(string)
	if !ok {
		t.Fatalf("expected string subscription id, got %T", subResp.Result)
	}
	if !strings.HasPrefix(subID, "0x") {
		t.Fatalf("expected hex subscription id, got %q", subID)
	}
}

// TestWSManager_BSVConfirmationNotification verifies that bsvConfirmation
// subscribers receive notifications when NotifyBSVConfirmation is called.
func TestWSManager_BSVConfirmationNotification(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	// Subscribe to bsvConfirmation.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []string{"bsvConfirmation"},
	})

	var subResp wsResponse
	readJSON(t, conn, &subResp)
	if subResp.Error != nil {
		t.Fatalf("unexpected error: %v", subResp.Error.Message)
	}
	subID := subResp.Result.(string)

	// Send a confirmation event.
	evt := BSVConfirmationEvent{
		L2BlockNumber: "0x1",
		BSVTxID:       "0xdeadbeef",
		Confirmations: 3,
		Status:        "confirmed",
	}
	wts.wsManager.NotifyBSVConfirmation(evt)

	// Read the notification.
	var notification struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Subscription string               `json:"subscription"`
			Result       BSVConfirmationEvent `json:"result"`
		} `json:"params"`
	}
	readJSON(t, conn, &notification)

	if notification.Method != "eth_subscription" {
		t.Errorf("expected method eth_subscription, got %q", notification.Method)
	}
	if notification.Params.Subscription != subID {
		t.Errorf("expected subscription %q, got %q", subID, notification.Params.Subscription)
	}
	if notification.Params.Result.L2BlockNumber != "0x1" {
		t.Errorf("expected L2BlockNumber 0x1, got %s", notification.Params.Result.L2BlockNumber)
	}
	if notification.Params.Result.Confirmations != 3 {
		t.Errorf("expected 3 confirmations, got %d", notification.Params.Result.Confirmations)
	}
	if notification.Params.Result.Status != "confirmed" {
		t.Errorf("expected status confirmed, got %s", notification.Params.Result.Status)
	}
}

// TestWSManager_BSVConfirmationUnsubscribe verifies that unsubscribing from
// bsvConfirmation works correctly.
func TestWSManager_BSVConfirmationUnsubscribe(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	// Subscribe.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []string{"bsvConfirmation"},
	})

	var subResp wsResponse
	readJSON(t, conn, &subResp)
	subID := subResp.Result.(string)

	// Unsubscribe.
	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "eth_unsubscribe",
		"params":  []string{subID},
	})

	var unsubResp wsResponse
	readJSON(t, conn, &unsubResp)

	if unsubResp.Error != nil {
		t.Fatalf("unexpected error: %v", unsubResp.Error.Message)
	}
	result, ok := unsubResp.Result.(bool)
	if !ok || !result {
		t.Fatalf("expected unsubscribe to return true, got %v", unsubResp.Result)
	}

	// Send a confirmation event. Since we've unsubscribed, we should NOT
	// receive it.
	wts.wsManager.NotifyBSVConfirmation(BSVConfirmationEvent{
		L2BlockNumber: "0x1",
		BSVTxID:       "0xdeadbeef",
		Confirmations: 1,
		Status:        "confirmed",
	})

	// Wait briefly for any notification. We should get none.
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Error("expected no message after unsubscribe, but received one")
	}
}

// TestWSManager_MatchesLogSubscription tests the log matching logic.
func TestWSManager_MatchesLogSubscription(t *testing.T) {
	addr1 := types.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := types.HexToAddress("0x2222222222222222222222222222222222222222")
	topic1 := types.HexToHash("0xaaaa")
	topic2 := types.HexToHash("0xbbbb")

	log := &types.Log{
		Address: addr1,
		Topics:  []types.Hash{topic1},
	}

	tests := []struct {
		name   string
		filter *FilterQuery
		match  bool
	}{
		{"nil filter matches all", nil, true},
		{"empty filter matches all", &FilterQuery{}, true},
		{"matching address", &FilterQuery{Addresses: []types.Address{addr1}}, true},
		{"non-matching address", &FilterQuery{Addresses: []types.Address{addr2}}, false},
		{"matching topic", &FilterQuery{Topics: [][]types.Hash{{topic1}}}, true},
		{"non-matching topic", &FilterQuery{Topics: [][]types.Hash{{topic2}}}, false},
		{"address + topic match", &FilterQuery{Addresses: []types.Address{addr1}, Topics: [][]types.Hash{{topic1}}}, true},
		{"address match topic mismatch", &FilterQuery{Addresses: []types.Address{addr1}, Topics: [][]types.Hash{{topic2}}}, false},
		{"wildcard topic", &FilterQuery{Topics: [][]types.Hash{{}}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesLogSubscription(log, tc.filter)
			if got != tc.match {
				t.Errorf("matchesLogSubscription() = %v, want %v", got, tc.match)
			}
		})
	}
}
