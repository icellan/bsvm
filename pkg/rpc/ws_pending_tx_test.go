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

	"github.com/icellan/bsvm/pkg/event"
	"github.com/icellan/bsvm/pkg/types"
)

// newTestWSConn creates a wsConn with a buffered event channel for testing.
// It creates a real websocket connection pair so that Close works correctly.
func newTestWSConn(t *testing.T, manager *WSManager) *wsConn {
	t.Helper()
	// Create a minimal websocket server/client pair so conn.Close() works.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Hold the connection open until the server shuts down.
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial test websocket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &wsConn{
		conn:    conn,
		subs:    make(map[string]*WSSubscription),
		done:    make(chan struct{}),
		eventCh: make(chan interface{}, 100),
		manager: manager,
	}
}

// readEvent reads a single event from the wsConn's event channel with a timeout.
func readEvent(t *testing.T, wc *wsConn) interface{} {
	t.Helper()
	select {
	case evt := <-wc.eventCh:
		return evt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
		return nil
	}
}

// newTestPendingTx creates a simple legacy transaction for testing.
func newTestPendingTx() *types.Transaction {
	to := types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	return types.NewTx(&types.LegacyTx{
		Nonce:    7,
		GasPrice: big.NewInt(1000000000),
		Gas:      21000,
		To:       &to,
		Value:    uint256.NewInt(1000000),
		Data:     nil,
		V:        big.NewInt(27),
		R:        big.NewInt(1),
		S:        big.NewInt(2),
	})
}

// TestWSNewPendingTransactionsSubscription verifies that subscribing to
// newPendingTransactions returns a valid subscription ID.
func TestWSNewPendingTransactionsSubscription(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []string{"newPendingTransactions"},
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
	if subID == "" {
		t.Fatal("expected non-empty subscription id")
	}
}

// TestWSNewPendingTransactionsNotify verifies that subscribing to
// newPendingTransactions and calling NotifyPendingTransaction sends
// a notification with the transaction hash.
func TestWSNewPendingTransactionsNotify(t *testing.T) {
	feed := &event.Feed{}
	wm := NewWSManager(nil, feed)

	wc := newTestWSConn(t, wm)
	wm.mu.Lock()
	wm.conns[wc] = struct{}{}
	wm.mu.Unlock()

	// Subscribe to newPendingTransactions (hash-only).
	subID := wm.allocateID()
	wc.subs[subID] = &WSSubscription{
		id:      subID,
		subType: "newPendingTransactions",
		fullTx:  false,
	}

	tx := newTestPendingTx()
	wm.NotifyPendingTransaction(tx)

	evt := readEvent(t, wc)
	notification, ok := evt.(*wsNotification)
	if !ok {
		t.Fatalf("expected *wsNotification, got %T", evt)
	}
	if notification.Method != "eth_subscription" {
		t.Errorf("expected method eth_subscription, got %q", notification.Method)
	}

	params, ok := notification.Params.(subscriptionParams)
	if !ok {
		t.Fatalf("expected subscriptionParams, got %T", notification.Params)
	}
	if params.Subscription != subID {
		t.Errorf("expected subscription %q, got %q", subID, params.Subscription)
	}

	// Result should be just the tx hash string.
	hashStr, ok := params.Result.(string)
	if !ok {
		t.Fatalf("expected string result (tx hash), got %T", params.Result)
	}
	expectedHash := tx.Hash().Hex()
	if hashStr != expectedHash {
		t.Errorf("expected tx hash %q, got %q", expectedHash, hashStr)
	}

	wm.Stop()
}

// TestWSNewPendingTransactionsFullTx verifies that subscribing with
// includeTransactions:true sends the full transaction object.
func TestWSNewPendingTransactionsFullTx(t *testing.T) {
	feed := &event.Feed{}
	wm := NewWSManager(nil, feed)

	wc := newTestWSConn(t, wm)
	wm.mu.Lock()
	wm.conns[wc] = struct{}{}
	wm.mu.Unlock()

	// Subscribe with fullTx=true.
	subID := wm.allocateID()
	wc.subs[subID] = &WSSubscription{
		id:      subID,
		subType: "newPendingTransactions",
		fullTx:  true,
	}

	tx := newTestPendingTx()
	wm.NotifyPendingTransaction(tx)

	evt := readEvent(t, wc)
	notification, ok := evt.(*wsNotification)
	if !ok {
		t.Fatalf("expected *wsNotification, got %T", evt)
	}

	params, ok := notification.Params.(subscriptionParams)
	if !ok {
		t.Fatalf("expected subscriptionParams, got %T", notification.Params)
	}

	// Result should be a map with tx fields.
	txObj, ok := params.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result (full tx), got %T", params.Result)
	}

	// Verify expected fields.
	expectedHash := tx.Hash().Hex()
	if txObj["hash"] != expectedHash {
		t.Errorf("expected hash %q, got %v", expectedHash, txObj["hash"])
	}
	if txObj["nonce"] != EncodeUint64(7) {
		t.Errorf("expected nonce %q, got %v", EncodeUint64(7), txObj["nonce"])
	}
	if txObj["gas"] != EncodeUint64(21000) {
		t.Errorf("expected gas %q, got %v", EncodeUint64(21000), txObj["gas"])
	}
	if txObj["to"] != tx.To().Hex() {
		t.Errorf("expected to %q, got %v", tx.To().Hex(), txObj["to"])
	}
	if txObj["value"] != EncodeBig(tx.Value().ToBig()) {
		t.Errorf("expected value %q, got %v", EncodeBig(tx.Value().ToBig()), txObj["value"])
	}
	if txObj["gasPrice"] != EncodeBig(tx.GasPrice()) {
		t.Errorf("expected gasPrice %q, got %v", EncodeBig(tx.GasPrice()), txObj["gasPrice"])
	}
	if txObj["type"] != EncodeUint64(0) {
		t.Errorf("expected type %q, got %v", EncodeUint64(0), txObj["type"])
	}

	wm.Stop()
}

// TestWSNewPendingTransactionsFullTxViaSubscribe verifies that passing
// includeTransactions:true in the subscribe params sets fullTx correctly.
func TestWSNewPendingTransactionsFullTxViaSubscribe(t *testing.T) {
	wts := newWSTestSetup(t)
	defer wts.close()

	conn := wts.dial(t)
	defer conn.Close()

	sendJSON(t, conn, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_subscribe",
		"params":  []interface{}{"newPendingTransactions", map[string]interface{}{"includeTransactions": true}},
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

	// Notify a pending transaction.
	tx := newTestPendingTx()
	wts.wsManager.NotifyPendingTransaction(tx)

	// Read the notification and verify it's a full tx object.
	var notification struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Subscription string                 `json:"subscription"`
			Result       map[string]interface{} `json:"result"`
		} `json:"params"`
	}
	readJSON(t, conn, &notification)

	if notification.Params.Subscription != subID {
		t.Errorf("expected subscription %q, got %q", subID, notification.Params.Subscription)
	}
	if notification.Params.Result["hash"] == nil {
		t.Error("expected hash field in full tx result")
	}
	if notification.Params.Result["nonce"] == nil {
		t.Error("expected nonce field in full tx result")
	}
}

// TestWSNewPendingTransactionsUnsubscribe verifies that after unsubscribing,
// no more notifications are received.
func TestWSNewPendingTransactionsUnsubscribe(t *testing.T) {
	feed := &event.Feed{}
	wm := NewWSManager(nil, feed)

	wc := newTestWSConn(t, wm)
	wm.mu.Lock()
	wm.conns[wc] = struct{}{}
	wm.mu.Unlock()

	// Subscribe.
	subID := wm.allocateID()
	wc.subs[subID] = &WSSubscription{
		id:      subID,
		subType: "newPendingTransactions",
		fullTx:  false,
	}

	// Notify - should produce an event.
	tx := newTestPendingTx()
	wm.NotifyPendingTransaction(tx)

	evt := readEvent(t, wc)
	if evt == nil {
		t.Fatal("expected event before unsubscribe")
	}

	// Unsubscribe by removing the subscription.
	delete(wc.subs, subID)

	// Notify again - should NOT produce an event.
	wm.NotifyPendingTransaction(tx)

	select {
	case evt := <-wc.eventCh:
		// Marshal for debugging.
		raw, _ := json.Marshal(evt)
		t.Fatalf("expected no event after unsubscribe, got %s", string(raw))
	case <-time.After(200 * time.Millisecond):
		// OK: no event received.
	}

	wm.Stop()
}

// TestWSNewPendingTransactionsMultipleSubscribers verifies that multiple
// connections subscribing to newPendingTransactions all get notified.
func TestWSNewPendingTransactionsMultipleSubscribers(t *testing.T) {
	feed := &event.Feed{}
	wm := NewWSManager(nil, feed)

	// Create 3 connections, each with a newPendingTransactions subscription.
	conns := make([]*wsConn, 3)
	subIDs := make([]string, 3)
	for i := range conns {
		wc := newTestWSConn(t, wm)
		conns[i] = wc
		wm.mu.Lock()
		wm.conns[wc] = struct{}{}
		wm.mu.Unlock()

		subID := wm.allocateID()
		subIDs[i] = subID
		wc.subs[subID] = &WSSubscription{
			id:      subID,
			subType: "newPendingTransactions",
			fullTx:  false,
		}
	}

	tx := newTestPendingTx()
	wm.NotifyPendingTransaction(tx)

	expectedHash := tx.Hash().Hex()

	for i, wc := range conns {
		evt := readEvent(t, wc)
		notification, ok := evt.(*wsNotification)
		if !ok {
			t.Fatalf("conn%d: expected *wsNotification, got %T", i, evt)
		}

		params, ok := notification.Params.(subscriptionParams)
		if !ok {
			t.Fatalf("conn%d: expected subscriptionParams, got %T", i, notification.Params)
		}
		if params.Subscription != subIDs[i] {
			t.Errorf("conn%d: expected subscription %q, got %q", i, subIDs[i], params.Subscription)
		}
		hashStr, ok := params.Result.(string)
		if !ok {
			t.Fatalf("conn%d: expected string result, got %T", i, params.Result)
		}
		if hashStr != expectedHash {
			t.Errorf("conn%d: expected hash %q, got %q", i, expectedHash, hashStr)
		}
	}

	wm.Stop()
}
