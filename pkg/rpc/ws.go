package rpc

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/event"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
)

// upgrader configures the WebSocket upgrade with permissive origin checking
// (CORS is handled at the HTTP level by corsMiddleware).
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WSSubscription represents a single WebSocket subscription for a connected
// client. Each subscription has a unique hex ID, a type ("newHeads", "logs",
// "newPendingTransactions", or "bsvConfirmation"), and optional parameters
// depending on the subscription type.
type WSSubscription struct {
	id      string
	subType string       // "newHeads", "logs", "newPendingTransactions", or "bsvConfirmation"
	filter  *FilterQuery // non-nil only for "logs" subscriptions
	fullTx  bool         // for "newPendingTransactions": send full tx objects instead of just hashes
}

// wsConn represents a single WebSocket connection that may hold multiple
// subscriptions. Events are delivered through a buffered channel to
// enforce event queue depth limits (M16).
type wsConn struct {
	conn    *websocket.Conn
	mu      sync.Mutex // protects writes to conn
	subs    map[string]*WSSubscription
	done    chan struct{}
	closed  atomic.Bool
	eventCh chan interface{} // buffered event queue
	manager *WSManager       // back-reference for config
}

// startEventWriter drains the buffered event channel and writes events to
// the WebSocket connection. If the queue is full and the consumer is slow,
// events are dropped after SlowConsumerTimeout.
func (wc *wsConn) startEventWriter() {
	go func() {
		for {
			select {
			case <-wc.done:
				return
			case evt, ok := <-wc.eventCh:
				if !ok {
					return
				}
				wc.mu.Lock()
				err := wc.conn.WriteJSON(evt)
				wc.mu.Unlock()
				if err != nil {
					slog.Warn("failed to write event to websocket", "error", err)
				}
			}
		}
	}()
}

// enqueueEvent sends an event to the buffered channel. If the buffer is
// full, it waits up to SlowConsumerTimeout before dropping the event AND
// tearing down the connection. Per spec 05 (ws_slow_consumer_timeout), a
// client that cannot keep up with its subscription traffic within the
// configured window is considered dead and is dropped.
func (wc *wsConn) enqueueEvent(v interface{}) bool {
	select {
	case wc.eventCh <- v:
		return true
	default:
		// Buffer full -- wait with timeout.
		timeout := 30 * time.Second
		if wc.manager != nil && wc.manager.slowConsumerTimeout > 0 {
			timeout = wc.manager.slowConsumerTimeout
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case wc.eventCh <- v:
			return true
		case <-timer.C:
			slog.Warn("dropping event for slow websocket consumer; closing connection")
			// Drop the event AND evict the client. The manager removes
			// the connection from its active-connection set so no further
			// events are routed to a socket we are about to close.
			if wc.manager != nil {
				wc.manager.removeConn(wc)
			}
			wc.close()
			return false
		case <-wc.done:
			return false
		}
	}
}

// writeJSON sends a JSON message to the WebSocket connection in a
// concurrency-safe manner (for non-subscription messages like responses).
func (wc *wsConn) writeJSON(v interface{}) error {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.conn.WriteJSON(v)
}

// close shuts down the connection and signals all goroutines to stop.
func (wc *wsConn) close() {
	if wc.closed.CompareAndSwap(false, true) {
		close(wc.done)
		wc.conn.Close()
	}
}

// BSVConfirmationEvent represents a BSV confirmation event for an L2 block.
// It is sent to bsvConfirmation subscribers when a covenant advance
// transaction receives a new BSV confirmation.
type BSVConfirmationEvent struct {
	L2BlockNumber string `json:"l2BlockNumber"` // hex
	BSVTxID       string `json:"bsvTxId"`       // hex
	Confirmations uint64 `json:"confirmations"`
	Status        string `json:"status"` // "confirmed", "finalized"
}

// WSManager manages WebSocket connections and event subscriptions. It
// subscribes to the overlay node's event feed and broadcasts new heads and
// logs to all matching WebSocket subscribers.
type WSManager struct {
	mu    sync.Mutex
	conns map[*wsConn]struct{}

	nextID atomic.Uint64

	server    *RPCServer
	eventFeed *event.Feed

	// Configurable limits.
	maxConns            int           // Default: 1000
	maxSubsPerConn      int           // Default: 100
	eventQueueDepth     int           // Default: 1000
	slowConsumerTimeout time.Duration // Default: 30s

	quit chan struct{}
}

// NewWSManager creates a new WSManager attached to the given RPC server.
// The event feed should be the overlay node's event feed obtained via
// OverlayNode.EventFeed().
func NewWSManager(server *RPCServer, feed *event.Feed) *WSManager {
	// Pull limits from server config if available, otherwise use defaults.
	maxConns := 1000
	maxSubsPerConn := 100
	eventQueueDepth := 1000
	slowConsumerTimeout := 30 * time.Second

	if server != nil {
		cfg := server.config
		if cfg.WSMaxConnections > 0 {
			maxConns = cfg.WSMaxConnections
		}
		if cfg.WSMaxSubscriptionsPerConn > 0 {
			maxSubsPerConn = cfg.WSMaxSubscriptionsPerConn
		}
		if cfg.WSEventQueueDepth > 0 {
			eventQueueDepth = cfg.WSEventQueueDepth
		}
		if cfg.WSSlowConsumerTimeout > 0 {
			slowConsumerTimeout = cfg.WSSlowConsumerTimeout
		}
	}

	return &WSManager{
		conns:               make(map[*wsConn]struct{}),
		server:              server,
		eventFeed:           feed,
		maxConns:            maxConns,
		maxSubsPerConn:      maxSubsPerConn,
		eventQueueDepth:     eventQueueDepth,
		slowConsumerTimeout: slowConsumerTimeout,
		quit:                make(chan struct{}),
	}
}

// NewWSManagerWithLimits creates a new WSManager with explicit limit
// parameters. This is useful for testing.
func NewWSManagerWithLimits(server *RPCServer, feed *event.Feed, maxConns, maxSubsPerConn, eventQueueDepth int, slowConsumerTimeout time.Duration) *WSManager {
	return &WSManager{
		conns:               make(map[*wsConn]struct{}),
		server:              server,
		eventFeed:           feed,
		maxConns:            maxConns,
		maxSubsPerConn:      maxSubsPerConn,
		eventQueueDepth:     eventQueueDepth,
		slowConsumerTimeout: slowConsumerTimeout,
		quit:                make(chan struct{}),
	}
}

// Start subscribes to the overlay's event feed and begins dispatching
// events to WebSocket subscribers. It should be called once, typically
// from RPCServer.Start().
func (wm *WSManager) Start() {
	ch := make(chan overlay.NewHeadEvent, 100)
	sub := wm.eventFeed.Subscribe(ch)

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case evt, ok := <-ch:
				if !ok {
					return
				}
				wm.NotifyNewHead(evt.Block)
				wm.notifyLogsFromBlock(evt.Block)
			case <-sub.Err():
				return
			case <-wm.quit:
				return
			}
		}
	}()
}

// Stop shuts down the WSManager, closing all connections and stopping
// the event dispatch goroutine.
func (wm *WSManager) Stop() {
	close(wm.quit)

	wm.mu.Lock()
	defer wm.mu.Unlock()
	for wc := range wm.conns {
		wc.close()
	}
}

// ActiveConnections returns the current number of active WebSocket connections.
func (wm *WSManager) ActiveConnections() int {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	return len(wm.conns)
}

// removeConn removes wc from the active-connection set if present. It is
// safe to call multiple times and is idempotent with respect to wc.close().
func (wm *WSManager) removeConn(wc *wsConn) {
	wm.mu.Lock()
	delete(wm.conns, wc)
	wm.mu.Unlock()
}

// HandleWebSocket upgrades an HTTP connection to WebSocket and begins
// reading JSON-RPC messages from the client. It supports eth_subscribe,
// eth_unsubscribe, and also proxies regular JSON-RPC methods.
func (wm *WSManager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Enforce maximum connection limit.
	wm.mu.Lock()
	if wm.maxConns > 0 && len(wm.conns) >= wm.maxConns {
		wm.mu.Unlock()
		http.Error(w, "too many websocket connections", http.StatusServiceUnavailable)
		slog.Warn("websocket connection rejected: max connections reached",
			"max", wm.maxConns, "remote", r.RemoteAddr)
		return
	}
	wm.mu.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	queueDepth := wm.eventQueueDepth
	if queueDepth <= 0 {
		queueDepth = 1000
	}

	wc := &wsConn{
		conn:    conn,
		subs:    make(map[string]*WSSubscription),
		done:    make(chan struct{}),
		eventCh: make(chan interface{}, queueDepth),
		manager: wm,
	}
	wc.startEventWriter()

	wm.mu.Lock()
	wm.conns[wc] = struct{}{}
	wm.mu.Unlock()

	slog.Info("websocket connection established", "remote", r.RemoteAddr)

	// Read loop runs in the current goroutine. When it exits we clean up.
	defer func() {
		wc.close()
		wm.mu.Lock()
		delete(wm.conns, wc)
		wm.mu.Unlock()
		slog.Info("websocket connection closed", "remote", r.RemoteAddr)
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway,
				websocket.CloseNormalClosure) {
				slog.Warn("websocket read error", "error", err)
			}
			return
		}
		wm.handleMessage(wc, message)
	}
}

// wsRequest represents an incoming JSON-RPC request over WebSocket.
type wsRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      json.RawMessage `json:"id"`
}

// wsResponse represents a JSON-RPC response sent over WebSocket.
type wsResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

// wsNotification is a JSON-RPC notification for subscription events.
// It has no ID and uses the "eth_subscription" method per the Ethereum spec.
type wsNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// subscriptionParams wraps the subscription ID and result for notifications.
type subscriptionParams struct {
	Subscription string      `json:"subscription"`
	Result       interface{} `json:"result"`
}

// handleMessage parses and dispatches a single JSON-RPC message from a
// WebSocket client.
func (wm *WSManager) handleMessage(wc *wsConn, data []byte) {
	var req wsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "invalid json"},
			ID:      json.RawMessage("null"),
		})
		return
	}

	id := req.ID
	if id == nil {
		id = json.RawMessage("null")
	}

	switch req.Method {
	case "eth_subscribe":
		wm.handleSubscribe(wc, id, req.Params)
	case "eth_unsubscribe":
		wm.handleUnsubscribe(wc, id, req.Params)
	default:
		// Proxy to the regular RPC dispatcher for any other method.
		if wm.server != nil {
			result, err := wm.server.dispatch(req.Method, req.Params)
			if err != nil {
				code := errCodeInternal
				if rpcErr, ok := err.(*rpcError); ok {
					code = rpcErr.code
				}
				wc.writeJSON(&wsResponse{
					JSONRPC: "2.0",
					Error:   &jsonrpcError{Code: code, Message: err.Error()},
					ID:      id,
				})
				return
			}
			wc.writeJSON(&wsResponse{
				JSONRPC: "2.0",
				Result:  result,
				ID:      id,
			})
		} else {
			wc.writeJSON(&wsResponse{
				JSONRPC: "2.0",
				Error:   &jsonrpcError{Code: errCodeMethodNotFound, Message: fmt.Sprintf("method %q not found", req.Method)},
				ID:      id,
			})
		}
	}
}

// handleSubscribe processes an eth_subscribe request.
func (wm *WSManager) handleSubscribe(wc *wsConn, id json.RawMessage, params json.RawMessage) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidParams, Message: "expected [subscriptionType, ...]"},
			ID:      id,
		})
		return
	}

	var subType string
	if err := json.Unmarshal(args[0], &subType); err != nil {
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidParams, Message: "invalid subscription type"},
			ID:      id,
		})
		return
	}

	// Enforce per-connection subscription limit.
	if wm.maxSubsPerConn > 0 && len(wc.subs) >= wm.maxSubsPerConn {
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeServerError, Message: fmt.Sprintf("max subscriptions per connection reached (%d)", wm.maxSubsPerConn)},
			ID:      id,
		})
		return
	}

	switch subType {
	case "newHeads":
		subID := wm.allocateID()
		sub := &WSSubscription{
			id:      subID,
			subType: "newHeads",
		}
		wc.subs[subID] = sub

		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Result:  subID,
			ID:      id,
		})

		slog.Debug("websocket subscription created", "id", subID, "type", "newHeads")

	case "logs":
		var filter FilterQuery
		if len(args) >= 2 {
			if err := parseFilterQuery(args[1], &filter); err != nil {
				wc.writeJSON(&wsResponse{
					JSONRPC: "2.0",
					Error:   &jsonrpcError{Code: errCodeInvalidParams, Message: "invalid filter: " + err.Error()},
					ID:      id,
				})
				return
			}
		}

		subID := wm.allocateID()
		sub := &WSSubscription{
			id:      subID,
			subType: "logs",
			filter:  &filter,
		}
		wc.subs[subID] = sub

		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Result:  subID,
			ID:      id,
		})

		slog.Debug("websocket subscription created", "id", subID, "type", "logs")

	case "newPendingTransactions":
		// Parse optional params: {"includeTransactions": true}
		fullTx := false
		if len(args) >= 2 {
			var opts struct {
				IncludeTransactions bool `json:"includeTransactions"`
			}
			if err := json.Unmarshal(args[1], &opts); err == nil {
				fullTx = opts.IncludeTransactions
			}
		}

		subID := wm.allocateID()
		sub := &WSSubscription{
			id:      subID,
			subType: "newPendingTransactions",
			fullTx:  fullTx,
		}
		wc.subs[subID] = sub

		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Result:  subID,
			ID:      id,
		})

		slog.Debug("websocket subscription created", "id", subID, "type", "newPendingTransactions", "fullTx", fullTx)

	case "bsvConfirmation":
		subID := wm.allocateID()
		sub := &WSSubscription{
			id:      subID,
			subType: "bsvConfirmation",
		}
		wc.subs[subID] = sub

		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Result:  subID,
			ID:      id,
		})

		slog.Debug("websocket subscription created", "id", subID, "type", "bsvConfirmation")

	default:
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidParams, Message: fmt.Sprintf("unsupported subscription type: %q", subType)},
			ID:      id,
		})
	}
}

// handleUnsubscribe processes an eth_unsubscribe request.
func (wm *WSManager) handleUnsubscribe(wc *wsConn, id json.RawMessage, params json.RawMessage) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidParams, Message: "expected [subscriptionId]"},
			ID:      id,
		})
		return
	}

	var subID string
	if err := json.Unmarshal(args[0], &subID); err != nil {
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidParams, Message: "invalid subscription id"},
			ID:      id,
		})
		return
	}

	if _, ok := wc.subs[subID]; ok {
		delete(wc.subs, subID)
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Result:  true,
			ID:      id,
		})
		slog.Debug("websocket subscription removed", "id", subID)
	} else {
		wc.writeJSON(&wsResponse{
			JSONRPC: "2.0",
			Result:  false,
			ID:      id,
		})
	}
}

// allocateID generates a unique hex subscription ID.
func (wm *WSManager) allocateID() string {
	n := wm.nextID.Add(1)
	return "0x" + strconv.FormatUint(n, 16)
}

// NotifyNewHead broadcasts a new block header to all "newHeads" subscribers.
func (wm *WSManager) NotifyNewHead(blk *block.L2Block) {
	if blk == nil {
		return
	}
	headerResult := formatBlockHeader(blk)

	wm.mu.Lock()
	conns := make([]*wsConn, 0, len(wm.conns))
	for wc := range wm.conns {
		conns = append(conns, wc)
	}
	wm.mu.Unlock()

	for _, wc := range conns {
		for _, sub := range wc.subs {
			if sub.subType == "newHeads" {
				notification := &wsNotification{
					JSONRPC: "2.0",
					Method:  "eth_subscription",
					Params: subscriptionParams{
						Subscription: sub.id,
						Result:       headerResult,
					},
				}
				wc.enqueueEvent(notification)
			}
		}
	}
}

// NotifyLogs broadcasts matching log entries to all "logs" subscribers.
// Each matching log is sent as an individual notification.
func (wm *WSManager) NotifyLogs(logs []*types.Log) {
	if len(logs) == 0 {
		return
	}

	wm.mu.Lock()
	conns := make([]*wsConn, 0, len(wm.conns))
	for wc := range wm.conns {
		conns = append(conns, wc)
	}
	wm.mu.Unlock()

	for _, wc := range conns {
		for _, sub := range wc.subs {
			if sub.subType != "logs" {
				continue
			}
			for _, log := range logs {
				if !matchesLogSubscription(log, sub.filter) {
					continue
				}
				notification := &wsNotification{
					JSONRPC: "2.0",
					Method:  "eth_subscription",
					Params: subscriptionParams{
						Subscription: sub.id,
						Result:       formatLog(log),
					},
				}
				wc.enqueueEvent(notification)
			}
		}
	}
}

// NotifyPendingTransaction broadcasts a pending transaction to all
// "newPendingTransactions" subscribers. If the subscriber's fullTx flag
// is false, only the transaction hash is sent. If fullTx is true, a
// map with the transaction's fields is sent.
func (wm *WSManager) NotifyPendingTransaction(tx *types.Transaction) {
	if tx == nil {
		return
	}

	txHash := tx.Hash().Hex()

	wm.mu.Lock()
	conns := make([]*wsConn, 0, len(wm.conns))
	for wc := range wm.conns {
		conns = append(conns, wc)
	}
	wm.mu.Unlock()

	for _, wc := range conns {
		for _, sub := range wc.subs {
			if sub.subType != "newPendingTransactions" {
				continue
			}

			var result interface{}
			if sub.fullTx {
				txObj := map[string]interface{}{
					"hash":     txHash,
					"nonce":    EncodeUint64(tx.Nonce()),
					"value":    EncodeBig(tx.Value().ToBig()),
					"gas":      EncodeUint64(tx.Gas()),
					"gasPrice": EncodeBig(tx.GasPrice()),
					"input":    EncodeBytes(tx.Data()),
					"type":     EncodeUint64(uint64(tx.Type())),
				}
				if tx.To() != nil {
					txObj["to"] = tx.To().Hex()
				} else {
					txObj["to"] = nil
				}
				v, r, s := tx.RawSignatureValues()
				if v != nil {
					txObj["v"] = EncodeBig(v)
				}
				if r != nil {
					txObj["r"] = EncodeBig(r)
				}
				if s != nil {
					txObj["s"] = EncodeBig(s)
				}
				result = txObj
			} else {
				result = txHash
			}

			notification := &wsNotification{
				JSONRPC: "2.0",
				Method:  "eth_subscription",
				Params: subscriptionParams{
					Subscription: sub.id,
					Result:       result,
				},
			}
			wc.enqueueEvent(notification)
		}
	}
}

// notifyLogsFromBlock extracts logs from a block's receipts (read from
// ChainDB) and broadcasts them to log subscribers.
func (wm *WSManager) notifyLogsFromBlock(blk *block.L2Block) {
	if wm.server == nil || wm.server.ethAPI == nil {
		return
	}

	blockHash := blk.Hash()
	blockNumber := blk.NumberU64()

	receipts := wm.server.ethAPI.chainDB.ReadReceipts(blockHash, blockNumber)
	if len(receipts) == 0 {
		return
	}

	var allLogs []*types.Log
	for _, receipt := range receipts {
		for _, log := range receipt.Logs {
			log.BlockNumber = blockNumber
			log.BlockHash = blockHash
			allLogs = append(allLogs, log)
		}
	}

	wm.NotifyLogs(allLogs)
}

// NotifyBSVConfirmation broadcasts a BSV confirmation event to all
// bsvConfirmation subscribers. This is called when an L2 block's covenant
// advance transaction receives a new BSV confirmation.
func (wm *WSManager) NotifyBSVConfirmation(evt BSVConfirmationEvent) {
	wm.mu.Lock()
	conns := make([]*wsConn, 0, len(wm.conns))
	for wc := range wm.conns {
		conns = append(conns, wc)
	}
	wm.mu.Unlock()

	for _, wc := range conns {
		for _, sub := range wc.subs {
			if sub.subType == "bsvConfirmation" {
				notification := &wsNotification{
					JSONRPC: "2.0",
					Method:  "eth_subscription",
					Params: subscriptionParams{
						Subscription: sub.id,
						Result:       evt,
					},
				}
				wc.enqueueEvent(notification)
			}
		}
	}
}

// matchesLogSubscription checks whether a log matches a subscription's filter.
// A nil or empty filter matches all logs.
func matchesLogSubscription(log *types.Log, filter *FilterQuery) bool {
	if filter == nil {
		return true
	}
	return matchLog(log, filter.Addresses, filter.Topics)
}

// formatBlockHeader converts a block to the newHeads subscription result
// format, which matches the Ethereum JSON-RPC header object.
func formatBlockHeader(blk *block.L2Block) map[string]interface{} {
	header := blk.Header
	if header.Number == nil {
		header.Number = new(big.Int)
	}
	if header.BaseFee == nil {
		header.BaseFee = new(big.Int)
	}

	return map[string]interface{}{
		"number":           EncodeUint64(header.Number.Uint64()),
		"hash":             blk.Hash().Hex(),
		"parentHash":       header.ParentHash.Hex(),
		"nonce":            "0x0000000000000000",
		"sha3Uncles":       types.EmptyRootHash.Hex(),
		"logsBloom":        EncodeBytes(header.LogsBloom.Bytes()),
		"transactionsRoot": header.TxHash.Hex(),
		"stateRoot":        header.StateRoot.Hex(),
		"receiptsRoot":     header.ReceiptHash.Hex(),
		"miner":            EncodeAddress(header.Coinbase),
		"difficulty":       "0x0",
		"extraData":        EncodeBytes(header.Extra),
		"gasLimit":         EncodeUint64(header.GasLimit),
		"gasUsed":          EncodeUint64(header.GasUsed),
		"timestamp":        EncodeUint64(header.Timestamp),
		"baseFeePerGas":    EncodeBig(header.BaseFee),
		"mixHash":          types.Hash{}.Hex(),
	}
}
