package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/indexer"
	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/rpc/auth"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/webui"
)

// JSON-RPC error codes matching Ethereum conventions.
const (
	errCodeInvalidRequest = -32600
	errCodeMethodNotFound = -32601
	errCodeInvalidParams  = -32602
	errCodeInternal       = -32603
	errCodeServerError    = -32000
)

// maxRequestSize is the maximum allowed size for an HTTP JSON-RPC request
// body (5 MB). Requests exceeding this limit are rejected.
const maxRequestSize = 5 * 1024 * 1024

// RPCServer is the HTTP JSON-RPC server that exposes the Ethereum-compatible
// API to clients like MetaMask, ethers.js, Hardhat, and Foundry.
type RPCServer struct {
	config     RPCConfig
	ethAPI     *EthAPI
	netAPI     *NetAPI
	web3API    *Web3API
	bsvAPI     *BsvAPI
	debugAPI   *DebugAPI
	adminAPI   *AdminAPI
	overlay    *overlay.OverlayNode
	wsManager  *WSManager
	httpServer *http.Server
	wsServer   *http.Server // separate WebSocket server on WSAddr
	limiter    *rateLimiter // per-IP rate limiting
	registry    *metrics.Registry
	authConfig  auth.Config
	logStreamer *LogStreamer
	indexer     IndexerReader
}

// IndexerReader is the read-side of pkg/indexer that bsv_getAddressTxs
// depends on. Declared as an interface so tests can stub it without
// spinning up a LevelDB.
type IndexerReader interface {
	LookupEntries(indexer.Query) ([]indexer.Entry, error)
}

// SetIndexer attaches an indexer provider. Must be called before
// Start(). Passing nil disables the bsv_getAddressTxs RPC — callers
// will receive "indexer disabled" errors.
func (s *RPCServer) SetIndexer(idx IndexerReader) {
	s.indexer = idx
}

// SetAdminAuth configures the auth layer that guards /admin/rpc. Must
// be called before Start(). When DevAuthSecret is empty AND
// GovernanceChecker is nil, the admin endpoint is unmounted entirely —
// a node with no admin credentials simply doesn't expose the surface.
func (s *RPCServer) SetAdminAuth(cfg auth.Config) {
	s.authConfig = cfg
}

// AdminAPI returns the admin JSON-RPC handler. Exposed so callers
// outside pkg/rpc (e.g. cmd/bsvm) can inject cross-cutting
// dependencies like the governance workflow without every handler
// owning the full startup order.
func (s *RPCServer) AdminAPI() *AdminAPI {
	return s.adminAPI
}

// SetMetricsRegistry attaches a Prometheus registry. When set, the HTTP
// handler exposes `GET /metrics` for scraping. Must be called before
// Start(). Passing nil disables the scrape endpoint.
func (s *RPCServer) SetMetricsRegistry(r *metrics.Registry) {
	s.registry = r
}

// SetLogStreamer attaches the admin log streamer. The WebSocket
// manager uses it to back adminLogs subscriptions (spec 15 A9). Must
// be called before Start().
func (s *RPCServer) SetLogStreamer(ls *LogStreamer) {
	s.logStreamer = ls
}

// NewRPCServer creates a new JSON-RPC server with the given configuration and
// dependencies. The server is not started until Start is called.
func NewRPCServer(
	config RPCConfig,
	overlayNode *overlay.OverlayNode,
	chainDB *block.ChainDB,
	database db.Database,
) *RPCServer {
	chainConfig := vm.DefaultL2Config(overlayNode.ChainDB().ReadHeadHeader().Number.Int64())
	// Try to use the overlay's chain ID.
	if overlayNode.ChainDB() != nil {
		// Read from config — the overlay node was initialised with the chain ID.
		// Use the chainConfig's ChainID which was set from DefaultL2Config.
	}

	stateReader := NewStateReader(database, chainDB)

	ethAPI := NewEthAPI(chainConfig, chainDB, stateReader, overlayNode)
	ethAPI.SetGetLogsMaxRange(config.GetLogsMaxRange)
	return &RPCServer{
		config:   config,
		ethAPI:   ethAPI,
		netAPI:   NewNetAPI(chainConfig.ChainID.Int64()),
		web3API:  NewWeb3API(),
		bsvAPI:   NewBsvAPI(overlayNode),
		debugAPI: NewDebugAPI(ethAPI, overlayNode),
		adminAPI: NewAdminAPI(overlayNode),
		overlay:  overlayNode,
	}
}

// NewRPCServerWithConfig creates a new JSON-RPC server with explicit chain
// configuration. This is preferred over NewRPCServer when the chain ID is
// known at construction time.
func NewRPCServerWithConfig(
	config RPCConfig,
	chainConfig *vm.ChainConfig,
	overlayNode *overlay.OverlayNode,
	chainDB *block.ChainDB,
	database db.Database,
) *RPCServer {
	stateReader := NewStateReader(database, chainDB)

	ethAPI := NewEthAPI(chainConfig, chainDB, stateReader, overlayNode)
	ethAPI.SetGetLogsMaxRange(config.GetLogsMaxRange)
	return &RPCServer{
		config:   config,
		ethAPI:   ethAPI,
		netAPI:   NewNetAPI(chainConfig.ChainID.Int64()),
		web3API:  NewWeb3API(),
		bsvAPI:   NewBsvAPI(overlayNode),
		debugAPI: NewDebugAPI(ethAPI, overlayNode),
		adminAPI: NewAdminAPI(overlayNode),
		overlay:  overlayNode,
	}
}

// Start starts the HTTP server and begins accepting JSON-RPC requests.
// It also initialises the WebSocket subscription manager for real-time
// event streaming via eth_subscribe on a separate server listening on WSAddr.
func (s *RPCServer) Start() error {
	// Create and start the WebSocket subscription manager.
	s.wsManager = NewWSManager(s, s.overlay.EventFeed())
	if s.logStreamer != nil {
		s.wsManager.SetLogStreamer(s.logStreamer)
	}
	s.wsManager.Start()

	// Initialise rate limiter if configured.
	if s.config.RequestsPerSecond > 0 {
		s.limiter = newRateLimiter(s.config.RequestsPerSecond, s.config.BurstSize)
	}

	// HTTP server for JSON-RPC + static SPA.
	httpMux := http.NewServeMux()
	if s.registry != nil {
		// Expose Prometheus scrape. Mounted before "/" so it bypasses
		// the JSON-RPC dispatcher. OpenMetrics is negotiated via the
		// Accept header by promhttp.
		httpMux.Handle("/metrics", s.registry.HTTPHandler())
	}
	// /admin/rpc — authenticated admin JSON-RPC. Only mounted when
	// admin auth has been configured; a node with no admin credentials
	// simply doesn't expose the surface.
	if s.authConfig.DevAuthSecret != "" || s.authConfig.GovernanceChecker != nil {
		adminHandler := http.HandlerFunc(s.handleAdminRPC)
		httpMux.Handle("/admin/rpc", s.authConfig.Middleware(adminHandler))
	}

	// /.well-known/auth — BRC-103 handshake endpoint. Required for
	// admin wallets to open a session; gated on the same auth config
	// so a node with no wallet-auth wiring returns 503 rather than
	// silently missing the endpoint.
	if s.authConfig.ServerIdentity != nil && s.authConfig.GovernanceChecker != nil && s.authConfig.SessionStore != nil {
		httpMux.Handle("/.well-known/auth", s.authConfig.HandshakeHandler())
	}

	// Root handler: GET → embedded explorer SPA (spec 15), POST → JSON-RPC.
	// webui.Handler delegates non-GET requests to the RPC handler, so the
	// dispatcher still sees every JSON-RPC call exactly as before.
	httpMux.Handle("/", webui.Handler(http.HandlerFunc(s.handleHTTP)))

	var httpHandler http.Handler = httpMux
	if s.limiter != nil {
		httpHandler = s.limiter.middleware(httpHandler)
	}

	s.httpServer = &http.Server{
		Addr:    s.config.HTTPAddr,
		Handler: s.corsMiddleware(httpHandler),
	}

	// Separate WebSocket server on WSAddr.
	wsMux := http.NewServeMux()
	wsMux.HandleFunc("/", s.wsManager.HandleWebSocket)
	wsMux.HandleFunc("/ws", s.wsManager.HandleWebSocket)

	wsAddr := s.config.WSAddr
	if wsAddr == "" {
		wsAddr = s.config.HTTPAddr // fallback to same address
	}

	s.wsServer = &http.Server{
		Addr:    wsAddr,
		Handler: s.corsMiddleware(wsMux),
	}

	slog.Info("starting JSON-RPC server",
		"httpAddr", s.config.HTTPAddr,
		"wsAddr", wsAddr,
	)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("JSON-RPC HTTP server error", "error", err)
		}
	}()
	go func() {
		if err := s.wsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("JSON-RPC WebSocket server error", "error", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP and WebSocket servers and the
// subscription manager.
func (s *RPCServer) Stop() error {
	if s.wsManager != nil {
		s.wsManager.Stop()
	}
	if s.wsServer != nil {
		s.wsServer.Shutdown(context.Background())
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(context.Background())
	}
	return nil
}

// WSManager returns the server's WebSocket subscription manager.
func (s *RPCServer) WSManager() *WSManager {
	return s.wsManager
}

// EthAPI returns the server's EthAPI for direct method access in tests.
func (s *RPCServer) EthAPI() *EthAPI {
	return s.ethAPI
}

// NetAPI returns the server's NetAPI for direct method access in tests.
func (s *RPCServer) NetAPI() *NetAPI {
	return s.netAPI
}

// Web3API returns the server's Web3API for direct method access in tests.
func (s *RPCServer) Web3API() *Web3API {
	return s.web3API
}

// BsvAPI returns the server's BsvAPI for direct method access in tests.
func (s *RPCServer) BsvAPI() *BsvAPI {
	return s.bsvAPI
}

// DebugAPI returns the server's DebugAPI for direct method access in tests.
func (s *RPCServer) DebugAPI() *DebugAPI {
	return s.debugAPI
}

// jsonrpcRequest represents a single JSON-RPC 2.0 request.
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      json.RawMessage `json:"id"`
}

// jsonrpcResponse represents a single JSON-RPC 2.0 response.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

// jsonrpcError represents a JSON-RPC 2.0 error.
type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// handleHTTP handles incoming HTTP JSON-RPC requests, supporting both single
// requests and batch (array) requests.
func (s *RPCServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize))
	if err != nil {
		writeJSONResponse(w, &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "failed to read request body"},
			ID:      json.RawMessage("null"),
		})
		return
	}

	// Trim whitespace to detect if this is a batch request.
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		writeJSONResponse(w, &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "empty request body"},
			ID:      json.RawMessage("null"),
		})
		return
	}

	if trimmed[0] == '[' {
		// Batch request: parse as array of raw messages so that
		// individual malformed entries do not break the entire batch.
		var rawRequests []json.RawMessage
		if err := json.Unmarshal(body, &rawRequests); err != nil {
			writeJSONResponse(w, &jsonrpcResponse{
				JSONRPC: "2.0",
				Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "invalid batch request"},
				ID:      json.RawMessage("null"),
			})
			return
		}
		responses := s.handleBatch(rawRequests)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responses)
	} else if trimmed[0] == '{' {
		// Single request.
		resp := s.processSingleRequest(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	} else {
		// Neither object nor array — parse error.
		writeJSONResponse(w, &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "invalid request: expected object or array"},
			ID:      json.RawMessage("null"),
		})
	}
}

// handleBatch processes a batch of JSON-RPC requests. Each request is
// individually parsed and dispatched; a malformed entry produces an error
// response for that position without affecting other entries.
func (s *RPCServer) handleBatch(requests []json.RawMessage) []json.RawMessage {
	results := make([]json.RawMessage, len(requests))
	for i, req := range requests {
		results[i] = s.processSingleRequest(req)
	}
	return results
}

// processSingleRequest parses and dispatches a single JSON-RPC request
// from raw bytes and returns the JSON-encoded response.
func (s *RPCServer) processSingleRequest(raw json.RawMessage) json.RawMessage {
	var req jsonrpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		resp := &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "invalid request"},
			ID:      json.RawMessage("null"),
		}
		data, _ := json.Marshal(resp)
		return data
	}
	resp := s.handleRequest(&req)
	data, _ := json.Marshal(resp)
	return data
}

// handleRequest routes a single JSON-RPC request to the appropriate handler.
func (s *RPCServer) handleRequest(req *jsonrpcRequest) *jsonrpcResponse {
	id := req.ID
	if id == nil {
		id = json.RawMessage("null")
	}

	result, err := s.dispatch(req.Method, req.Params)
	if err != nil {
		code := errCodeInternal
		if rpcErr, ok := err.(*rpcError); ok {
			code = rpcErr.code
		}
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: code, Message: err.Error()},
			ID:      id,
		}
	}

	return &jsonrpcResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
}

// rpcError is an error with an associated JSON-RPC error code.
type rpcError struct {
	code    int
	message string
}

// Error implements the error interface.
func (e *rpcError) Error() string {
	return e.message
}

// newRPCError creates a new rpcError with the given code and message.
func newRPCError(code int, msg string) *rpcError {
	return &rpcError{code: code, message: msg}
}

// dispatch routes a method name to the appropriate API handler and returns
// the result.
func (s *RPCServer) dispatch(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	// -- eth_ namespace --
	case "eth_chainId":
		return s.ethAPI.ChainId(), nil

	case "eth_blockNumber":
		return s.ethAPI.BlockNumber(), nil

	case "eth_getBalance":
		return s.handleEthGetBalance(params)

	case "eth_getTransactionCount":
		return s.handleEthGetTransactionCount(params)

	case "eth_getCode":
		return s.handleEthGetCode(params)

	case "eth_getStorageAt":
		return s.handleEthGetStorageAt(params)

	case "eth_call":
		return s.handleEthCall(params)

	case "eth_estimateGas":
		return s.handleEthEstimateGas(params)

	case "eth_sendRawTransaction":
		return s.handleEthSendRawTransaction(params)

	case "eth_getTransactionByHash":
		return s.handleEthGetTransactionByHash(params)

	case "eth_getTransactionReceipt":
		return s.handleEthGetTransactionReceipt(params)

	case "eth_getBlockByNumber":
		return s.handleEthGetBlockByNumber(params)

	case "eth_getBlockByHash":
		return s.handleEthGetBlockByHash(params)

	case "eth_gasPrice":
		return s.ethAPI.GasPrice(), nil

	case "eth_getLogs":
		return s.handleEthGetLogs(params)

	case "eth_getBlockReceipts":
		return s.handleEthGetBlockReceipts(params)

	case "eth_getBlockTransactionCountByNumber":
		return s.handleEthGetBlockTransactionCountByNumber(params)

	case "eth_getBlockTransactionCountByHash":
		return s.handleEthGetBlockTransactionCountByHash(params)

	case "eth_syncing":
		return s.ethAPI.Syncing(), nil

	case "eth_accounts":
		return s.ethAPI.Accounts(), nil

	case "eth_maxPriorityFeePerGas":
		return s.ethAPI.MaxPriorityFeePerGas(), nil

	case "eth_getTransactionByBlockHashAndIndex":
		return s.handleEthGetTransactionByBlockHashAndIndex(params)

	case "eth_getTransactionByBlockNumberAndIndex":
		return s.handleEthGetTransactionByBlockNumberAndIndex(params)

	case "eth_getProof":
		return s.handleEthGetProof(params)

	case "eth_createAccessList":
		return s.handleEthCreateAccessList(params)

	case "eth_feeHistory":
		return s.handleEthFeeHistory(params)

	case "eth_sign":
		return nil, &rpcError{code: errCodeMethodNotFound, message: "eth_sign is not supported (no key management)"}

	case "eth_sendTransaction":
		return nil, &rpcError{code: errCodeMethodNotFound, message: "eth_sendTransaction is not supported, use eth_sendRawTransaction"}

	// -- debug_ namespace --
	case "debug_traceTransaction":
		return s.handleDebugTraceTransaction(params)

	case "debug_traceCall":
		return s.handleDebugTraceCall(params)

	case "debug_traceBlockByNumber":
		return s.handleDebugTraceBlockByNumber(params)

	case "debug_traceBlockByHash":
		return s.handleDebugTraceBlockByHash(params)

	case "debug_evmDisagreement":
		return s.debugAPI.EVMDisagreement()

	// -- net_ namespace --
	case "net_version":
		return s.netAPI.Version(), nil

	case "net_listening":
		return s.netAPI.Listening(), nil

	case "net_peerCount":
		return s.netAPI.PeerCount(), nil

	// -- web3_ namespace --
	case "web3_clientVersion":
		return s.web3API.ClientVersion(), nil

	case "web3_sha3":
		return s.handleWeb3Sha3(params)

	// -- bsv_ namespace --
	case "bsv_shardInfo":
		return s.bsvAPI.ShardInfo(), nil

	case "bsv_getConfirmationStatus":
		return s.handleBsvGetConfirmationStatus(params)

	case "bsv_getCachedChainLength":
		return s.bsvAPI.GetCachedChainLength(), nil

	case "bsv_feeWalletBalance":
		return s.bsvAPI.FeeWalletBalance(), nil

	case "bsv_peerCount":
		return s.bsvAPI.PeerCount(), nil

	case "bsv_getPeers":
		return s.bsvAPI.GetPeers(), nil

	case "bsv_getCovenantTip":
		return s.bsvAPI.GetCovenantTip(), nil

	case "bsv_getGovernanceState":
		return s.bsvAPI.GetGovernanceState(), nil

	case "bsv_buildWithdrawalClaim":
		return s.handleBsvBuildWithdrawalClaim(params)

	// -- bsv_ namespace (spec 15 explorer surface) --
	case "bsv_bridgeStatus":
		return s.bsvAPI.BridgeStatus(), nil

	case "bsv_getDeposits":
		return s.handleBsvGetDeposits(params)

	case "bsv_getWithdrawals":
		return s.handleBsvGetWithdrawals(params)

	case "bsv_networkHealth":
		return s.bsvAPI.NetworkHealth(), nil

	case "bsv_provingStatus":
		return s.bsvAPI.ProvingStatus(), nil

	case "bsv_getAddressTxs":
		return s.handleBsvGetAddressTxs(params)

	case "bsv_indexerStatus":
		return s.handleBsvIndexerStatus()

	default:
		return nil, newRPCError(errCodeMethodNotFound, fmt.Sprintf("method %q not found", method))
	}
}

// handleBsvGetAddressTxs resolves `bsv_getAddressTxs(address, opts?)`.
// opts is an optional object: {"fromBlock","toBlock","limit"} — all
// numeric fields accept either decimal or 0x-prefixed hex. Returns
// newest-first entries, capped by server-side limit.
func (s *RPCServer) handleBsvGetAddressTxs(params json.RawMessage) (interface{}, error) {
	if s.indexer == nil {
		return nil, newRPCError(errCodeServerError,
			"indexer disabled (set BSVM_INDEXER_ENABLED=true to enable)")
	}
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [address, opts?]")
	}
	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}

	q := indexer.Query{Address: addr, Limit: 50}
	if len(args) > 1 && len(args[1]) > 0 && string(args[1]) != "null" {
		var opts struct {
			FromBlock json.RawMessage `json:"fromBlock"`
			ToBlock   json.RawMessage `json:"toBlock"`
			Limit     json.RawMessage `json:"limit"`
		}
		if err := json.Unmarshal(args[1], &opts); err != nil {
			return nil, newRPCError(errCodeInvalidParams, "invalid opts: "+err.Error())
		}
		if len(opts.FromBlock) > 0 {
			n, err := parseNumberFlexible(opts.FromBlock)
			if err != nil {
				return nil, newRPCError(errCodeInvalidParams, "fromBlock: "+err.Error())
			}
			q.FromBlock = n
		}
		if len(opts.ToBlock) > 0 {
			n, err := parseNumberFlexible(opts.ToBlock)
			if err != nil {
				return nil, newRPCError(errCodeInvalidParams, "toBlock: "+err.Error())
			}
			q.ToBlock = n
		}
		if len(opts.Limit) > 0 {
			n, err := parseNumberFlexible(opts.Limit)
			if err != nil {
				return nil, newRPCError(errCodeInvalidParams, "limit: "+err.Error())
			}
			q.Limit = int(n)
		}
	}

	entries, err := s.indexer.LookupEntries(q)
	if err != nil {
		return nil, newRPCError(errCodeInternal, "indexer lookup: "+err.Error())
	}

	// Shape the response for JSON — hex-encode numbers to stay
	// consistent with every other bsv_* method.
	out := make([]map[string]any, len(entries))
	for i, e := range entries {
		row := map[string]any{
			"txHash":           e.TxHash.Hex(),
			"blockNumber":      fmt.Sprintf("0x%x", e.BlockNumber),
			"transactionIndex": fmt.Sprintf("0x%x", e.TxIndex),
			"direction":        string(e.Direction),
			"status":           fmt.Sprintf("0x%x", e.Status),
		}
		if e.Other != nil {
			row["otherParty"] = e.Other.Hex()
		}
		out[i] = row
	}
	return out, nil
}

// handleBsvIndexerStatus reports indexer enabled/disabled + tip so the
// UI can show a tasteful fallback without another RPC round-trip.
func (s *RPCServer) handleBsvIndexerStatus() (interface{}, error) {
	if s.indexer == nil {
		return map[string]any{"enabled": false}, nil
	}
	// Duck-type the Stats method so we don't force every IndexerReader
	// implementation to expose it (tests can stub LookupEntries only).
	type statser interface {
		Stats() indexer.Stats
	}
	resp := map[string]any{"enabled": true}
	if st, ok := s.indexer.(statser); ok {
		s := st.Stats()
		resp["lastBlock"] = fmt.Sprintf("0x%x", s.LastBlock)
		resp["ingested"] = fmt.Sprintf("0x%x", s.Ingested)
		resp["dropped"] = fmt.Sprintf("0x%x", s.Dropped)
	}
	return resp, nil
}

// parseNumberFlexible decodes a JSON number value that may be either a
// JSON integer or a hex string ("0x…"). Standard Ethereum JSON-RPC
// uses hex; simulator / HTTP clients often send plain integers.
func parseNumberFlexible(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	// Try hex-string form first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimPrefix(s, "0x")
		s = strings.TrimPrefix(s, "0X")
		if s == "" {
			return 0, nil
		}
		var n uint64
		_, err := fmt.Sscanf(s, "%x", &n)
		if err != nil {
			return 0, fmt.Errorf("parse hex %q: %w", s, err)
		}
		return n, nil
	}
	// Fall back to raw JSON integer.
	var n uint64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("expected hex string or integer, got %s", string(raw))
	}
	return n, nil
}

// -- Parameter parsing handlers --

// handleEthGetBalance parses params for eth_getBalance.
func (s *RPCServer) handleEthGetBalance(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [address, blockTag]")
	}
	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}
	blockNrOrHash, err := parseBlockNrOrHash(args[1])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	return s.ethAPI.GetBalance(addr, blockNrOrHash)
}

// handleEthGetTransactionCount parses params for eth_getTransactionCount.
func (s *RPCServer) handleEthGetTransactionCount(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [address, blockTag]")
	}
	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}
	blockNrOrHash, err := parseBlockNrOrHash(args[1])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	return s.ethAPI.GetTransactionCount(addr, blockNrOrHash)
}

// handleEthGetCode parses params for eth_getCode.
func (s *RPCServer) handleEthGetCode(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [address, blockTag]")
	}
	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}
	blockNrOrHash, err := parseBlockNrOrHash(args[1])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	return s.ethAPI.GetCode(addr, blockNrOrHash)
}

// handleEthGetStorageAt parses params for eth_getStorageAt.
func (s *RPCServer) handleEthGetStorageAt(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
		return nil, newRPCError(errCodeInvalidParams, "expected [address, slot, blockTag]")
	}
	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}
	var slotStr string
	if err := json.Unmarshal(args[1], &slotStr); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid slot: "+err.Error())
	}
	slot := types.HexToHash(slotStr)
	blockNrOrHash, err := parseBlockNrOrHash(args[2])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	return s.ethAPI.GetStorageAt(addr, slot, blockNrOrHash)
}

// handleEthCall parses params for eth_call.
func (s *RPCServer) handleEthCall(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [txArgs, blockTag]")
	}
	var txArgs TransactionArgs
	if err := parseTransactionArgs(args[0], &txArgs); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid tx args: "+err.Error())
	}
	blockNrOrHash := BlockNumberOrHashWithNumber(-1) // default: latest
	if len(args) >= 2 {
		var err error
		blockNrOrHash, err = parseBlockNrOrHash(args[1])
		if err != nil {
			return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
		}
	}
	return s.ethAPI.Call(txArgs, blockNrOrHash)
}

// handleEthEstimateGas parses params for eth_estimateGas.
func (s *RPCServer) handleEthEstimateGas(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [txArgs, blockTag?]")
	}
	var txArgs TransactionArgs
	if err := parseTransactionArgs(args[0], &txArgs); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid tx args: "+err.Error())
	}
	var blockNrOrHash *BlockNumberOrHash
	if len(args) >= 2 {
		bnh, err := parseBlockNrOrHash(args[1])
		if err != nil {
			return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
		}
		blockNrOrHash = &bnh
	}
	return s.ethAPI.EstimateGas(txArgs, blockNrOrHash)
}

// handleEthSendRawTransaction parses params for eth_sendRawTransaction.
func (s *RPCServer) handleEthSendRawTransaction(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [encodedTx]")
	}
	var hexTx string
	if err := json.Unmarshal(args[0], &hexTx); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hex data: "+err.Error())
	}
	txBytes, err := decodeHexBytes(hexTx)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hex encoding: "+err.Error())
	}
	return s.ethAPI.SendRawTransaction(txBytes)
}

// handleEthGetTransactionByHash parses params for eth_getTransactionByHash.
func (s *RPCServer) handleEthGetTransactionByHash(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [txHash]")
	}
	hash, err := parseHash(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hash: "+err.Error())
	}
	return s.ethAPI.GetTransactionByHash(hash)
}

// handleEthGetTransactionReceipt parses params for eth_getTransactionReceipt.
func (s *RPCServer) handleEthGetTransactionReceipt(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [txHash]")
	}
	hash, err := parseHash(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hash: "+err.Error())
	}
	return s.ethAPI.GetTransactionReceipt(hash)
}

// handleEthGetBlockByNumber parses params for eth_getBlockByNumber.
func (s *RPCServer) handleEthGetBlockByNumber(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockTag, fullTxs]")
	}
	var blockTag string
	if err := json.Unmarshal(args[0], &blockTag); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	blockNr, err := resolveBlockTag(blockTag)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	var fullTxs bool
	if err := json.Unmarshal(args[1], &fullTxs); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid fullTxs: "+err.Error())
	}
	return s.ethAPI.GetBlockByNumber(blockNr, fullTxs)
}

// handleEthGetBlockByHash parses params for eth_getBlockByHash.
func (s *RPCServer) handleEthGetBlockByHash(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockHash, fullTxs]")
	}
	hash, err := parseHash(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hash: "+err.Error())
	}
	var fullTxs bool
	if err := json.Unmarshal(args[1], &fullTxs); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid fullTxs: "+err.Error())
	}
	return s.ethAPI.GetBlockByHash(hash, fullTxs)
}

// handleEthGetLogs parses params for eth_getLogs.
func (s *RPCServer) handleEthGetLogs(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [filterQuery]")
	}
	var filter FilterQuery
	if err := parseFilterQuery(args[0], &filter); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid filter: "+err.Error())
	}
	return s.ethAPI.GetLogs(filter)
}

// handleEthGetBlockReceipts parses params for eth_getBlockReceipts.
func (s *RPCServer) handleEthGetBlockReceipts(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockTag]")
	}
	var blockTag string
	if err := json.Unmarshal(args[0], &blockTag); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	blockNr, err := resolveBlockTag(blockTag)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	return s.ethAPI.GetBlockReceipts(blockNr)
}

// handleEthGetBlockTransactionCountByNumber parses params.
func (s *RPCServer) handleEthGetBlockTransactionCountByNumber(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockTag]")
	}
	var blockTag string
	if err := json.Unmarshal(args[0], &blockTag); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	blockNr, err := resolveBlockTag(blockTag)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	return s.ethAPI.GetBlockTransactionCountByNumber(blockNr)
}

// handleEthGetBlockTransactionCountByHash parses params.
func (s *RPCServer) handleEthGetBlockTransactionCountByHash(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockHash]")
	}
	hash, err := parseHash(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hash: "+err.Error())
	}
	return s.ethAPI.GetBlockTransactionCountByHash(hash)
}

// handleEthFeeHistory parses params [blockCount, newestBlock, rewardPercentiles]
// and delegates to EthAPI.FeeHistory.
func (s *RPCServer) handleEthFeeHistory(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockCount, newestBlock, rewardPercentiles?]")
	}

	// Parse blockCount (hex or decimal number).
	var blockCountRaw interface{}
	if err := json.Unmarshal(args[0], &blockCountRaw); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid blockCount: "+err.Error())
	}

	var blockCount uint64
	switch v := blockCountRaw.(type) {
	case string:
		var err error
		blockCount, err = parseHexUint64(v)
		if err != nil {
			return nil, newRPCError(errCodeInvalidParams, "invalid blockCount: "+err.Error())
		}
	case float64:
		blockCount = uint64(v)
	default:
		return nil, newRPCError(errCodeInvalidParams, "invalid blockCount type")
	}

	// Parse newestBlock (could be "latest", "safe", "finalized", or hex number).
	var newestBlockStr string
	if err := json.Unmarshal(args[1], &newestBlockStr); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid newestBlock: "+err.Error())
	}

	blockNr, err := resolveBlockTag(newestBlockStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid newestBlock: "+err.Error())
	}

	newestBlock, err := s.ethAPI.resolveBlockNumber(blockNr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid newestBlock: "+err.Error())
	}

	return s.ethAPI.FeeHistory(blockCount, newestBlock)
}

// handleWeb3Sha3 parses params for web3_sha3.
func (s *RPCServer) handleWeb3Sha3(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [data]")
	}
	var hexData string
	if err := json.Unmarshal(args[0], &hexData); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hex data: "+err.Error())
	}
	data, err := decodeHexBytes(hexData)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hex encoding: "+err.Error())
	}
	return s.web3API.Sha3(data), nil
}

// handleBsvGetConfirmationStatus parses params for bsv_getConfirmationStatus.
func (s *RPCServer) handleBsvGetConfirmationStatus(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockNumber]")
	}
	var blockTag string
	if err := json.Unmarshal(args[0], &blockTag); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block number: "+err.Error())
	}
	blockNum, err := parseHexUint64(blockTag)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block number: "+err.Error())
	}
	return s.bsvAPI.GetConfirmationStatus(blockNum), nil
}

// handleBsvBuildWithdrawalClaim parses params for bsv_buildWithdrawalClaim.
func (s *RPCServer) handleBsvBuildWithdrawalClaim(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
		return nil, newRPCError(errCodeInvalidParams, "expected [bsvAddress, satoshiAmount, nonce]")
	}
	var bsvAddress string
	if err := json.Unmarshal(args[0], &bsvAddress); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid bsvAddress: "+err.Error())
	}
	var satoshiAmountHex string
	if err := json.Unmarshal(args[1], &satoshiAmountHex); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid satoshiAmount: "+err.Error())
	}
	satoshiAmount, err := parseHexUint64(satoshiAmountHex)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid satoshiAmount: "+err.Error())
	}
	var nonceHex string
	if err := json.Unmarshal(args[2], &nonceHex); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid nonce: "+err.Error())
	}
	nonce, err := parseHexUint64(nonceHex)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid nonce: "+err.Error())
	}
	return s.bsvAPI.BuildWithdrawalClaim(bsvAddress, satoshiAmount, nonce)
}

// handleBsvGetDeposits parses params for bsv_getDeposits.
// Expects [fromBlock, toBlock] as hex-encoded uint64 strings. Both bounds
// are inclusive; pass toBlock = "0x0" to mean "no upper bound".
func (s *RPCServer) handleBsvGetDeposits(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [fromBlock, toBlock]")
	}
	fromBlock, err := parseBlockNumberArg(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid fromBlock: "+err.Error())
	}
	toBlock, err := parseBlockNumberArg(args[1])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid toBlock: "+err.Error())
	}
	return s.bsvAPI.GetDeposits(fromBlock, toBlock), nil
}

// handleBsvGetWithdrawals parses params for bsv_getWithdrawals.
// Expects [fromNonce, toNonce] as hex-encoded uint64 strings. The range
// is half-open [fromNonce, toNonce); pass toNonce = "0x0" to mean "no
// upper bound".
func (s *RPCServer) handleBsvGetWithdrawals(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [fromNonce, toNonce]")
	}
	fromNonce, err := parseBlockNumberArg(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid fromNonce: "+err.Error())
	}
	toNonce, err := parseBlockNumberArg(args[1])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid toNonce: "+err.Error())
	}
	return s.bsvAPI.GetWithdrawals(fromNonce, toNonce), nil
}

// parseBlockNumberArg decodes a hex-encoded uint64 wrapped in a JSON
// string. Used by bsv_getDeposits / bsv_getWithdrawals for their
// range-pair inputs.
func parseBlockNumberArg(raw json.RawMessage) (uint64, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, err
	}
	return parseHexUint64(s)
}

// handleEthGetTransactionByBlockHashAndIndex parses params for
// eth_getTransactionByBlockHashAndIndex.
func (s *RPCServer) handleEthGetTransactionByBlockHashAndIndex(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockHash, index]")
	}
	hash, err := parseHash(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid hash: "+err.Error())
	}
	var indexStr string
	if err := json.Unmarshal(args[1], &indexStr); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid index: "+err.Error())
	}
	index, err := parseHexUint64(indexStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid index: "+err.Error())
	}
	return s.ethAPI.GetTransactionByBlockHashAndIndex(hash, index)
}

// handleEthGetTransactionByBlockNumberAndIndex parses params for
// eth_getTransactionByBlockNumberAndIndex.
func (s *RPCServer) handleEthGetTransactionByBlockNumberAndIndex(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockTag, index]")
	}
	var blockTag string
	if err := json.Unmarshal(args[0], &blockTag); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	blockNr, err := resolveBlockTag(blockTag)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	var indexStr string
	if err := json.Unmarshal(args[1], &indexStr); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid index: "+err.Error())
	}
	index, err := parseHexUint64(indexStr)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid index: "+err.Error())
	}
	return s.ethAPI.GetTransactionByBlockNumberAndIndex(blockNr, index)
}

// handleEthGetProof parses params for eth_getProof (EIP-1186).
func (s *RPCServer) handleEthGetProof(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
		return nil, newRPCError(errCodeInvalidParams, "expected [address, storageKeys, blockTag]")
	}
	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid address: "+err.Error())
	}

	// Parse storage keys array.
	var keyStrs []string
	if err := json.Unmarshal(args[1], &keyStrs); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid storage keys: "+err.Error())
	}
	storageKeys := make([]types.Hash, len(keyStrs))
	for i, k := range keyStrs {
		storageKeys[i] = types.HexToHash(k)
	}

	blockNrOrHash, err := parseBlockNrOrHash(args[2])
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
	}
	return s.ethAPI.GetProof(addr, storageKeys, blockNrOrHash)
}

// handleEthCreateAccessList parses params for eth_createAccessList.
func (s *RPCServer) handleEthCreateAccessList(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [txArgs, blockTag?]")
	}
	var txArgs TransactionArgs
	if err := parseTransactionArgs(args[0], &txArgs); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid tx args: "+err.Error())
	}
	var blockNrOrHash *BlockNumberOrHash
	if len(args) >= 2 {
		bnh, err := parseBlockNrOrHash(args[1])
		if err != nil {
			return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
		}
		blockNrOrHash = &bnh
	}
	return s.ethAPI.CreateAccessList(txArgs, blockNrOrHash)
}

// -- Debug handlers --

// handleDebugTraceTransaction parses params for debug_traceTransaction.
func (s *RPCServer) handleDebugTraceTransaction(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [txHash]")
	}
	var txHash string
	if err := json.Unmarshal(args[0], &txHash); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid tx hash: "+err.Error())
	}
	return s.debugAPI.TraceTransaction(txHash)
}

// handleDebugTraceCall parses params for debug_traceCall.
func (s *RPCServer) handleDebugTraceCall(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [txArgs, blockTag]")
	}
	var txArgs TransactionArgs
	if err := parseTransactionArgs(args[0], &txArgs); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid tx args: "+err.Error())
	}
	blockTag := "latest"
	if len(args) >= 2 {
		if err := json.Unmarshal(args[1], &blockTag); err != nil {
			return nil, newRPCError(errCodeInvalidParams, "invalid block tag: "+err.Error())
		}
	}
	return s.debugAPI.TraceCall(txArgs, blockTag)
}

// handleDebugTraceBlockByNumber parses params for debug_traceBlockByNumber.
func (s *RPCServer) handleDebugTraceBlockByNumber(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockNumber]")
	}
	var blockNr string
	if err := json.Unmarshal(args[0], &blockNr); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block number: "+err.Error())
	}
	return s.debugAPI.TraceBlockByNumber(blockNr)
}

// handleDebugTraceBlockByHash parses params for debug_traceBlockByHash.
func (s *RPCServer) handleDebugTraceBlockByHash(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [blockHash]")
	}
	var blockHash string
	if err := json.Unmarshal(args[0], &blockHash); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid block hash: "+err.Error())
	}
	return s.debugAPI.TraceBlockByHash(blockHash)
}

// -- Helpers --

// resolveBlockTag converts a block tag string to a signed int64 that the
// EthAPI methods understand.
func resolveBlockTag(tag string) (int64, error) {
	switch tag {
	case blockTagLatest, blockTagPending:
		return -1, nil
	case blockTagSafe:
		return -2, nil
	case blockTagFinalized:
		return -3, nil
	case blockTagConfirmed:
		return -4, nil
	case blockTagEarliest:
		return 0, nil
	default:
		n, err := parseHexUint64(tag)
		if err != nil {
			return 0, err
		}
		return int64(n), nil
	}
}

// parseAddress parses a JSON-encoded address string.
func parseAddress(data json.RawMessage) (types.Address, error) {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return types.Address{}, err
	}
	return types.HexToAddress(s), nil
}

// parseHash parses a JSON-encoded hash string.
func parseHash(data json.RawMessage) (types.Hash, error) {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return types.Hash{}, err
	}
	return types.HexToHash(s), nil
}

// parseBlockNrOrHash parses a JSON-encoded block number or hash.
func parseBlockNrOrHash(data json.RawMessage) (BlockNumberOrHash, error) {
	var bnh BlockNumberOrHash
	if err := bnh.UnmarshalJSON(data); err != nil {
		return BlockNumberOrHash{}, err
	}
	return bnh, nil
}

// parseTransactionArgs parses JSON-encoded transaction arguments. Fields that
// use hex-encoded values (gas, gasPrice, value, nonce, data/input) are decoded
// from their hex string representation.
func parseTransactionArgs(data json.RawMessage, out *TransactionArgs) error {
	// Parse using a raw struct to handle hex-encoded fields.
	var raw struct {
		From                 *types.Address `json:"from"`
		To                   *types.Address `json:"to"`
		Gas                  *string        `json:"gas"`
		GasPrice             *string        `json:"gasPrice"`
		MaxFeePerGas         *string        `json:"maxFeePerGas"`
		MaxPriorityFeePerGas *string        `json:"maxPriorityFeePerGas"`
		Value                *string        `json:"value"`
		Data                 *string        `json:"data"`
		Input                *string        `json:"input"`
		Nonce                *string           `json:"nonce"`
		AccessList           *types.AccessList `json:"accessList"`
		ChainID              *string           `json:"chainId"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	out.From = raw.From
	out.To = raw.To

	if raw.Gas != nil {
		g, err := parseHexUint64(*raw.Gas)
		if err != nil {
			return fmt.Errorf("invalid gas: %w", err)
		}
		out.Gas = &g
	}
	if raw.GasPrice != nil {
		v, ok := parseHexBig(*raw.GasPrice)
		if !ok {
			return fmt.Errorf("invalid gasPrice: %s", *raw.GasPrice)
		}
		out.GasPrice = v
	}
	if raw.MaxFeePerGas != nil {
		v, ok := parseHexBig(*raw.MaxFeePerGas)
		if !ok {
			return fmt.Errorf("invalid maxFeePerGas: %s", *raw.MaxFeePerGas)
		}
		out.MaxFeePerGas = v
	}
	if raw.MaxPriorityFeePerGas != nil {
		v, ok := parseHexBig(*raw.MaxPriorityFeePerGas)
		if !ok {
			return fmt.Errorf("invalid maxPriorityFeePerGas: %s", *raw.MaxPriorityFeePerGas)
		}
		out.MaxPriorityFeePerGas = v
	}
	if raw.Value != nil {
		v, ok := parseHexBig(*raw.Value)
		if !ok {
			return fmt.Errorf("invalid value: %s", *raw.Value)
		}
		out.Value = v
	}
	if raw.Data != nil {
		b, err := decodeHexBytes(*raw.Data)
		if err != nil {
			return fmt.Errorf("invalid data: %w", err)
		}
		out.Data = &b
	}
	if raw.Input != nil {
		b, err := decodeHexBytes(*raw.Input)
		if err != nil {
			return fmt.Errorf("invalid input: %w", err)
		}
		out.Input = &b
	}
	if raw.Nonce != nil {
		n, err := parseHexUint64(*raw.Nonce)
		if err != nil {
			return fmt.Errorf("invalid nonce: %w", err)
		}
		out.Nonce = &n
	}
	if raw.AccessList != nil {
		out.AccessList = raw.AccessList
	}
	if raw.ChainID != nil {
		v, ok := parseHexBig(*raw.ChainID)
		if !ok {
			return fmt.Errorf("invalid chainId: %s", *raw.ChainID)
		}
		out.ChainID = v
	}

	return nil
}

// parseFilterQuery parses JSON-encoded filter query parameters.
func parseFilterQuery(data json.RawMessage, out *FilterQuery) error {
	var raw struct {
		FromBlock *string           `json:"fromBlock"`
		ToBlock   *string           `json:"toBlock"`
		Address   json.RawMessage   `json:"address"`
		Topics    []json.RawMessage `json:"topics"`
		BlockHash *types.Hash       `json:"blockHash"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.FromBlock != nil {
		n, err := parseHexUint64(*raw.FromBlock)
		if err == nil {
			out.FromBlock = new(big.Int).SetUint64(n)
		}
	}
	if raw.ToBlock != nil {
		n, err := parseHexUint64(*raw.ToBlock)
		if err == nil {
			out.ToBlock = new(big.Int).SetUint64(n)
		}
	}
	out.BlockHash = raw.BlockHash

	// Parse address (can be a single address or an array).
	if raw.Address != nil {
		trimmed := strings.TrimSpace(string(raw.Address))
		if len(trimmed) > 0 && trimmed != "null" {
			if trimmed[0] == '"' {
				// Single address.
				var addr string
				if err := json.Unmarshal(raw.Address, &addr); err == nil {
					out.Addresses = []types.Address{types.HexToAddress(addr)}
				}
			} else if trimmed[0] == '[' {
				// Array of addresses.
				var addrs []string
				if err := json.Unmarshal(raw.Address, &addrs); err == nil {
					for _, a := range addrs {
						out.Addresses = append(out.Addresses, types.HexToAddress(a))
					}
				}
			}
		}
	}

	// Parse topics.
	for _, topicRaw := range raw.Topics {
		trimmed := strings.TrimSpace(string(topicRaw))
		if trimmed == "null" || len(trimmed) == 0 {
			out.Topics = append(out.Topics, nil) // wildcard
			continue
		}
		if trimmed[0] == '"' {
			// Single topic.
			var t string
			if err := json.Unmarshal(topicRaw, &t); err == nil {
				out.Topics = append(out.Topics, []types.Hash{types.HexToHash(t)})
			}
		} else if trimmed[0] == '[' {
			// Array of topics (OR'd).
			var ts []string
			if err := json.Unmarshal(topicRaw, &ts); err == nil {
				var hashes []types.Hash
				for _, t := range ts {
					hashes = append(hashes, types.HexToHash(t))
				}
				out.Topics = append(out.Topics, hashes)
			}
		}
	}

	return nil
}

// writeJSONResponse writes a JSON-RPC response to the HTTP response writer.
func writeJSONResponse(w http.ResponseWriter, resp *jsonrpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// rateLimiter provides per-IP rate limiting using a token bucket algorithm.
type rateLimiter struct {
	mu             sync.Mutex
	buckets        map[string]*tokenBucket
	ratePerSecond  int
	burstSize      int
}

// tokenBucket is a simple token bucket for rate limiting.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// newRateLimiter creates a new per-IP rate limiter.
func newRateLimiter(ratePerSecond, burstSize int) *rateLimiter {
	if burstSize <= 0 {
		burstSize = ratePerSecond * 2
	}
	return &rateLimiter{
		buckets:       make(map[string]*tokenBucket),
		ratePerSecond: ratePerSecond,
		burstSize:     burstSize,
	}
}

// allow checks if a request from the given IP is allowed.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, ok := rl.buckets[ip]
	if !ok {
		bucket = &tokenBucket{
			tokens:     float64(rl.burstSize),
			maxTokens:  float64(rl.burstSize),
			refillRate: float64(rl.ratePerSecond),
			lastRefill: time.Now(),
		}
		rl.buckets[ip] = bucket
	}

	// Refill tokens based on elapsed time.
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens += elapsed * bucket.refillRate
	if bucket.tokens > bucket.maxTokens {
		bucket.tokens = bucket.maxTokens
	}
	bucket.lastRefill = now

	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// middleware returns an HTTP middleware that rate-limits requests by IP.
func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Strip port from IP.
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		if !rl.allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers to responses.
func (s *RPCServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, origin := range s.config.CORSOrigins {
			if origin == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				break
			}
			if r.Header.Get("Origin") == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
