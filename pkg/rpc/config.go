package rpc

import "time"

// RPCConfig holds configuration for the JSON-RPC server.
type RPCConfig struct {
	// HTTPAddr is the address to listen on for HTTP JSON-RPC requests.
	// Example: "0.0.0.0:8545"
	HTTPAddr string

	// WSAddr is the address to listen on for WebSocket JSON-RPC requests.
	// Example: "0.0.0.0:8546"
	WSAddr string

	// CORSOrigins is a list of allowed CORS origins. An empty list
	// disables CORS. Use ["*"] to allow all origins.
	CORSOrigins []string

	// MaxConns is the maximum number of simultaneous connections.
	// Zero means unlimited.
	MaxConns int

	// RequestsPerSecond is the per-IP rate limit for incoming requests.
	// Zero disables rate limiting.
	RequestsPerSecond int

	// BurstSize is the maximum burst size for rate limiting.
	BurstSize int

	// WSMaxConnections is the maximum number of concurrent WebSocket
	// connections. Zero means unlimited.
	WSMaxConnections int `json:"ws_max_connections"`

	// WSMaxSubscriptionsPerConn is the maximum number of subscriptions
	// allowed per single WebSocket connection.
	WSMaxSubscriptionsPerConn int `json:"ws_max_subscriptions_per_conn"`

	// WSEventQueueDepth is the size of the per-connection buffered event
	// channel. Events are dropped when the buffer is full.
	WSEventQueueDepth int `json:"ws_event_queue_depth"`

	// WSSlowConsumerTimeout is the maximum duration to wait when writing
	// to a slow consumer before dropping the event.
	WSSlowConsumerTimeout time.Duration `json:"ws_slow_consumer_timeout"`

	// GetLogsMaxRange is the maximum inclusive block range allowed for a
	// single eth_getLogs call (to - from + 1). Zero means unlimited, which
	// is discouraged — DefaultRPCConfig seeds a conservative cap.
	GetLogsMaxRange uint64 `json:"get_logs_max_range"`
}

// DefaultRPCConfig returns an RPCConfig with sensible defaults.
//
// CORSOrigins defaults to an empty slice: cross-origin access must be an
// explicit opt-in decision by the operator. A wildcard ("*") origin is a
// legitimate choice for local development but should never be a library
// default.
func DefaultRPCConfig() RPCConfig {
	return RPCConfig{
		HTTPAddr:                  "0.0.0.0:8545",
		WSAddr:                    "0.0.0.0:8546",
		CORSOrigins:               []string{},
		MaxConns:                  1000,
		RequestsPerSecond:         100,
		BurstSize:                 200,
		WSMaxConnections:          1000,
		WSMaxSubscriptionsPerConn: 100,
		WSEventQueueDepth:         1000,
		WSSlowConsumerTimeout:     30 * time.Second,
		GetLogsMaxRange:           1000,
	}
}
