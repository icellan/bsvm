// Package bsvclient is the production-shippable BSV JSON-RPC client for
// BSVM. It provides an RPCProvider that implements runar.Provider by
// talking directly to a bitcoind-compatible JSON-RPC endpoint (SV Node,
// Teranode, or any node exposing the classic JSON-RPC 1.0 surface).
//
// This is NOT the same as runar/integration/go/helpers. That helpers
// package is a test-only mirror that lives in a separate Go module, uses
// process-global mutable state (env-driven URL, user, password) and
// auto-mines a block after every Broadcast so regtest integration tests
// can make forward progress without a separate mining step. None of
// that is appropriate in a long-running production node.
//
// This implementation is intentionally minimal:
//
//   - No auto-mining on Broadcast. Nodes broadcasting on mainnet or
//     testnet obviously do not mine; even on regtest the caller should
//     drive mining explicitly.
//   - No package-level globals for URL / user / password. Each
//     RPCProvider instance owns its own transport configuration, which
//     makes it safe to run multiple shards pointed at different nodes
//     from the same binary.
//   - Explicit URL + credentials + network per-instance via
//     NewRPCProvider. Basic auth is parsed once from the URL userinfo;
//     if no userinfo is present the requests go out without basic auth
//     (some nodes are open on localhost).
//   - A 30-minute HTTP timeout, matching the helpers.rpcClient timeout.
//     Large Groth16 witness-assisted transactions can spend a long time
//     in the node's script verifier on a loaded box; shorter timeouts
//     cause spurious RPC failures mid-broadcast.
package bsvclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
	runar "github.com/icellan/runar/packages/runar-go"
)

// rpcRequestID is the sole package-level global: a monotonically
// increasing JSON-RPC request identifier shared by all RPCProvider
// instances. Collisions across instances are harmless because responses
// are correlated by the HTTP round-trip, not by id.
var rpcRequestID uint64

// rpcTimeout is the HTTP client timeout. See the package doc for why
// it is deliberately long.
const rpcTimeout = 30 * time.Minute

// RPCProvider implements runar.Provider against a bitcoind-compatible
// JSON-RPC endpoint. Construct via NewRPCProvider.
type RPCProvider struct {
	endpoint string // scheme://host:port/path (userinfo stripped)
	user     string // basic-auth user, empty if none
	pass     string // basic-auth password, empty if none
	hasAuth  bool   // true if basic auth should be attached to requests
	network  string // "regtest" | "testnet" | "mainnet"
	client   *http.Client
}

// NewRPCProvider parses a bitcoin-node JSON-RPC URL of the form
// http://user:pass@host:port/ and returns a provider that satisfies
// runar.Provider.
//
// The network string must be one of "regtest", "testnet", or "mainnet".
// It only drives GetNetwork() and any address-derivation helpers layered
// on top of this provider; the wire traffic to the node is identical
// across networks.
//
// If the URL has userinfo, both user and password are forwarded via
// HTTP basic auth on every request. If the URL has no userinfo, the
// provider issues requests without an Authorization header (some
// localhost regtest setups run open).
func NewRPCProvider(rpcURL, network string) (*RPCProvider, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("bsvclient: rpcURL is required")
	}
	switch network {
	case "regtest", "testnet", "mainnet":
	default:
		return nil, fmt.Errorf("bsvclient: network must be regtest, testnet, or mainnet, got %q", network)
	}

	parsed, err := url.Parse(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("bsvclient: parse rpcURL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("bsvclient: rpcURL scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("bsvclient: rpcURL has no host: %q", rpcURL)
	}

	var user, pass string
	hasAuth := false
	if parsed.User != nil {
		user = parsed.User.Username()
		if p, ok := parsed.User.Password(); ok {
			pass = p
		}
		hasAuth = true
	}

	// Rebuild the endpoint without userinfo; we attach credentials via
	// req.SetBasicAuth so they never end up in logs as part of the URL.
	stripped := *parsed
	stripped.User = nil

	return &RPCProvider{
		endpoint: stripped.String(),
		user:     user,
		pass:     pass,
		hasAuth:  hasAuth,
		network:  network,
		client:   &http.Client{Timeout: rpcTimeout},
	}, nil
}

// ---------------------------------------------------------------------
// JSON-RPC transport
// ---------------------------------------------------------------------

type rpcRequestEnvelope struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      uint64        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResponseEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcErrorBody   `json:"error"`
}

type rpcErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// call issues a single JSON-RPC 1.0 request to the node and returns the
// raw result payload. Modelled on helpers.RPCCall but bound to this
// instance's endpoint and credentials.
func (p *RPCProvider) call(method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}
	body, err := json.Marshal(rpcRequestEnvelope{
		JSONRPC: "1.0",
		ID:      atomic.AddUint64(&rpcRequestID, 1),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, fmt.Errorf("bsvclient: marshal %s request: %w", method, err)
	}

	req, err := http.NewRequest(http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("bsvclient: build %s request: %w", method, err)
	}
	if p.hasAuth {
		req.SetBasicAuth(p.user, p.pass)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bsvclient: %s connection failed: %w", method, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bsvclient: %s read body: %w", method, err)
	}

	var envelope rpcResponseEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("bsvclient: %s response parse error: %w (body: %s)", method, err, string(respBody))
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("bsvclient: %s RPC error %d: %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	return envelope.Result, nil
}

// Call performs a raw JSON-RPC call against the underlying BSV node.
// Exposed for dev/regtest ops like generatetoaddress, sendtoaddress,
// importaddress — anything the Provider interface doesn't cover.
// Production code should prefer the typed Provider methods; this
// escape hatch exists so cmd/bsvm devnet bootstrap can drive the
// regtest node without carrying its own RPC transport.
func (p *RPCProvider) Call(method string, params ...interface{}) (json.RawMessage, error) {
	return p.call(method, params...)
}

// ---------------------------------------------------------------------
// runar.Provider implementation
// ---------------------------------------------------------------------

// GetTransaction fetches a transaction by txid and maps the verbose
// getrawtransaction response into a runar.TransactionData. Only the
// fields the Rúnar SDK actually reads (Raw, Version, Outputs) are
// populated; Inputs and Locktime are left zero because no current
// codepath needs them.
func (p *RPCProvider) GetTransaction(txid string) (*runar.TransactionData, error) {
	raw, err := p.GetRawTransactionVerbose(txid)
	if err != nil {
		return nil, err
	}
	rawHex, _ := raw["hex"].(string)

	var outputs []runar.TxOutput
	if vout, ok := raw["vout"].([]interface{}); ok {
		for _, o := range vout {
			om, _ := o.(map[string]interface{})
			valBTC, _ := om["value"].(float64)
			// The node reports BSV amounts in decimal BSV (same as BTC
			// conventions). Round to the nearest satoshi to avoid
			// float drift for round-number values.
			sats := int64(math.Round(valBTC * 1e8))
			scriptHex := ""
			if sp, ok := om["scriptPubKey"].(map[string]interface{}); ok {
				scriptHex, _ = sp["hex"].(string)
			}
			outputs = append(outputs, runar.TxOutput{
				Satoshis: sats,
				Script:   scriptHex,
			})
		}
	}

	return &runar.TransactionData{
		Txid:    txid,
		Version: 1,
		Outputs: outputs,
		Raw:     rawHex,
	}, nil
}

// Broadcast submits a fully signed transaction via sendrawtransaction
// and returns the node-reported txid. Unlike the test helper, this
// method does NOT auto-mine — mining is outside the responsibility of
// a production broadcast path.
func (p *RPCProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	rawTx := tx.Hex()
	result, err := p.call("sendrawtransaction", rawTx)
	if err != nil {
		return "", fmt.Errorf("bsvclient: sendrawtransaction: %w", err)
	}
	var txid string
	if err := json.Unmarshal(result, &txid); err != nil {
		return "", fmt.Errorf("bsvclient: sendrawtransaction result: %w", err)
	}
	return txid, nil
}

// GetUtxos returns all UTXOs currently reported by the node's wallet
// for the given address via listunspent. The node's wallet must have
// the address imported / watched for this to return anything; that is
// the caller's concern.
func (p *RPCProvider) GetUtxos(address string) ([]runar.UTXO, error) {
	result, err := p.call("listunspent", 0, 9999999, []string{address})
	if err != nil {
		return nil, fmt.Errorf("bsvclient: listunspent: %w", err)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(result, &rows); err != nil {
		return nil, fmt.Errorf("bsvclient: listunspent parse: %w", err)
	}

	utxos := make([]runar.UTXO, 0, len(rows))
	for _, u := range rows {
		txid, _ := u["txid"].(string)
		vout, _ := u["vout"].(float64)
		amount, _ := u["amount"].(float64)
		scriptPubKey, _ := u["scriptPubKey"].(string)
		utxos = append(utxos, runar.UTXO{
			Txid:        txid,
			OutputIndex: int(vout),
			Satoshis:    int64(math.Round(amount * 1e8)),
			Script:      scriptPubKey,
		})
	}
	return utxos, nil
}

// GetContractUtxo is not supported over plain JSON-RPC. The node has no
// index of "UTXOs by scriptHash" that would let us serve this query
// without a separate overlay / indexer. Rúnar's SDK only consults
// GetContractUtxo for stateful-contract discovery; BSVM's broadcast
// path never hits that branch, so we return a clear error rather than
// silently returning nil.
func (p *RPCProvider) GetContractUtxo(scriptHash string) (*runar.UTXO, error) {
	return nil, fmt.Errorf("bsvclient: GetContractUtxo not supported in RPC mode")
}

// GetNetwork returns the network string configured on this provider.
func (p *RPCProvider) GetNetwork() string {
	return p.network
}

// GetFeeRate returns the fee rate in satoshis per KB. The current
// implementation returns 1 sat/KB (well below the BSV default of 100
// sat/KB) because that is the regtest default every test in the
// integration suite assumes.
//
// TODO: once a production node config surface lands (e.g. a
// BSVM_BSV_FEE_RATE env var or equivalent) this should read from it so
// testnet / mainnet shards can advertise a realistic rate. Not
// required for Phase 3a.
func (p *RPCProvider) GetFeeRate() (int64, error) {
	return 1, nil
}

// GetRawTransaction returns only the raw hex of a transaction. Callers
// that need the full verbose body (e.g. to inspect confirmations)
// should call GetRawTransactionVerbose instead.
func (p *RPCProvider) GetRawTransaction(txid string) (string, error) {
	raw, err := p.GetRawTransactionVerbose(txid)
	if err != nil {
		return "", err
	}
	rawHex, _ := raw["hex"].(string)
	return rawHex, nil
}

// ---------------------------------------------------------------------
// Non-interface extras
// ---------------------------------------------------------------------

// GetRawTransactionVerbose returns the full verbose getrawtransaction
// result map, including the `confirmations` field. The standard
// Provider.GetRawTransaction API only returns hex; this method lets
// callers check confirmation count without a second RPC call.
//
// Uses int 1 (not bool true) for verbose — Teranode requires the int
// form.
func (p *RPCProvider) GetRawTransactionVerbose(txid string) (map[string]interface{}, error) {
	result, err := p.call("getrawtransaction", txid, 1)
	if err != nil {
		return nil, fmt.Errorf("bsvclient: getrawtransaction: %w", err)
	}
	var tx map[string]interface{}
	if err := json.Unmarshal(result, &tx); err != nil {
		return nil, fmt.Errorf("bsvclient: getrawtransaction parse: %w", err)
	}
	return tx, nil
}

// compile-time check that RPCProvider satisfies runar.Provider.
var _ runar.Provider = (*RPCProvider)(nil)
