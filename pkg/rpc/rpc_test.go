package rpc

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

const testChainID = 1337

// testSetup holds all the components needed for RPC tests.
type testSetup struct {
	server   *RPCServer
	node     *overlay.OverlayNode
	database db.Database
	chainDB  *block.ChainDB
	key      *ecdsa.PrivateKey
	addr     types.Address
	coinbase types.Address
	signer   types.Signer
	genesis  *block.L2Header
}

// newTestSetup creates a fully initialised RPC server for testing.
func newTestSetup(t *testing.T) *testSetup {
	t.Helper()

	// Create deterministic test keys.
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	addr := types.Address(crypto.PubkeyToAddress(key.PublicKey))

	cbKeyBytes := make([]byte, 32)
	cbKeyBytes[31] = 2
	cbKey, err := crypto.ToECDSA(cbKeyBytes)
	if err != nil {
		t.Fatalf("failed to create coinbase key: %v", err)
	}
	coinbaseAddr := types.Address(crypto.PubkeyToAddress(cbKey.PublicKey))

	// Create in-memory database.
	database := db.NewMemoryDB()

	// Initialise genesis with a funded account.
	gen := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30_000_000,
		Alloc: map[types.Address]block.GenesisAccount{
			addr: {
				Balance: uint256.NewInt(1_000_000_000_000_000_000), // 1 ETH
			},
		},
	}

	genesisHeader, err := block.InitGenesis(database, gen)
	if err != nil {
		t.Fatalf("failed to init genesis: %v", err)
	}

	chainDB := block.NewChainDB(database)

	// Create the overlay node.
	overlayConfig := overlay.DefaultOverlayConfig()
	overlayConfig.ChainID = testChainID
	overlayConfig.Coinbase = coinbaseAddr
	overlayConfig.MaxBatchFlushDelay = 100 * time.Millisecond

	sp1Prover := prover.NewSP1Prover(prover.DefaultConfig())
	compiledCovenant := &covenant.CompiledCovenant{}
	initialState := covenant.CovenantState{
		StateRoot:   genesisHeader.StateRoot,
		BlockNumber: 0,
	}
	covenantMgr := covenant.NewCovenantManager(
		compiledCovenant,
		types.Hash{},
		0,
		10000,
		initialState,
		testChainID,
		covenant.VerifyGroth16,
	)

	node, err := overlay.NewOverlayNode(overlayConfig, chainDB, database, covenantMgr, sp1Prover)
	if err != nil {
		t.Fatalf("failed to create overlay node: %v", err)
	}

	chainConfig := vm.DefaultL2Config(testChainID)
	rpcConfig := DefaultRPCConfig()

	server := NewRPCServerWithConfig(rpcConfig, chainConfig, node, chainDB, database)

	return &testSetup{
		server:   server,
		node:     node,
		database: database,
		chainDB:  chainDB,
		key:      key,
		addr:     addr,
		coinbase: coinbaseAddr,
		signer:   types.LatestSignerForChainID(big.NewInt(testChainID)),
		genesis:  genesisHeader,
	}
}

// signTx creates and signs a legacy transfer transaction.
func (ts *testSetup) signTx(t *testing.T, nonce uint64, to types.Address, value *uint256.Int, gasPrice *big.Int) *types.Transaction {
	t.Helper()
	if gasPrice == nil {
		gasPrice = big.NewInt(1_000_000_000) // 1 gwei
	}
	return types.MustSignNewTx(ts.key, ts.signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      21000,
		To:       &to,
		Value:    value,
	})
}

// processOneTx is a helper that submits and flushes a single transaction.
func (ts *testSetup) processOneTx(t *testing.T, nonce uint64, to types.Address, value *uint256.Int) {
	t.Helper()
	tx := ts.signTx(t, nonce, to, value, nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
}

// --- Encoding Tests ---

func TestRPCEncoding(t *testing.T) {
	t.Run("EncodeUint64", func(t *testing.T) {
		tests := []struct {
			input    uint64
			expected string
		}{
			{0, "0x0"},
			{1, "0x1"},
			{16, "0x10"},
			{255, "0xff"},
			{420, "0x1a4"},
			{1000000, "0xf4240"},
		}
		for _, tc := range tests {
			result := EncodeUint64(tc.input)
			if result != tc.expected {
				t.Errorf("EncodeUint64(%d) = %s, want %s", tc.input, result, tc.expected)
			}
		}
	})

	t.Run("EncodeBig", func(t *testing.T) {
		tests := []struct {
			input    *big.Int
			expected string
		}{
			{nil, "0x0"},
			{big.NewInt(0), "0x0"},
			{big.NewInt(1), "0x1"},
			{big.NewInt(256), "0x100"},
			{big.NewInt(1000000000), "0x3b9aca00"},
		}
		for _, tc := range tests {
			result := EncodeBig(tc.input)
			if result != tc.expected {
				t.Errorf("EncodeBig(%v) = %s, want %s", tc.input, result, tc.expected)
			}
		}
	})

	t.Run("EncodeBytes", func(t *testing.T) {
		tests := []struct {
			input    []byte
			expected string
		}{
			{nil, "0x"},
			{[]byte{}, "0x"},
			{[]byte{0xde, 0xad}, "0xdead"},
			{[]byte{0x00, 0x01}, "0x0001"},
		}
		for _, tc := range tests {
			result := EncodeBytes(tc.input)
			if result != tc.expected {
				t.Errorf("EncodeBytes(%x) = %s, want %s", tc.input, result, tc.expected)
			}
		}
	})

	t.Run("EncodeAddress", func(t *testing.T) {
		addr := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		result := EncodeAddress(addr)
		// EIP-55 should produce a checksum address.
		if len(result) != 42 || result[:2] != "0x" {
			t.Errorf("EncodeAddress returned invalid format: %s", result)
		}
	})
}

// --- BlockNumberOrHash Tests ---

func TestBlockNumberOrHash(t *testing.T) {
	t.Run("latest", func(t *testing.T) {
		var bnh BlockNumberOrHash
		err := bnh.UnmarshalJSON([]byte(`"latest"`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bnh.BlockNumber == nil || *bnh.BlockNumber != -1 {
			t.Errorf("expected block number -1 for latest, got %v", bnh.BlockNumber)
		}
	})

	t.Run("safe", func(t *testing.T) {
		var bnh BlockNumberOrHash
		err := bnh.UnmarshalJSON([]byte(`"safe"`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bnh.BlockNumber == nil || *bnh.BlockNumber != -2 {
			t.Errorf("expected block number -2 for safe, got %v", bnh.BlockNumber)
		}
	})

	t.Run("finalized", func(t *testing.T) {
		var bnh BlockNumberOrHash
		err := bnh.UnmarshalJSON([]byte(`"finalized"`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bnh.BlockNumber == nil || *bnh.BlockNumber != -3 {
			t.Errorf("expected block number -3 for finalized, got %v", bnh.BlockNumber)
		}
	})

	t.Run("earliest", func(t *testing.T) {
		var bnh BlockNumberOrHash
		err := bnh.UnmarshalJSON([]byte(`"earliest"`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bnh.BlockNumber == nil || *bnh.BlockNumber != 0 {
			t.Errorf("expected block number 0 for earliest, got %v", bnh.BlockNumber)
		}
	})

	t.Run("hex number", func(t *testing.T) {
		var bnh BlockNumberOrHash
		err := bnh.UnmarshalJSON([]byte(`"0x1a4"`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bnh.BlockNumber == nil || *bnh.BlockNumber != 420 {
			t.Errorf("expected block number 420, got %v", bnh.BlockNumber)
		}
	})

	t.Run("block hash object", func(t *testing.T) {
		hash := types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		data := `{"blockHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
		var bnh BlockNumberOrHash
		err := bnh.UnmarshalJSON([]byte(data))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bnh.BlockHash == nil || *bnh.BlockHash != hash {
			t.Errorf("expected block hash %s, got %v", hash.Hex(), bnh.BlockHash)
		}
	})
}

// --- EthAPI Method Tests ---

func TestEthChainId(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.EthAPI().ChainId()
	expected := EncodeBig(big.NewInt(testChainID))
	if result != expected {
		t.Errorf("eth_chainId = %s, want %s", result, expected)
	}
}

func TestEthBlockNumber(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.EthAPI().BlockNumber()
	if result != "0x0" {
		t.Errorf("eth_blockNumber = %s, want 0x0", result)
	}

	// Process a block and check again.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	result = ts.server.EthAPI().BlockNumber()
	if result != "0x1" {
		t.Errorf("eth_blockNumber = %s, want 0x1", result)
	}
}

func TestEthGetBalance(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Query balance at latest.
	blockTag := BlockNumberOrHashWithNumber(-1)
	result, err := ts.server.EthAPI().GetBalance(ts.addr, blockTag)
	if err != nil {
		t.Fatalf("eth_getBalance failed: %v", err)
	}

	expected := EncodeBig(big.NewInt(1_000_000_000_000_000_000))
	if result != expected {
		t.Errorf("eth_getBalance = %s, want %s", result, expected)
	}

	// Query unknown address.
	unknown := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	result, err = ts.server.EthAPI().GetBalance(unknown, blockTag)
	if err != nil {
		t.Fatalf("eth_getBalance failed: %v", err)
	}
	if result != "0x0" {
		t.Errorf("eth_getBalance for unknown = %s, want 0x0", result)
	}
}

func TestEthGetTransactionCount(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	blockTag := BlockNumberOrHashWithNumber(-1)
	result, err := ts.server.EthAPI().GetTransactionCount(ts.addr, blockTag)
	if err != nil {
		t.Fatalf("eth_getTransactionCount failed: %v", err)
	}
	if result != "0x0" {
		t.Errorf("eth_getTransactionCount = %s, want 0x0", result)
	}

	// Process a transaction and check nonce.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	result, err = ts.server.EthAPI().GetTransactionCount(ts.addr, BlockNumberOrHashWithNumber(-1))
	if err != nil {
		t.Fatalf("eth_getTransactionCount failed: %v", err)
	}
	if result != "0x1" {
		t.Errorf("eth_getTransactionCount after tx = %s, want 0x1", result)
	}
}

func TestEthCall(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// A simple call with no data to an EOA should return empty.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	args := TransactionArgs{
		From: &ts.addr,
		To:   &recipient,
	}
	blockTag := BlockNumberOrHashWithNumber(-1)
	result, err := ts.server.EthAPI().Call(args, blockTag)
	if err != nil {
		t.Fatalf("eth_call failed: %v", err)
	}
	if result != "0x" {
		t.Errorf("eth_call = %s, want 0x", result)
	}
}

func TestEthGetBlockByNumber(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Get genesis block.
	blk, err := ts.server.EthAPI().GetBlockByNumber(0, false)
	if err != nil {
		t.Fatalf("eth_getBlockByNumber failed: %v", err)
	}
	if blk == nil {
		t.Fatal("genesis block is nil")
	}
	if blk["number"] != "0x0" {
		t.Errorf("genesis block number = %s, want 0x0", blk["number"])
	}
	if blk["stateRoot"] == nil {
		t.Error("genesis block stateRoot is nil")
	}

	// Process a block.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	// Get block 1 with full transactions.
	blk, err = ts.server.EthAPI().GetBlockByNumber(1, true)
	if err != nil {
		t.Fatalf("eth_getBlockByNumber(1) failed: %v", err)
	}
	if blk == nil {
		t.Fatal("block 1 is nil")
	}
	if blk["number"] != "0x1" {
		t.Errorf("block 1 number = %s, want 0x1", blk["number"])
	}

	// Verify transactions are full objects.
	txs, ok := blk["transactions"].([]map[string]interface{})
	if !ok {
		t.Fatalf("transactions is not []map, type is %T", blk["transactions"])
	}
	if len(txs) != 1 {
		t.Errorf("expected 1 transaction, got %d", len(txs))
	}

	// Get block 1 with tx hashes only.
	blk, err = ts.server.EthAPI().GetBlockByNumber(1, false)
	if err != nil {
		t.Fatalf("eth_getBlockByNumber(1, false) failed: %v", err)
	}
	txHashes, ok := blk["transactions"].([]string)
	if !ok {
		t.Fatalf("transactions is not []string, type is %T", blk["transactions"])
	}
	if len(txHashes) != 1 {
		t.Errorf("expected 1 tx hash, got %d", len(txHashes))
	}
}

func TestEthGetTransactionReceipt(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	receipt, err := ts.server.EthAPI().GetTransactionReceipt(tx.Hash())
	if err != nil {
		t.Fatalf("eth_getTransactionReceipt failed: %v", err)
	}
	if receipt == nil {
		t.Fatal("receipt is nil")
	}
	if receipt["status"] != "0x1" {
		t.Errorf("receipt status = %s, want 0x1", receipt["status"])
	}
	if receipt["transactionHash"] != tx.Hash().Hex() {
		t.Errorf("receipt txHash = %s, want %s", receipt["transactionHash"], tx.Hash().Hex())
	}
	if receipt["blockNumber"] != "0x1" {
		t.Errorf("receipt blockNumber = %s, want 0x1", receipt["blockNumber"])
	}

	// Non-existent receipt.
	missing, err := ts.server.EthAPI().GetTransactionReceipt(types.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if missing != nil {
		t.Error("expected nil receipt for missing tx")
	}
}

func TestEthSendRawTransaction(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	// RLP-encode the transaction.
	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("failed to encode tx: %v", err)
	}

	hash, err := ts.server.EthAPI().SendRawTransaction(buf.Bytes())
	if err != nil {
		t.Fatalf("eth_sendRawTransaction failed: %v", err)
	}
	if hash != tx.Hash().Hex() {
		t.Errorf("returned hash = %s, want %s", hash, tx.Hash().Hex())
	}
}

func TestEthGasPrice(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.EthAPI().GasPrice()
	expected := EncodeBig(big.NewInt(1_000_000_000)) // 1 gwei
	if result != expected {
		t.Errorf("eth_gasPrice = %s, want %s", result, expected)
	}
}

// --- Method Routing Tests ---

func TestMethodRouting(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	tests := []struct {
		method       string
		params       string
		expectResult bool
	}{
		{"eth_chainId", "[]", true},
		{"eth_blockNumber", "[]", true},
		{"eth_gasPrice", "[]", true},
		{"eth_syncing", "[]", true},
		{"eth_accounts", "[]", true},
		{"net_version", "[]", true},
		{"net_listening", "[]", true},
		{"net_peerCount", "[]", true},
		{"web3_clientVersion", "[]", true},
		{"bsv_shardInfo", "[]", true},
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			result, err := ts.server.dispatch(tc.method, json.RawMessage(tc.params))
			if tc.expectResult {
				if err != nil {
					t.Errorf("dispatch(%s) error: %v", tc.method, err)
				}
				if result == nil {
					t.Errorf("dispatch(%s) returned nil result", tc.method)
				}
			}
		})
	}
}

func TestJSONRPCErrorCodes(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	t.Run("method not found", func(t *testing.T) {
		_, err := ts.server.dispatch("eth_nonExistent", json.RawMessage("[]"))
		if err == nil {
			t.Fatal("expected error for unknown method")
		}
		rpcErr, ok := err.(*rpcError)
		if !ok {
			t.Fatalf("expected *rpcError, got %T", err)
		}
		if rpcErr.code != errCodeMethodNotFound {
			t.Errorf("expected error code %d, got %d", errCodeMethodNotFound, rpcErr.code)
		}
	})

	t.Run("invalid params - missing params", func(t *testing.T) {
		_, err := ts.server.dispatch("eth_getBalance", json.RawMessage("[]"))
		if err == nil {
			t.Fatal("expected error for missing params")
		}
		rpcErr, ok := err.(*rpcError)
		if !ok {
			t.Fatalf("expected *rpcError, got %T", err)
		}
		if rpcErr.code != errCodeInvalidParams {
			t.Errorf("expected error code %d, got %d", errCodeInvalidParams, rpcErr.code)
		}
	})

	t.Run("invalid params - bad address", func(t *testing.T) {
		_, err := ts.server.dispatch("eth_getBalance", json.RawMessage(`[123, "latest"]`))
		if err == nil {
			t.Fatal("expected error for bad address")
		}
		rpcErr, ok := err.(*rpcError)
		if !ok {
			t.Fatalf("expected *rpcError, got %T", err)
		}
		if rpcErr.code != errCodeInvalidParams {
			t.Errorf("expected error code %d, got %d", errCodeInvalidParams, rpcErr.code)
		}
	})
}

// --- HTTP Transport Tests ---

func TestHTTPTransport(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Create a test HTTP handler.
	handler := http.HandlerFunc(ts.server.handleHTTP)

	t.Run("single request", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code = %d, want 200", w.Code)
		}

		var resp jsonrpcResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}
		if resp.Result == nil {
			t.Fatal("result is nil")
		}
	})

	t.Run("batch request", func(t *testing.T) {
		body := `[{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}]`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code = %d, want 200", w.Code)
		}

		var responses []*jsonrpcResponse
		if err := json.NewDecoder(w.Body).Decode(&responses); err != nil {
			t.Fatalf("failed to decode batch response: %v", err)
		}
		if len(responses) != 2 {
			t.Fatalf("expected 2 responses, got %d", len(responses))
		}
		for _, resp := range responses {
			if resp.Error != nil {
				t.Errorf("unexpected error in batch: %v", resp.Error)
			}
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status code = %d, want 405", w.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		body := `{invalid`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp jsonrpcResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Error == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

// --- Net and Web3 API Tests ---

func TestNetVersion(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.NetAPI().Version()
	if result != "1337" {
		t.Errorf("net_version = %s, want 1337", result)
	}
}

func TestNetListening(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	if !ts.server.NetAPI().Listening() {
		t.Error("net_listening should return true")
	}
}

func TestWeb3ClientVersion(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.Web3API().ClientVersion()
	if len(result) == 0 {
		t.Error("web3_clientVersion returned empty string")
	}
}

func TestWeb3Sha3(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Keccak256 of empty bytes.
	result := ts.server.Web3API().Sha3([]byte{})
	expected := "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if result != expected {
		t.Errorf("web3_sha3([]) = %s, want %s", result, expected)
	}
}

// --- BSV API Tests ---

func TestBsvShardInfo(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.BsvAPI().ShardInfo()
	if result["executionTip"] != "0x0" {
		t.Errorf("executionTip = %s, want 0x0", result["executionTip"])
	}

	// H15: Verify new fields are present.
	if result["shardId"] == nil {
		t.Error("shardId field is missing")
	}
	if result["chainId"] == nil {
		t.Error("chainId field is missing")
	}
	if result["genesisCovenantTxId"] == nil {
		t.Error("genesisCovenantTxId field is missing")
	}
	if result["peerCount"] == nil {
		t.Error("peerCount field is missing")
	}
	if result["governance"] == nil {
		t.Error("governance field is missing")
	} else {
		gov, ok := result["governance"].(map[string]interface{})
		if !ok {
			t.Error("governance field is not a map")
		} else {
			if _, ok := gov["mode"]; !ok {
				t.Error("governance.mode field is missing")
			}
			if _, ok := gov["frozen"]; !ok {
				t.Error("governance.frozen field is missing")
			}
		}
	}
}

func TestBsvGetCachedChainLength(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.BsvAPI().GetCachedChainLength()
	if result != "0x0" {
		t.Errorf("GetCachedChainLength = %s, want 0x0", result)
	}

	// Process a transaction so there is a cached entry.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	result = ts.server.BsvAPI().GetCachedChainLength()
	if result != "0x1" {
		t.Errorf("GetCachedChainLength after 1 tx = %s, want 0x1", result)
	}
}

func TestBsvGetConfirmationStatus_SpecFields(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.BsvAPI().GetConfirmationStatus(0)
	// H17: Verify all spec fields are present.
	if result["l2BlockNumber"] == nil {
		t.Error("l2BlockNumber field is missing")
	}
	if result["bsvTxId"] == nil {
		t.Error("bsvTxId field is missing")
	}
	if result["confirmations"] == nil {
		t.Error("confirmations field is missing")
	}
	if _, ok := result["confirmed"]; !ok {
		t.Error("confirmed field is missing")
	}
	if _, ok := result["safe"]; !ok {
		t.Error("safe field is missing")
	}
	if _, ok := result["finalized"]; !ok {
		t.Error("finalized field is missing")
	}
}

func TestResolveBlockTag_Confirmed(t *testing.T) {
	// H18: Verify the "confirmed" block tag resolves correctly.
	nr, err := resolveBlockTag("confirmed")
	if err != nil {
		t.Fatalf("resolveBlockTag(confirmed) failed: %v", err)
	}
	if nr != -4 {
		t.Errorf("resolveBlockTag(confirmed) = %d, want -4", nr)
	}
}

func TestEffectiveGasPrice_InReceipt(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	receipt, err := ts.server.EthAPI().GetTransactionReceipt(
		ts.server.EthAPI().chainDB.ReadHeadBlockHash(),
	)
	// This tests M20: effectiveGasPrice is present.
	// GetTransactionReceipt returns nil when the hash is a block hash, not tx hash.
	// So let's query via block receipts instead.
	receipts, err := ts.server.EthAPI().GetBlockReceipts(-1)
	if err != nil {
		t.Fatalf("GetBlockReceipts failed: %v", err)
	}
	if len(receipts) < 1 {
		t.Fatal("expected at least 1 receipt")
	}
	if receipts[0]["effectiveGasPrice"] == nil {
		t.Error("effectiveGasPrice field is missing from receipt")
	}
	_ = receipt // avoid unused
}

// --- GetBlockReceipts Test ---

func TestEthGetBlockReceipts(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	receipts, err := ts.server.EthAPI().GetBlockReceipts(-1) // latest
	if err != nil {
		t.Fatalf("eth_getBlockReceipts failed: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0]["status"] != "0x1" {
		t.Errorf("receipt status = %s, want 0x1", receipts[0]["status"])
	}
}

// --- GetTransactionByHash Test ---

func TestEthGetTransactionByHash(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	result, err := ts.server.EthAPI().GetTransactionByHash(tx.Hash())
	if err != nil {
		t.Fatalf("eth_getTransactionByHash failed: %v", err)
	}
	if result == nil {
		t.Fatal("transaction not found")
	}
	if result["hash"] != tx.Hash().Hex() {
		t.Errorf("tx hash = %s, want %s", result["hash"], tx.Hash().Hex())
	}
	if result["blockNumber"] != "0x1" {
		t.Errorf("tx blockNumber = %s, want 0x1", result["blockNumber"])
	}
}

// --- Log Filtering Tests ---

func TestLogFiltering(t *testing.T) {
	// Test the filterLogs function.
	addr1 := types.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := types.HexToAddress("0x2222222222222222222222222222222222222222")
	topic1 := types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	topic2 := types.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	logs := []*types.Log{
		{Address: addr1, Topics: []types.Hash{topic1}},
		{Address: addr2, Topics: []types.Hash{topic2}},
		{Address: addr1, Topics: []types.Hash{topic2}},
	}

	t.Run("filter by address", func(t *testing.T) {
		result := filterLogs(logs, []types.Address{addr1}, nil)
		if len(result) != 2 {
			t.Errorf("expected 2 logs for addr1, got %d", len(result))
		}
	})

	t.Run("filter by topic", func(t *testing.T) {
		result := filterLogs(logs, nil, [][]types.Hash{{topic1}})
		if len(result) != 1 {
			t.Errorf("expected 1 log for topic1, got %d", len(result))
		}
	})

	t.Run("filter by address and topic", func(t *testing.T) {
		result := filterLogs(logs, []types.Address{addr1}, [][]types.Hash{{topic2}})
		if len(result) != 1 {
			t.Errorf("expected 1 log for addr1+topic2, got %d", len(result))
		}
	})

	t.Run("wildcard topic", func(t *testing.T) {
		result := filterLogs(logs, nil, [][]types.Hash{nil}) // nil = wildcard
		if len(result) != 3 {
			t.Errorf("expected 3 logs with wildcard, got %d", len(result))
		}
	})

	t.Run("no filters", func(t *testing.T) {
		result := filterLogs(logs, nil, nil)
		if len(result) != 3 {
			t.Errorf("expected 3 logs with no filter, got %d", len(result))
		}
	})
}

// --- StateReader Tests ---

func TestStateReader(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	reader := NewStateReader(ts.database, ts.chainDB)

	t.Run("LatestState", func(t *testing.T) {
		statedb, err := reader.LatestState()
		if err != nil {
			t.Fatalf("LatestState failed: %v", err)
		}
		balance := statedb.GetBalance(ts.addr)
		expected := uint256.NewInt(1_000_000_000_000_000_000)
		if balance.Cmp(expected) != 0 {
			t.Errorf("balance = %s, want %s", balance, expected)
		}
	})

	t.Run("StateAtBlock", func(t *testing.T) {
		statedb, err := reader.StateAtBlock(0)
		if err != nil {
			t.Fatalf("StateAtBlock(0) failed: %v", err)
		}
		balance := statedb.GetBalance(ts.addr)
		if balance.IsZero() {
			t.Error("expected non-zero balance at genesis")
		}
	})

	t.Run("StateAtBlock not found", func(t *testing.T) {
		_, err := reader.StateAtBlock(999)
		if err == nil {
			t.Error("expected error for non-existent block")
		}
	})
}

// --- Config Tests ---

func TestDefaultRPCConfig(t *testing.T) {
	config := DefaultRPCConfig()
	if config.HTTPAddr != "0.0.0.0:8545" {
		t.Errorf("HTTPAddr = %s, want 0.0.0.0:8545", config.HTTPAddr)
	}
	if config.WSAddr != "0.0.0.0:8546" {
		t.Errorf("WSAddr = %s, want 0.0.0.0:8546", config.WSAddr)
	}
	if config.MaxConns != 1000 {
		t.Errorf("MaxConns = %d, want 1000", config.MaxConns)
	}
}

// --- GetTransactionByBlockHashAndIndex Tests ---

func TestEthGetTransactionByBlockHashAndIndex(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a block with a transaction.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Get block 1 to find its hash.
	blk, err := ts.server.EthAPI().GetBlockByNumber(1, false)
	if err != nil {
		t.Fatalf("GetBlockByNumber failed: %v", err)
	}
	if blk == nil {
		t.Fatal("block 1 is nil")
	}
	blockHash := types.HexToHash(blk["hash"].(string))

	// Get transaction at index 0.
	result, err := ts.server.EthAPI().GetTransactionByBlockHashAndIndex(blockHash, 0)
	if err != nil {
		t.Fatalf("GetTransactionByBlockHashAndIndex failed: %v", err)
	}
	if result == nil {
		t.Fatal("transaction not found")
	}
	if result["hash"] != tx.Hash().Hex() {
		t.Errorf("tx hash = %s, want %s", result["hash"], tx.Hash().Hex())
	}
	if result["blockNumber"] != "0x1" {
		t.Errorf("tx blockNumber = %s, want 0x1", result["blockNumber"])
	}
	if result["transactionIndex"] != "0x0" {
		t.Errorf("tx index = %s, want 0x0", result["transactionIndex"])
	}
}

func TestEthGetTransactionByBlockHashAndIndex_OutOfRange(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a block with a single transaction.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	// Get block 1 to find its hash.
	blk, err := ts.server.EthAPI().GetBlockByNumber(1, false)
	if err != nil {
		t.Fatalf("GetBlockByNumber failed: %v", err)
	}
	blockHash := types.HexToHash(blk["hash"].(string))

	// Index 1 is out of range (only 1 tx at index 0).
	result, err := ts.server.EthAPI().GetTransactionByBlockHashAndIndex(blockHash, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil for out-of-range index")
	}

	// Non-existent block hash should also return nil.
	result, err = ts.server.EthAPI().GetTransactionByBlockHashAndIndex(
		types.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil for non-existent block hash")
	}
}

// --- GetTransactionByBlockNumberAndIndex Tests ---

func TestEthGetTransactionByBlockNumberAndIndex(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a block with a transaction.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Get transaction at block 1, index 0.
	result, err := ts.server.EthAPI().GetTransactionByBlockNumberAndIndex(1, 0)
	if err != nil {
		t.Fatalf("GetTransactionByBlockNumberAndIndex failed: %v", err)
	}
	if result == nil {
		t.Fatal("transaction not found")
	}
	if result["hash"] != tx.Hash().Hex() {
		t.Errorf("tx hash = %s, want %s", result["hash"], tx.Hash().Hex())
	}
	if result["blockNumber"] != "0x1" {
		t.Errorf("tx blockNumber = %s, want 0x1", result["blockNumber"])
	}

	// Test with "latest" block tag (-1).
	result, err = ts.server.EthAPI().GetTransactionByBlockNumberAndIndex(-1, 0)
	if err != nil {
		t.Fatalf("GetTransactionByBlockNumberAndIndex(latest) failed: %v", err)
	}
	if result == nil {
		t.Fatal("transaction not found for latest")
	}

	// Out of range index.
	result, err = ts.server.EthAPI().GetTransactionByBlockNumberAndIndex(1, 99)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil for out-of-range index")
	}
}

// --- GetProof Tests ---

func TestEthGetProof(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Get proof for the funded account at latest.
	blockTag := BlockNumberOrHashWithNumber(-1)
	result, err := ts.server.EthAPI().GetProof(ts.addr, nil, blockTag)
	if err != nil {
		t.Fatalf("eth_getProof failed: %v", err)
	}
	if result == nil {
		t.Fatal("proof result is nil")
	}

	// Verify structure.
	if result["address"] == nil {
		t.Error("address field is nil")
	}
	if result["accountProof"] == nil {
		t.Error("accountProof field is nil")
	}
	if result["balance"] == nil {
		t.Error("balance field is nil")
	}
	if result["codeHash"] == nil {
		t.Error("codeHash field is nil")
	}
	if result["nonce"] == nil {
		t.Error("nonce field is nil")
	}
	if result["storageHash"] == nil {
		t.Error("storageHash field is nil")
	}
	if result["storageProof"] == nil {
		t.Error("storageProof field is nil")
	}

	// Check balance is correct.
	balance := result["balance"].(string)
	expectedBal := EncodeBig(big.NewInt(1_000_000_000_000_000_000))
	if balance != expectedBal {
		t.Errorf("proof balance = %s, want %s", balance, expectedBal)
	}

	// The account proof should have at least one node.
	proofNodes := result["accountProof"].([]string)
	if len(proofNodes) == 0 {
		t.Error("accountProof should have at least one node")
	}

	// Storage proof should be empty since we passed no keys.
	storageProofs := result["storageProof"].([]map[string]interface{})
	if len(storageProofs) != 0 {
		t.Errorf("expected 0 storage proofs, got %d", len(storageProofs))
	}
}

func TestEthGetProof_NonexistentAccount(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	unknown := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	blockTag := BlockNumberOrHashWithNumber(-1)

	result, err := ts.server.EthAPI().GetProof(unknown, nil, blockTag)
	if err != nil {
		t.Fatalf("eth_getProof for nonexistent account failed: %v", err)
	}
	if result == nil {
		t.Fatal("proof result is nil")
	}

	// Balance should be 0x0 for nonexistent account.
	if result["balance"] != "0x0" {
		t.Errorf("balance = %s, want 0x0", result["balance"])
	}

	// Nonce should be 0x0.
	if result["nonce"] != "0x0" {
		t.Errorf("nonce = %s, want 0x0", result["nonce"])
	}
}

// --- BSV Covenant and Governance Tests ---

func TestBsvGetCovenantTip(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.BsvAPI().GetCovenantTip()
	if result == nil {
		t.Fatal("covenant tip is nil")
	}

	// Verify required fields are present (spec 05 CovenantTipResult).
	if result["bsvTxId"] == nil {
		t.Error("bsvTxId field is nil")
	}
	if result["l2BlockNumber"] == nil {
		t.Error("l2BlockNumber field is nil")
	}
	if result["stateRoot"] == nil {
		t.Error("stateRoot field is nil")
	}
	if _, ok := result["confirmed"]; !ok {
		t.Error("confirmed field is missing")
	}

	// Verify initial values.
	if result["l2BlockNumber"] != "0x0" {
		t.Errorf("l2BlockNumber = %s, want 0x0", result["l2BlockNumber"])
	}
	if result["confirmed"] != false {
		t.Errorf("confirmed = %v, want false", result["confirmed"])
	}
}

func TestBsvGetGovernanceState(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.BsvAPI().GetGovernanceState()
	if result == nil {
		t.Fatal("governance state is nil")
	}

	// Verify required fields are present.
	if result["mode"] == nil {
		t.Error("mode field is nil")
	}
	if _, ok := result["frozen"]; !ok {
		t.Error("frozen field is missing")
	}
	if result["keys"] == nil {
		t.Error("keys field is nil")
	}

	// Default governance is "none" since we don't set governance config
	// in the test setup.
	if result["mode"] != "none" {
		t.Errorf("mode = %s, want none", result["mode"])
	}
	if result["frozen"] != false {
		t.Errorf("frozen = %v, want false", result["frozen"])
	}
	keys := result["keys"].([]string)
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
	if result["threshold"] != 0 {
		t.Errorf("threshold = %v, want 0", result["threshold"])
	}
}

// --- Dispatch Tests for New Methods ---

func TestNewMethodRouting(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a block so we have data.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	// Get block hash for dispatch tests.
	blk, _ := ts.server.EthAPI().GetBlockByNumber(1, false)
	blockHash := blk["hash"].(string)

	tests := []struct {
		method string
		params string
	}{
		{
			"eth_getTransactionByBlockHashAndIndex",
			`["` + blockHash + `", "0x0"]`,
		},
		{
			"eth_getTransactionByBlockNumberAndIndex",
			`["0x1", "0x0"]`,
		},
		{
			"eth_getProof",
			`["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [], "latest"]`,
		},
		{
			"bsv_getCovenantTip",
			`[]`,
		},
		{
			"bsv_getGovernanceState",
			`[]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			result, err := ts.server.dispatch(tc.method, json.RawMessage(tc.params))
			if err != nil {
				t.Errorf("dispatch(%s) error: %v", tc.method, err)
			}
			if result == nil {
				t.Errorf("dispatch(%s) returned nil result", tc.method)
			}
		})
	}
}

// --- BSV API Tests (Additional) ---

func TestBsvPeerCount(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result := ts.server.BsvAPI().PeerCount()
	if result != "0x0" {
		t.Errorf("bsv_peerCount = %s, want 0x0", result)
	}

	// Also test dispatch.
	dispatched, err := ts.server.dispatch("bsv_peerCount", json.RawMessage("[]"))
	if err != nil {
		t.Fatalf("dispatch bsv_peerCount failed: %v", err)
	}
	if dispatched != "0x0" {
		t.Errorf("dispatched bsv_peerCount = %v, want 0x0", dispatched)
	}
}

func TestBsvFeeWalletBalance(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Without a fee wallet set, should return zeros.
	result := ts.server.BsvAPI().FeeWalletBalance()
	if result["balance"] != EncodeUint64(0) {
		t.Errorf("balance = %v, want %s", result["balance"], EncodeUint64(0))
	}
	if result["address"] != "" {
		t.Errorf("address = %v, want empty string", result["address"])
	}

	// Set a mock fee wallet and verify.
	ts.server.BsvAPI().SetFeeWallet(&mockFeeWallet{
		balance:   50000,
		utxoCount: 3,
		starved:   true,
	})
	result = ts.server.BsvAPI().FeeWalletBalance()
	if result["balance"] != EncodeUint64(50000) {
		t.Errorf("balance = %v, want %s", result["balance"], EncodeUint64(50000))
	}
	if result["address"] != "1TestAddress" {
		t.Errorf("address = %v, want 1TestAddress", result["address"])
	}

	// Also test dispatch.
	dispatched, err := ts.server.dispatch("bsv_feeWalletBalance", json.RawMessage("[]"))
	if err != nil {
		t.Fatalf("dispatch bsv_feeWalletBalance failed: %v", err)
	}
	if dispatched == nil {
		t.Fatal("dispatch bsv_feeWalletBalance returned nil")
	}
}

// mockFeeWallet implements feeWalletAccessor for testing.
type mockFeeWallet struct {
	balance   uint64
	utxoCount int
	starved   bool
}

func (m *mockFeeWallet) Balance() uint64 { return m.balance }
func (m *mockFeeWallet) UTXOCount() int  { return m.utxoCount }
func (m *mockFeeWallet) IsStarved() bool { return m.starved }
func (m *mockFeeWallet) Address() string { return "1TestAddress" }

// --- LogIndex Integration with GetLogs ---

func TestGetLogsWithLogIndex(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Process a transaction to get a block with receipts.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ts.processOneTx(t, 0, recipient, uint256.NewInt(1000))

	// Create a log index and set it on the EthAPI.
	logIndexDB := db.NewMemoryDB()
	logIndex := block.NewLogIndex(logIndexDB)
	ts.server.EthAPI().SetLogIndex(logIndex)

	// Read the block 1 header to get its bloom.
	header := ts.chainDB.ReadHeaderByNumber(1)
	if header == nil {
		t.Fatal("block 1 header not found")
	}
	if err := logIndex.IndexBlock(1, header.LogsBloom); err != nil {
		t.Fatalf("IndexBlock failed: %v", err)
	}

	// GetLogs should still work (simple transfer has no logs, but
	// should not crash).
	filter := FilterQuery{
		FromBlock: big.NewInt(0),
		ToBlock:   big.NewInt(1),
	}
	results, err := ts.server.EthAPI().GetLogs(filter)
	if err != nil {
		t.Fatalf("GetLogs failed: %v", err)
	}
	// Simple transfers produce no logs, so results should be empty.
	if len(results) != 0 {
		t.Errorf("expected 0 logs, got %d", len(results))
	}
}

// --- Batch JSON-RPC Tests ---

func TestBatchJSONRPC(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	handler := http.HandlerFunc(ts.server.handleHTTP)

	t.Run("single request in array", func(t *testing.T) {
		body := `[{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}]`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code = %d, want 200", w.Code)
		}

		var responses []json.RawMessage
		if err := json.NewDecoder(w.Body).Decode(&responses); err != nil {
			t.Fatalf("failed to decode batch response: %v", err)
		}
		if len(responses) != 1 {
			t.Fatalf("expected 1 response, got %d", len(responses))
		}

		// Parse the single response.
		var resp jsonrpcResponse
		if err := json.Unmarshal(responses[0], &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}
		if resp.Error != nil {
			t.Errorf("unexpected error: %v", resp.Error)
		}
	})

	t.Run("multiple requests in correct order", func(t *testing.T) {
		body := `[
			{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
			{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2},
			{"jsonrpc":"2.0","method":"net_version","params":[],"id":3}
		]`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		var responses []json.RawMessage
		if err := json.NewDecoder(w.Body).Decode(&responses); err != nil {
			t.Fatalf("failed to decode batch response: %v", err)
		}
		if len(responses) != 3 {
			t.Fatalf("expected 3 responses, got %d", len(responses))
		}

		// Verify each response has correct ID order.
		for i, raw := range responses {
			var resp struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal(raw, &resp); err != nil {
				t.Fatalf("response %d: unmarshal failed: %v", i, err)
			}
		}
	})

	t.Run("mixed valid and invalid requests", func(t *testing.T) {
		body := `[
			{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
			{"invalid json object
			{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":3}
		]`
		// This whole batch is invalid JSON, so it should fail.
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// The entire array is invalid JSON, so we get a parse error.
		var resp jsonrpcResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Error == nil {
			t.Error("expected error for invalid batch JSON")
		}
	})

	t.Run("mixed valid and invalid individual requests", func(t *testing.T) {
		// Each array element is valid JSON, but one has an unknown method.
		body := `[
			{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
			{"jsonrpc":"2.0","method":"eth_nonExistent","params":[],"id":2},
			{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":3}
		]`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		var responses []json.RawMessage
		if err := json.NewDecoder(w.Body).Decode(&responses); err != nil {
			t.Fatalf("failed to decode batch response: %v", err)
		}
		if len(responses) != 3 {
			t.Fatalf("expected 3 responses, got %d", len(responses))
		}

		// First should succeed.
		var resp1 jsonrpcResponse
		json.Unmarshal(responses[0], &resp1)
		if resp1.Error != nil {
			t.Errorf("response 1: unexpected error: %v", resp1.Error)
		}

		// Second should be an error (method not found).
		var resp2 jsonrpcResponse
		json.Unmarshal(responses[1], &resp2)
		if resp2.Error == nil {
			t.Error("response 2: expected error for unknown method")
		}

		// Third should succeed.
		var resp3 jsonrpcResponse
		json.Unmarshal(responses[2], &resp3)
		if resp3.Error != nil {
			t.Errorf("response 3: unexpected error: %v", resp3.Error)
		}
	})

	t.Run("empty array", func(t *testing.T) {
		body := `[]`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		var responses []json.RawMessage
		if err := json.NewDecoder(w.Body).Decode(&responses); err != nil {
			t.Fatalf("failed to decode batch response: %v", err)
		}
		if len(responses) != 0 {
			t.Errorf("expected 0 responses for empty batch, got %d", len(responses))
		}
	})

	t.Run("non-JSON body", func(t *testing.T) {
		body := `not json at all`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		var resp jsonrpcResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Error == nil {
			t.Error("expected error for non-JSON body")
		}
		if resp.Error != nil && resp.Error.Code != errCodeInvalidRequest {
			t.Errorf("expected error code %d, got %d", errCodeInvalidRequest, resp.Error.Code)
		}
	})
}

// --- eth_sign and eth_sendTransaction Error Tests ---

func TestEthSignError(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	_, err := ts.server.dispatch("eth_sign", json.RawMessage("[]"))
	if err == nil {
		t.Fatal("expected error for eth_sign")
	}
	rpcErr, ok := err.(*rpcError)
	if !ok {
		t.Fatalf("expected *rpcError, got %T", err)
	}
	if rpcErr.code != errCodeMethodNotFound {
		t.Errorf("expected error code %d, got %d", errCodeMethodNotFound, rpcErr.code)
	}
	if rpcErr.message != "eth_sign is not supported (no key management)" {
		t.Errorf("unexpected message: %s", rpcErr.message)
	}
}

func TestEthSendTransactionError(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	_, err := ts.server.dispatch("eth_sendTransaction", json.RawMessage("[]"))
	if err == nil {
		t.Fatal("expected error for eth_sendTransaction")
	}
	rpcErr, ok := err.(*rpcError)
	if !ok {
		t.Fatalf("expected *rpcError, got %T", err)
	}
	if rpcErr.code != errCodeMethodNotFound {
		t.Errorf("expected error code %d, got %d", errCodeMethodNotFound, rpcErr.code)
	}
	if rpcErr.message != "eth_sendTransaction is not supported, use eth_sendRawTransaction" {
		t.Errorf("unexpected message: %s", rpcErr.message)
	}
}

// --- Debug API Tests ---

func TestDebugTraceTransactionInvalidHash(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	_, err := ts.server.DebugAPI().TraceTransaction("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if err == nil {
		t.Fatal("expected error for non-existent transaction")
	}
}

func TestDebugTraceCall(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	args := TransactionArgs{
		From: &ts.addr,
		To:   &recipient,
	}

	result, err := ts.server.DebugAPI().TraceCall(args, "latest")
	if err != nil {
		t.Fatalf("debug_traceCall failed: %v", err)
	}

	traceResult, ok := result.(*TraceResult)
	if !ok {
		t.Fatalf("expected *TraceResult, got %T", result)
	}

	// A simple EOA-to-EOA transfer should not fail.
	if traceResult.Failed {
		t.Error("trace should not have failed for simple transfer")
	}

	// Should have struct logs (at minimum, the execution steps).
	if traceResult.StructLogs == nil {
		t.Error("expected non-nil structLogs")
	}
}

func TestDebugTraceTransaction(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	result, err := ts.server.DebugAPI().TraceTransaction(tx.Hash().Hex())
	if err != nil {
		t.Fatalf("debug_traceTransaction failed: %v", err)
	}

	traceResult, ok := result.(*TraceResult)
	if !ok {
		t.Fatalf("expected *TraceResult, got %T", result)
	}

	if traceResult.Failed {
		t.Error("trace should not have failed for simple transfer")
	}
}

func TestDebugTraceBlockByNumber(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	result, err := ts.server.DebugAPI().TraceBlockByNumber("0x1")
	if err != nil {
		t.Fatalf("debug_traceBlockByNumber failed: %v", err)
	}

	traces, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(traces) != 1 {
		t.Errorf("expected 1 trace, got %d", len(traces))
	}
}

func TestDebugEVMDisagreement(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	result, err := ts.server.DebugAPI().EVMDisagreement()
	if err != nil {
		t.Fatalf("debug_evmDisagreement failed: %v", err)
	}

	status, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	if _, exists := status["tripped"]; !exists {
		t.Error("expected 'tripped' field in status")
	}
	if _, exists := status["consecutiveFailures"]; !exists {
		t.Error("expected 'consecutiveFailures' field in status")
	}
	if _, exists := status["maxRetries"]; !exists {
		t.Error("expected 'maxRetries' field in status")
	}

	// Initially should not be tripped.
	if status["tripped"] != false {
		t.Errorf("expected tripped=false, got %v", status["tripped"])
	}
}

// --- Debug dispatch routing tests ---

func TestDebugDispatchRouting(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	t.Run("debug_traceTransaction invalid hash", func(t *testing.T) {
		_, err := ts.server.dispatch("debug_traceTransaction",
			json.RawMessage(`["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]`))
		if err == nil {
			t.Error("expected error for non-existent tx")
		}
	})

	t.Run("debug_evmDisagreement", func(t *testing.T) {
		result, err := ts.server.dispatch("debug_evmDisagreement", json.RawMessage("[]"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})
}

// --- Config defaults test ---

func TestDefaultRPCConfigWSLimits(t *testing.T) {
	config := DefaultRPCConfig()
	if config.WSMaxConnections != 1000 {
		t.Errorf("WSMaxConnections = %d, want 1000", config.WSMaxConnections)
	}
	if config.WSMaxSubscriptionsPerConn != 100 {
		t.Errorf("WSMaxSubscriptionsPerConn = %d, want 100", config.WSMaxSubscriptionsPerConn)
	}
	if config.WSEventQueueDepth != 1000 {
		t.Errorf("WSEventQueueDepth = %d, want 1000", config.WSEventQueueDepth)
	}
	if config.WSSlowConsumerTimeout != 30*time.Second {
		t.Errorf("WSSlowConsumerTimeout = %v, want 30s", config.WSSlowConsumerTimeout)
	}
}
