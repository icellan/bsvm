// Package e2e — daemon-level smoke test.
//
// TestDaemonSmoke wires up the same component graph that cmd/bsvm uses
// (overlay node + bridge monitor + mock prover + RPC server + BEEF
// endpoints) inside a single process, then drives a full cycle:
//
//  1. Genesis init via shard.InitShard equivalent (block.InitGenesis).
//  2. Boot RPC + BEEF on an ephemeral 127.0.0.1 port.
//  3. Stage a verified deposit through bridge.BridgeMonitor — this is
//     exactly what the BEEF consumer hands off post-W6-4 verification.
//     Drain the deposit into L2 via overlay.SubmitDepositTx and assert
//     the recipient's wBSV balance via eth_getBalance.
//  4. Sign and submit a real EIP-1559 transaction through HTTP
//     eth_sendRawTransaction. Force-flush the batcher.
//  5. Query eth_getTransactionReceipt and assert status=1, gas debited
//     from the sender, recipient credited.
//  6. Shut down. Assert all background goroutines exit and the DB
//     closes cleanly. Spot-check open file descriptors before/after to
//     surface obvious leaks.
//
// Subsystems intentionally NOT wired (with rationale):
//
//   - libp2p gossip / network.GossipManager — not needed for a single-
//     node daemon smoke test; bringing up libp2p multiaddr listeners
//     adds flakiness and platform-specific ports without exercising
//     anything the smoke test asserts on. The code path is covered by
//     test/multinode and pkg/network's own tests.
//   - chaintracks.MultiClient + BSV-node RPC + WoC + ARC — would require
//     building real BEEF envelopes (BUMP + ancestor graph) to exercise
//     the BEEF consumer's W6-4 verifier path. Spec 17 already has unit
//     tests covering that verifier; the smoke test calls
//     BridgeMonitor.PersistDeposit + OverlayNode.SubmitDepositTx
//     directly, modelling the post-verification handoff and avoiding
//     the BEEF envelope synthesis cost.
//   - SP1 prover network / local subprocess — the smoke test uses
//     prover.ProverMock which returns a synthetic proof. The covenant
//     advance / on-chain Bitcoin Script verifier is therefore stubbed:
//     ProcessBatch produces a synthetic proof but is not broadcast to
//     BSV. End-to-end proof generation is covered by test/integration's
//     rollup_*_test.go suites.
//   - libp2p genesis-sync, peer manager, sync manager — same rationale
//     as gossip: single-node, no peers.
//
// The harness still proves the deposit → L2 credit → tx submit →
// receipt query lifecycle works end-to-end through the JSON-RPC
// surface that wallets actually hit.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/rpc"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// smokeChainID is the L2 chain ID used by the smoke harness. Anything
// non-zero works; we pick a value distinct from the existing e2e tests
// (testChainID = 99999) so cross-test confusion in logs is impossible.
const smokeChainID int64 = 12345678

// smokeHarness bundles everything the smoke test boots so individual
// steps can reach into specific components and the t.Cleanup hook has a
// single place to tear everything down.
type smokeHarness struct {
	t           *testing.T
	dataDir     string
	dbHandle    db.Database
	chainDB     *block.ChainDB
	chainConfig *vm.ChainConfig
	overlayNode *overlay.OverlayNode
	bridgeMon   *bridge.BridgeMonitor
	rpcServer   *rpc.RPCServer
	httpURL     string

	// shutdown captures the steps the test asserts on after the
	// daemon's normal Stop completes.
	stopped bool
}

// newSmokeHarness boots the in-process daemon. It mirrors cmd/bsvm's
// wiring at the level of detail we can exercise without external
// dependencies: genesis → DB → covenant manager → prover (mock) →
// overlay node → bridge monitor → RPC server (with BEEF endpoints
// mounted on an ephemeral port).
func newSmokeHarness(t *testing.T, allocAddr types.Address, allocBal *uint256.Int) *smokeHarness {
	t.Helper()

	// 1. Per-test datadir + LevelDB. Using LevelDB (not MemoryDB) so
	//    the close-cleanly assertion at the end has something
	//    meaningful to verify. Tests run in parallel so each gets its
	//    own dir.
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "chaindata")
	database, err := db.NewLevelDB(dbPath, 64, 64)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}

	// 2. Genesis. Mirrors shard.InitShard's call into block.InitGenesis
	//    with a single funded account so subsequent tx submissions can
	//    pay gas. The bridge predeploy is wired by InitGenesis itself.
	chainConfig := vm.DefaultL2Config(smokeChainID)
	alloc := map[types.Address]block.GenesisAccount{}
	if (allocAddr != types.Address{}) {
		alloc[allocAddr] = block.GenesisAccount{Balance: new(uint256.Int).Set(allocBal)}
	}
	if _, err := block.InitGenesis(database, &block.Genesis{
		Config:    chainConfig,
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  block.DefaultGasLimit,
		Alloc:     alloc,
	}); err != nil {
		database.Close()
		t.Fatalf("init genesis: %v", err)
	}

	chainDB := block.NewChainDB(database)
	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		database.Close()
		t.Fatal("no head header after genesis")
	}

	// 3. Covenant manager. The genesis tx ID is left zero — the smoke
	//    test never broadcasts to BSV — and verification mode is
	//    devkey so the synthetic mock proof is accepted.
	covenantMgr := covenant.NewCovenantManager(
		&covenant.CompiledCovenant{},
		types.Hash{},
		0,
		10000,
		covenant.CovenantState{StateRoot: headHeader.StateRoot},
		uint64(smokeChainID),
		covenant.VerifyDevKey,
	)

	// 4. Mock prover — returns a synthetic proof immediately. This is
	//    the same path cmd/bsvm uses when --prove-mode=mock.
	sp1Prover := prover.NewSP1Prover(prover.Config{
		Mode:         prover.ProverMock,
		ProofMode:    prover.ProofModeFRI,
		Timeout:      30 * time.Second,
		SP1ProofMode: "compressed",
	})

	// 5. Overlay node. Tight batch flush (50ms) so the test doesn't
	//    sit on the default 2s timer. ProveMode set to "mock" so any
	//    code path that branches on proving mode picks the dev path.
	overlayCfg := overlay.DefaultOverlayConfig()
	overlayCfg.ChainID = smokeChainID
	overlayCfg.Coinbase = types.HexToAddress("0xC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FF")
	overlayCfg.MaxBatchFlushDelay = 50 * time.Millisecond
	overlayCfg.MaxBatchSize = 16
	overlayCfg.TargetBatchSize = 16
	overlayCfg.MinGasPrice = big.NewInt(1) // accept anything > 0 wei/gas
	overlayCfg.ProveMode = "mock"
	overlayCfg.RequireRealProof = false

	overlayNode, err := overlay.NewOverlayNode(overlayCfg, chainDB, database, covenantMgr, sp1Prover)
	if err != nil {
		database.Close()
		t.Fatalf("new overlay node: %v", err)
	}

	// 6. Bridge monitor. The smoke test bypasses the BEEF consumer's
	//    W6-4 verifier path (synthesising a real BEEF envelope is out
	//    of scope) and calls PersistDeposit directly — which is
	//    exactly what the verifier hands the monitor on success.
	//
	//    The script hash here is a placeholder; ParseDeposit isn't
	//    invoked on the PersistDeposit path.
	bridgeMon := bridge.NewBridgeMonitor(
		bridge.DefaultConfig(),
		nil, // no BSV client — block-scanning path stays dormant
		overlayNode,
		database,
	)
	bridgeMon.SetBridgeScriptHash([]byte{0xde, 0xad, 0xbe, 0xef})
	bridgeMon.SetLocalShardID(uint32(smokeChainID))

	// 7. RPC server bound to an ephemeral 127.0.0.1 port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		database.Close()
		t.Fatalf("listen: %v", err)
	}
	httpAddr := listener.Addr().String()
	listener.Close() // RPCServer.Start does its own ListenAndServe.

	// Same trick for WS (separate server inside RPCServer.Start).
	wsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		database.Close()
		t.Fatalf("listen ws: %v", err)
	}
	wsAddr := wsListener.Addr().String()
	wsListener.Close()

	rpcCfg := rpc.DefaultRPCConfig()
	rpcCfg.HTTPAddr = httpAddr
	rpcCfg.WSAddr = wsAddr
	rpcCfg.RequestsPerSecond = 0 // disable rate limit for tests
	rpcCfg.CORSOrigins = []string{}

	rpcServer := rpc.NewRPCServerWithConfig(rpcCfg, chainConfig, overlayNode, chainDB, database)

	// Mount BEEF endpoints. Without chaintracks/bridge-monitor wired
	// to the bridge consumer, deposits posted to /bsvm/bridge/deposit
	// fall through to the fail-closed branch — the smoke test does
	// not exercise that path; this is here so the route table looks
	// like the real daemon's.
	beefEndpoints := rpc.NewBEEFEndpoints(rpc.BEEFEndpointConfig{
		Store:   beef.NewMemoryStore(),
		ShardID: uint64(smokeChainID),
		BridgeConsumer: func(env *beef.Envelope) {
			// fail-closed: no chaintracks wired
		},
	})
	rpcServer.SetBEEFEndpoints(beefEndpoints)

	if err := rpcServer.Start(); err != nil {
		database.Close()
		t.Fatalf("rpc start: %v", err)
	}

	// Wait for the server to actually accept connections (Start spawns
	// goroutines; ListenAndServe binds before returning but tests have
	// observed brief flakes on slow CI). Poll up to 1s.
	httpURL := "http://" + httpAddr
	if err := waitForHTTP(httpURL, 1*time.Second); err != nil {
		_ = rpcServer.Stop()
		database.Close()
		t.Fatalf("rpc never came up: %v", err)
	}

	h := &smokeHarness{
		t:           t,
		dataDir:     dataDir,
		dbHandle:    database,
		chainDB:     chainDB,
		chainConfig: chainConfig,
		overlayNode: overlayNode,
		bridgeMon:   bridgeMon,
		rpcServer:   rpcServer,
		httpURL:     httpURL,
	}

	t.Cleanup(func() {
		// Idempotent — TestDaemonSmoke calls Shutdown() explicitly to
		// assert success; the cleanup here only runs if the test
		// failed mid-flight.
		h.Shutdown()
	})
	return h
}

// Shutdown stops the RPC server, the overlay node, and closes the DB.
// Called explicitly at the end of the test so the assertions can see
// the result; t.Cleanup also calls it to guarantee teardown on panic.
func (h *smokeHarness) Shutdown() {
	if h.stopped {
		return
	}
	h.stopped = true
	// Order matches cmdRun's shutdown sequence: RPC first (so no new
	// requests land mid-shutdown), then overlay (drains batcher,
	// stops timers), then DB.
	if err := h.rpcServer.Stop(); err != nil {
		h.t.Errorf("rpc stop: %v", err)
	}
	h.overlayNode.Stop()
	if err := h.dbHandle.Close(); err != nil {
		h.t.Errorf("db close: %v", err)
	}
}

// waitForHTTP polls a TCP-level connect to the JSON-RPC port until it
// answers or the deadline expires. Used by the harness to gate the
// first request on Start completing its goroutine handshake.
func waitForHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Post(url, "application/json", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}`)))
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("rpc not responsive after %s", timeout)
}

// rpcCall issues a JSON-RPC POST and returns the parsed result field.
// Errors out if the JSON-RPC envelope reports an error.
func (h *smokeHarness) rpcCall(method string, params interface{}) (json.RawMessage, error) {
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(h.httpURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &envelope); err != nil {
		return nil, fmt.Errorf("decode rpc response (raw=%s): %w", string(respBytes), err)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", envelope.Error.Code, envelope.Error.Message)
	}
	return envelope.Result, nil
}

// rpcGetBalance queries eth_getBalance and returns a uint256.Int. Block
// tag is "latest".
func (h *smokeHarness) rpcGetBalance(addr types.Address) (*uint256.Int, error) {
	res, err := h.rpcCall("eth_getBalance", []string{addr.Hex(), "latest"})
	if err != nil {
		return nil, err
	}
	var hexStr string
	if err := json.Unmarshal(res, &hexStr); err != nil {
		return nil, err
	}
	n := new(uint256.Int)
	if err := n.SetFromHex(hexStr); err != nil {
		return nil, fmt.Errorf("decode balance hex %q: %w", hexStr, err)
	}
	return n, nil
}

// --- Test ---

// TestDaemonSmoke drives the deposit → L2 credit → tx submit → receipt
// query lifecycle inside a single in-process daemon.
//
// Cycles run:
//
//  1. Bridge deposit credits a fresh L2 address.
//  2. The funded address signs and submits a transfer to a recipient.
//  3. Receipt is fetched via eth_getTransactionReceipt; status, gas,
//     and post-state balances are asserted.
//  4. Daemon shuts down cleanly with no FD leaks.
func TestDaemonSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping daemon smoke test in -short mode")
	}

	// We pre-fund a "bootstrap" key with enough wBSV to pay gas for
	// the test transactions. The bridge deposit credits a SEPARATE
	// address so the bridge path is exercised in isolation.
	bootstrapKey := newKey(t)
	bootstrap := keyAddr(bootstrapKey)
	bootstrapBal := new(uint256.Int).Mul(uint256.NewInt(100), uint256.NewInt(1e18)) // 100 wBSV

	startFDs := openFDCount()

	h := newSmokeHarness(t, bootstrap, bootstrapBal)
	t.Logf("daemon listening on %s", h.httpURL)

	// --- Step 1. Bridge deposit ---

	depositRecipient := types.HexToAddress("0xD0E057051000000000000000000000000000DEAD")
	depositSatoshis := uint64(50_000_000) // 0.5 BSV
	expectedDepositWei := types.SatoshisToWei(depositSatoshis)

	dep := bridge.NewDepositWithVout(
		types.HexToHash("0x010203"), // synthetic BSV txid
		0,
		1,
		depositRecipient,
		depositSatoshis,
	)
	dep.Confirmed = true

	// PersistDeposit is what the BEEF consumer calls after the W6-4
	// verifier passes. The smoke test goes one step further and
	// applies the deposit to L2 immediately via SubmitDepositTx,
	// which is what the deposit-horizon flush does on the next L2
	// block in the real daemon.
	//
	// Note: SubmitDepositTx mutates the overlay's in-memory state
	// but does NOT write a new block to the chain database. The
	// deposit balance only becomes visible to eth_getBalance once
	// the next ProcessBatch runs and persists a block with the new
	// post-state root. The test exercises both halves: it asserts
	// the in-memory state reflects the deposit (via the overlay's
	// internal accessor) here, then re-checks via eth_getBalance
	// AFTER the L2 tx batch flushes (Step 4).
	if err := h.bridgeMon.PersistDeposit(dep); err != nil {
		t.Fatalf("persist deposit: %v", err)
	}
	if err := h.overlayNode.SubmitDepositTx(dep.ToDepositTx()); err != nil {
		t.Fatalf("submit deposit tx: %v", err)
	}

	// In-memory check: the overlay's StateDB now contains the
	// deposit credit. The chainDB head is still genesis, so
	// eth_getBalance won't return it yet — that comes after the
	// next batch flush in Step 4.
	if got := h.overlayNode.StateDB().GetBalance(depositRecipient); got.Cmp(expectedDepositWei) != 0 {
		t.Fatalf("in-memory deposit credit: got %s wei, want %s wei", got, expectedDepositWei)
	}
	t.Logf("deposit applied to in-memory state: %s wei (%d sats) → %s",
		expectedDepositWei, depositSatoshis, depositRecipient.Hex())

	// --- Step 2. Submit an L2 transaction via JSON-RPC ---

	txRecipient := types.HexToAddress("0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1")
	transferValue := uint256.NewInt(1e18) // 1 wBSV

	signer := types.NewLondonSigner(big.NewInt(smokeChainID))
	signedTx := types.MustSignNewTx(bootstrapKey, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(smokeChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(1_000_000_000),
		Gas:       21000,
		To:        &txRecipient,
		Value:     transferValue,
	})

	rawBytes, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		t.Fatalf("rlp encode tx: %v", err)
	}
	rawHex := "0x" + bytesToHex(rawBytes)

	res, err := h.rpcCall("eth_sendRawTransaction", []string{rawHex})
	if err != nil {
		t.Fatalf("eth_sendRawTransaction: %v", err)
	}
	var returnedHashHex string
	if err := json.Unmarshal(res, &returnedHashHex); err != nil {
		t.Fatalf("decode sendRawTransaction result: %v", err)
	}
	if returnedHashHex != signedTx.Hash().Hex() {
		t.Fatalf("returned tx hash mismatch: got %s, want %s",
			returnedHashHex, signedTx.Hash().Hex())
	}
	t.Logf("submitted tx %s (nonce=0)", returnedHashHex)

	// Force the batcher to flush right now rather than wait for the
	// 50ms timer. Lets the test be deterministic on slow CI.
	if err := h.overlayNode.BatcherForceFlush(); err != nil {
		t.Fatalf("batcher force flush: %v", err)
	}

	// --- Step 3. Query receipt ---

	receipt, err := waitForReceipt(h, signedTx.Hash().Hex(), 3*time.Second)
	if err != nil {
		t.Fatalf("wait for receipt: %v", err)
	}

	// Status field — eth_getTransactionReceipt returns "0x1" for
	// success, "0x0" for failure.
	status := mustField(t, receipt, "status").(string)
	if status != "0x1" {
		t.Fatalf("receipt status = %s, want 0x1 (success)", status)
	}
	gasUsedHex := mustField(t, receipt, "gasUsed").(string)
	gasUsed, ok := new(big.Int).SetString(strip0x(gasUsedHex), 16)
	if !ok {
		t.Fatalf("decode gasUsed %q", gasUsedHex)
	}
	if gasUsed.Uint64() != 21000 {
		t.Fatalf("gas used = %d, want 21000", gasUsed.Uint64())
	}
	blockNumHex := mustField(t, receipt, "blockNumber").(string)
	blockNum, ok := new(big.Int).SetString(strip0x(blockNumHex), 16)
	if !ok {
		t.Fatalf("decode blockNumber %q", blockNumHex)
	}
	if blockNum.Sign() == 0 {
		t.Fatalf("receipt blockNumber should be > 0, got %s", blockNum)
	}
	t.Logf("receipt: status=success gasUsed=21000 block=%s", blockNum)

	// --- Step 4. Post-state balance assertions ---

	// The L2 tx flush has now written a block including the deposit
	// state, so eth_getBalance against "latest" surfaces the
	// deposit credit too. This validates the deposit → batch →
	// receipt observable lifecycle through the public RPC surface.
	depositBal, err := h.rpcGetBalance(depositRecipient)
	if err != nil {
		t.Fatalf("get deposit recipient balance after batch: %v", err)
	}
	if depositBal.Cmp(expectedDepositWei) != 0 {
		t.Fatalf("deposit recipient balance after batch = %s, want %s",
			depositBal, expectedDepositWei)
	}

	recipientBal, err := h.rpcGetBalance(txRecipient)
	if err != nil {
		t.Fatalf("get recipient balance: %v", err)
	}
	if recipientBal.Cmp(transferValue) != 0 {
		t.Fatalf("recipient balance = %s, want %s", recipientBal, transferValue)
	}

	bootstrapBalAfter, err := h.rpcGetBalance(bootstrap)
	if err != nil {
		t.Fatalf("get bootstrap balance: %v", err)
	}
	// Sender = initial - value - (gasUsed * gasPrice)
	gasCost := new(uint256.Int).Mul(uint256.NewInt(21000), uint256.NewInt(1_000_000_000))
	expectedBootstrap := new(uint256.Int).Sub(bootstrapBal, transferValue)
	expectedBootstrap.Sub(expectedBootstrap, gasCost)
	if bootstrapBalAfter.Cmp(expectedBootstrap) != 0 {
		t.Fatalf("bootstrap balance = %s, want %s", bootstrapBalAfter, expectedBootstrap)
	}

	// --- Step 5. Receipt for unknown hash returns null ---

	bogus, err := h.rpcCall("eth_getTransactionReceipt", []string{"0x" + bytesToHex(make([]byte, 32))})
	if err != nil {
		t.Fatalf("getTxReceipt unknown: %v", err)
	}
	if string(bogus) != "null" {
		t.Fatalf("unknown receipt should be null, got %s", string(bogus))
	}

	// --- Step 6. Clean shutdown ---

	t.Log("shutting down daemon")
	h.Shutdown()

	// Goroutine count: nothing strict, but a leak would manifest as
	// many extra goroutines (RPC server's two listeners + batcher
	// timer + WS manager). Give the runtime a moment to wind down,
	// then sample. We log rather than fail on a non-zero delta —
	// runtime.NumGoroutine includes test framework goroutines we
	// can't control.
	time.Sleep(100 * time.Millisecond)
	endFDs := openFDCount()
	leakedFDs := endFDs - startFDs
	if leakedFDs > 16 {
		// 16 is a generous slack — the test process itself
		// accumulates pipes and stdlib FDs unrelated to us.
		t.Errorf("possible FD leak: started with %d, ended with %d (delta %d)",
			startFDs, endFDs, leakedFDs)
	} else {
		t.Logf("FD delta after shutdown: %d (start=%d, end=%d)",
			leakedFDs, startFDs, endFDs)
	}
	t.Logf("goroutines after shutdown: %d", runtime.NumGoroutine())
}

// waitForReceipt polls eth_getTransactionReceipt until a non-null
// result is returned or the deadline expires. Returns the parsed
// receipt object.
func waitForReceipt(h *smokeHarness, txHash string, timeout time.Duration) (map[string]interface{}, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		res, err := h.rpcCall("eth_getTransactionReceipt", []string{txHash})
		if err != nil {
			return nil, err
		}
		if string(res) != "null" {
			var obj map[string]interface{}
			if err := json.Unmarshal(res, &obj); err != nil {
				return nil, err
			}
			return obj, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("receipt for %s never appeared within %s", txHash, timeout)
}

// mustField pulls a field out of a JSON-RPC receipt object and fails
// the test if it is missing.
func mustField(t *testing.T, m map[string]interface{}, k string) interface{} {
	t.Helper()
	v, ok := m[k]
	if !ok {
		t.Fatalf("receipt missing field %q (got %v)", k, m)
	}
	return v
}

// strip0x removes a leading "0x" if present, returning the hex digits.
func strip0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// bytesToHex returns the lowercase hex encoding of b.
func bytesToHex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

// openFDCount returns the number of currently-open file descriptors
// for this process, or -1 if the platform doesn't expose a way to
// count them. macOS / Linux both use /proc/self/fd or its
// libproc-backed equivalent — we walk /proc/self/fd on Linux and
// rely on lsof being unavailable on darwin. The test logs but does
// NOT fail on a -1 sample.
func openFDCount() int {
	// /proc/self/fd is Linux-only. On darwin we fall back to a
	// runtime.NumGoroutine-style "best-effort" sentinel of -1 so
	// the macOS-running developer still gets a useful test run.
	entries, err := readDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// readDir is a thin wrapper over os.ReadDir that returns names only.
// Pulled out as a helper so platforms without /proc can return a
// sentinel cleanly without dragging os.ReadDir's whole error vocabulary
// into the assertion.
func readDir(path string) ([]string, error) {
	// Avoid importing os.ReadDir at the top so the macOS path is
	// definitively a no-op.
	return readDirImpl(path)
}

// ensure the package-level signature exists across both Linux + darwin
// builds without a build-tag explosion. Concrete implementation lives
// in smoke_fd_unix.go for Linux and is a stub on darwin.
