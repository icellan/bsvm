package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/urfave/cli/v2"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// fakeChainReader is a hand-rolled covenantTipChainReader for the
// BuildCovenantTip unit tests. Writing to it sets the values
// ReadCovenantTxID and ReadCovenantState will return.
type fakeChainReader struct {
	txid       types.Hash
	stateBytes []byte
}

func (f *fakeChainReader) ReadCovenantTxID() types.Hash { return f.txid }
func (f *fakeChainReader) ReadCovenantState() []byte    { return f.stateBytes }

// stubScript is the locking-script bytes the fake fetcher serves. It
// is intentionally short so the test's expected sha256 hash is
// trivially auditable.
var stubScript = []byte{0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef, 0x88, 0xac}

// fakeUTXOFetcher returns a covenantUTXOFetcher that records every call
// and answers with stubScript / the supplied sats.
func fakeUTXOFetcher(t *testing.T, sats uint64, calls *[]string) covenantUTXOFetcher {
	t.Helper()
	return func(txid string, vout uint32) (string, uint64, error) {
		if calls != nil {
			*calls = append(*calls, fmt.Sprintf("%s:%d", txid, vout))
		}
		return hex.EncodeToString(stubScript), sats, nil
	}
}

// TestCovenantCommand_RegistersAsTipSubcommand confirms the CLI is
// wired correctly: the `covenant` parent exists with a `tip` child,
// and the `tip` child carries the documented flag set.
func TestCovenantCommand_RegistersAsTipSubcommand(t *testing.T) {
	cmd := covenantCommand()
	if cmd.Name != "covenant" {
		t.Fatalf("expected parent name 'covenant', got %q", cmd.Name)
	}
	if len(cmd.Subcommands) != 1 {
		t.Fatalf("expected exactly 1 subcommand under covenant, got %d", len(cmd.Subcommands))
	}
	tip := cmd.Subcommands[0]
	if tip.Name != "tip" {
		t.Fatalf("expected child name 'tip', got %q", tip.Name)
	}
	wantFlags := map[string]bool{
		"datadir":     false,
		"bsv-rpc":     false,
		"bsv-network": false,
		"shard-id":    false,
	}
	for _, f := range tip.Flags {
		for _, name := range f.Names() {
			if _, ok := wantFlags[name]; ok {
				wantFlags[name] = true
			}
		}
	}
	for name, seen := range wantFlags {
		if !seen {
			t.Errorf("expected --%s flag on `covenant tip`", name)
		}
	}
	if tip.Action == nil {
		t.Errorf("expected tip subcommand to define an Action")
	}
}

// TestBuildCovenantTip_PostAdvance is the headline shape check: the
// chaindata has a non-zero covenant txid and a populated state blob,
// the fetcher returns a stub locking script + sats, and the resulting
// JSON carries every field the rotate-vk runbook requires with the
// right values + encodings.
func TestBuildCovenantTip_PostAdvance(t *testing.T) {
	// Seed a covenant state with a recognisable state root + block
	// number so we can assert their projection into the JSON.
	wantStateRoot := types.HexToHash("0x4f9b0000000000000000000000000000000000000000000000000000000000aa")
	wantBlock := uint64(12847)
	state := &covenant.CovenantState{
		StateRoot:   wantStateRoot,
		BlockNumber: wantBlock,
	}

	// Build a fake txid in chainhash little-endian byte order — we
	// then assert that BSVString reverses it back to the expected
	// big-endian display form.
	hexTxIDBigEndian := strings.Repeat("ab", 32)
	hashLE := types.BSVHashFromHex(hexTxIDBigEndian)

	chain := &fakeChainReader{
		txid:       hashLE,
		stateBytes: state.Encode(),
	}

	var calls []string
	wantSats := uint64(10000)
	fetch := fakeUTXOFetcher(t, wantSats, &calls)

	tip, err := BuildCovenantTip(chain, fetch, "test-shard-1", t.TempDir())
	if err != nil {
		t.Fatalf("BuildCovenantTip: %v", err)
	}

	// Field-by-field assertions.
	if tip.ShardID != "test-shard-1" {
		t.Errorf("ShardID: got %q want %q", tip.ShardID, "test-shard-1")
	}
	if tip.CovenantTxID != hexTxIDBigEndian {
		t.Errorf("CovenantTxID: got %q want %q (BSV-canonical big-endian)",
			tip.CovenantTxID, hexTxIDBigEndian)
	}
	if tip.CovenantVout != 0 {
		t.Errorf("CovenantVout: got %d want 0", tip.CovenantVout)
	}
	if tip.CovenantSatsLive != wantSats {
		t.Errorf("CovenantSatsLive: got %d want %d", tip.CovenantSatsLive, wantSats)
	}
	if tip.CurrentStateRootHex != wantStateRoot.Hex() {
		t.Errorf("CurrentStateRootHex: got %q want %q",
			tip.CurrentStateRootHex, wantStateRoot.Hex())
	}
	if tip.CurrentBlockNumber != wantBlock {
		t.Errorf("CurrentBlockNumber: got %d want %d", tip.CurrentBlockNumber, wantBlock)
	}
	if tip.LockingScriptHex != hex.EncodeToString(stubScript) {
		t.Errorf("LockingScriptHex: got %q want %q",
			tip.LockingScriptHex, hex.EncodeToString(stubScript))
	}
	wantHash := sha256.Sum256(stubScript)
	if tip.LockingScriptSha256 != hex.EncodeToString(wantHash[:]) {
		t.Errorf("LockingScriptSha256: got %q want %q",
			tip.LockingScriptSha256, hex.EncodeToString(wantHash[:]))
	}

	// The fetcher must have been called with the BSV-canonical txid
	// and vout 0.
	if len(calls) != 1 {
		t.Fatalf("expected 1 fetcher call, got %d (%v)", len(calls), calls)
	}
	if calls[0] != hexTxIDBigEndian+":0" {
		t.Errorf("fetcher called with %q, want %q", calls[0], hexTxIDBigEndian+":0")
	}

	// Extra: the JSON envelope must round-trip without a custom
	// encoder — operators paste the result straight into a
	// RotateVKConfig file.
	enc, err := json.Marshal(tip)
	if err != nil {
		t.Fatalf("marshal tip: %v", err)
	}
	var probe map[string]interface{}
	if err := json.Unmarshal(enc, &probe); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	for _, key := range []string{
		"covenantTxId",
		"covenantVout",
		"covenantSatsLive",
		"currentStateRootHex",
		"currentBlockNumber",
		"lockingScriptHex",
		"lockingScriptSha256",
	} {
		if _, ok := probe[key]; !ok {
			t.Errorf("expected JSON key %q in output", key)
		}
	}
}

// TestBuildCovenantTip_NoAdvanceFallsBackToGenesisTxID covers the
// pre-first-advance path: ReadCovenantTxID is the zero hash, but a
// `<datadir>/genesis.txid` file is present (deploy-shard writes one).
// The tip should report the genesis txid and zero state.
func TestBuildCovenantTip_NoAdvanceFallsBackToGenesisTxID(t *testing.T) {
	chain := &fakeChainReader{} // both fields zero / nil

	dataDir := t.TempDir()
	genesisTxID := strings.Repeat("11", 32)
	if err := os.WriteFile(
		filepath.Join(dataDir, "genesis.txid"),
		[]byte(genesisTxID+"\n"),
		0o644,
	); err != nil {
		t.Fatalf("seed genesis.txid: %v", err)
	}

	fetch := fakeUTXOFetcher(t, 5000, nil)

	tip, err := BuildCovenantTip(chain, fetch, "", dataDir)
	if err != nil {
		t.Fatalf("BuildCovenantTip: %v", err)
	}
	if tip.CovenantTxID != genesisTxID {
		t.Errorf("CovenantTxID fallback: got %q want %q", tip.CovenantTxID, genesisTxID)
	}
	if tip.CurrentBlockNumber != 0 {
		t.Errorf("expected zero block number pre-first-advance, got %d", tip.CurrentBlockNumber)
	}
	if tip.CurrentStateRootHex != (types.Hash{}).Hex() {
		t.Errorf("expected zero state root, got %q", tip.CurrentStateRootHex)
	}
}

// TestBuildCovenantTip_NoAdvanceNoFallback ensures the helper returns
// a clear error rather than silently producing nonsense when the
// chaindata is empty AND no genesis.txid is on disk.
func TestBuildCovenantTip_NoAdvanceNoFallback(t *testing.T) {
	chain := &fakeChainReader{}
	fetch := fakeUTXOFetcher(t, 0, nil)
	_, err := BuildCovenantTip(chain, fetch, "", t.TempDir())
	if err == nil {
		t.Fatal("expected error when no covenant tip and no genesis.txid")
	}
	if !strings.Contains(err.Error(), "no covenant tip") {
		t.Errorf("error should mention missing tip; got %q", err.Error())
	}
}

// TestBuildCovenantTip_AgainstRealChainDB exercises BuildCovenantTip
// with the real ChainDB implementation rather than a hand-rolled fake.
// This catches any drift between the test's surface assumptions and
// pkg/block.ChainDB's actual ReadCovenantTxID / ReadCovenantState
// behaviour.
func TestBuildCovenantTip_AgainstRealChainDB(t *testing.T) {
	chainDB := block.NewChainDB(db.NewMemoryDB())

	// Seed an advanced covenant state.
	state := &covenant.CovenantState{
		StateRoot:   types.HexToHash("0xdeadbeef" + strings.Repeat("00", 28)),
		BlockNumber: 42,
	}
	if err := chainDB.WriteCovenantState(state.Encode()); err != nil {
		t.Fatalf("WriteCovenantState: %v", err)
	}
	bigEndianTxID := strings.Repeat("cd", 32)
	if err := chainDB.WriteCovenantTxID(types.BSVHashFromHex(bigEndianTxID)); err != nil {
		t.Fatalf("WriteCovenantTxID: %v", err)
	}

	tip, err := BuildCovenantTip(chainDB, fakeUTXOFetcher(t, 12345, nil), "shard-real", t.TempDir())
	if err != nil {
		t.Fatalf("BuildCovenantTip: %v", err)
	}
	if tip.CovenantTxID != bigEndianTxID {
		t.Errorf("CovenantTxID: got %q want %q", tip.CovenantTxID, bigEndianTxID)
	}
	if tip.CurrentBlockNumber != 42 {
		t.Errorf("CurrentBlockNumber: got %d want 42", tip.CurrentBlockNumber)
	}
	if tip.CovenantSatsLive != 12345 {
		t.Errorf("CovenantSatsLive: got %d want 12345", tip.CovenantSatsLive)
	}
}

// TestBuildCovenantTip_FetcherEmptyScriptIsError documents that we
// surface a clean error rather than emitting a tip with an empty
// locking script (which would produce an invalid sha256 == sha256("")).
func TestBuildCovenantTip_FetcherEmptyScriptIsError(t *testing.T) {
	state := &covenant.CovenantState{
		StateRoot:   types.HexToHash("0x" + strings.Repeat("11", 32)),
		BlockNumber: 1,
	}
	chain := &fakeChainReader{
		txid:       types.BSVHashFromHex(strings.Repeat("ab", 32)),
		stateBytes: state.Encode(),
	}
	fetch := func(txid string, vout uint32) (string, uint64, error) {
		return "", 0, nil
	}
	_, err := BuildCovenantTip(chain, fetch, "", t.TempDir())
	if err == nil {
		t.Fatal("expected error on empty locking-script hex")
	}
	if !strings.Contains(err.Error(), "empty locking-script hex") {
		t.Errorf("error should mention empty locking-script hex; got %q", err.Error())
	}
}

// TestCovenantTipFlags_ParsesShardIDFlag exercises the urfave/cli
// flag parsing surface: pointing the binary at a temp datadir and
// passing --shard-id should populate the flag without erroring.
// The action itself is NOT invoked (no BSV node available) — this is
// purely a flag-parse smoke check.
func TestCovenantTipFlags_ParsesShardIDFlag(t *testing.T) {
	tmp := t.TempDir()
	cmd := covenantCommand()
	app := &cli.App{Commands: []*cli.Command{cmd}}

	// Replace the action with a recorder so we don't actually call
	// cmdCovenantTip (which would require a live BSV node).
	var captured struct {
		dataDir string
		shardID string
	}
	cmd.Subcommands[0].Action = func(c *cli.Context) error {
		captured.dataDir = c.String("datadir")
		captured.shardID = c.String("shard-id")
		return nil
	}

	if err := app.Run([]string{
		"bsvm", "covenant", "tip",
		"--datadir", tmp,
		"--shard-id", "shard-xyz",
		"--bsv-rpc", "http://example.invalid",
	}); err != nil {
		t.Fatalf("app.Run: %v", err)
	}
	if captured.dataDir != tmp {
		t.Errorf("datadir: got %q want %q", captured.dataDir, tmp)
	}
	if captured.shardID != "shard-xyz" {
		t.Errorf("shard-id: got %q want %q", captured.shardID, "shard-xyz")
	}
}
