package shard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"
	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// mockFetcher is a test stub implementing TxFetcher by returning a
// pre-loaded TransactionData object.
type mockFetcher struct {
	tx  *runar.TransactionData
	err error
}

func (m *mockFetcher) GetTransaction(txid string) (*runar.TransactionData, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.tx, nil
}

// deriveTestFixture compiles a real FRI covenant with the given
// chainID / sp1VK / gov, produces its locking script with the given
// runtime state fields, and builds an OP_RETURN output carrying the
// manifest. Returns the fixture pieces a test can feed to a mock
// fetcher + DeriveShardFromTx.
//
// This uses the actual gocompiler to keep the cross-validation path
// honest — extracting chainID / VK hash / governance from a hand-rolled
// script would hide bugs in the helpers.
func deriveTestFixture(t *testing.T, chainID int64, sp1VK []byte, gov covenant.GovernanceConfig, stateRoot types.Hash, alloc map[string]GenesisAllocEntry) (*runar.TransactionData, *GenesisManifest) {
	t.Helper()

	// 1. Compile the real FRI covenant — bakes all readonly slots.
	compiled, err := covenant.CompileFRIRollup(sp1VK, uint64(chainID), gov)
	if err != nil {
		t.Fatalf("CompileFRIRollup: %v", err)
	}
	baseScriptHex := hex.EncodeToString(compiled.LockingScript)

	// 2. Append the stateful state data section. Layout mirrors the
	// Rúnar runtime constructor output for the FRI template:
	//   <stateRoot push32> <blockNumber script-num (0 → OP_0)> <frozen
	//   (0 → OP_0)> OP_RETURN
	// The Rúnar compiler places the state portion AFTER an OP_RETURN
	// separator. The sticker is that our compiled artifact already
	// includes the full readonly+code portion; we need to append the
	// state-data OP_RETURN + state pushes. To avoid re-implementing
	// the compiler's state emitter, we instead build a fresh artifact
	// by calling BuildFromTxId-style logic: treat the test as already
	// having a runtime state section. Simpler: run Rúnar Go's runtime
	// constructor through NewRunarContract(artifact, runtimeArgs) and
	// use GetLockingScript.
	artifact, err := artifactForMode(covenant.VerifyFRI)
	if err != nil {
		t.Fatalf("artifactForMode: %v", err)
	}
	// Baked artifact: since BuildFRIConstructorArgsExported was used,
	// artifact has no ConstructorSlots. We bake the same readonly args
	// and pass only the 3 mutable state values so the SDK produces the
	// complete locking script.
	constructorArgs, err := covenant.BuildFRIConstructorArgsExported(sp1VK, uint64(chainID), gov)
	if err != nil {
		t.Fatalf("BuildFRIConstructorArgsExported: %v", err)
	}
	bakedArt, err := compileFRIWithArgs(constructorArgs)
	if err != nil {
		t.Fatalf("compileFRIWithArgs: %v", err)
	}
	_ = artifact
	stateRootHex := strings.TrimPrefix(stateRoot.Hex(), "0x")
	contract := runar.NewRunarContract(bakedArt, []interface{}{
		stateRootHex,
		int64(0), // blockNumber
		int64(0), // frozen
	})
	scriptHex := contract.GetLockingScript()
	if scriptHex == "" {
		t.Fatalf("GetLockingScript returned empty")
	}

	// 3. Build the manifest + encode to OP_RETURN bytes.
	manifest := &GenesisManifest{
		Version:          GenesisManifestVersion,
		ChainID:          chainID,
		GasLimit:         30_000_000,
		VerificationMode: "fri",
		SP1VerifyingKey:  hex.EncodeToString(sp1VK),
		Governance:       GovernanceFromConfig(gov),
		Alloc:            alloc,
		CovenantSats:     10000,
		Timestamp:        1_700_000_000,
	}
	envelope, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	opReturnScript := buildOpReturn(envelope)
	_ = baseScriptHex

	return &runar.TransactionData{
		Txid:    "00" + strings.Repeat("11", 31),
		Version: 1,
		Outputs: []runar.TxOutput{
			{
				Satoshis: 10000,
				Script:   scriptHex,
			},
			{
				Satoshis: 0,
				Script:   opReturnScript,
			},
		},
	}, manifest
}

// artifactForMode is a thin wrapper around loadTemplateArtifact for
// tests in the same package.
func artifactForMode(mode covenant.VerificationMode) (*runar.RunarArtifact, error) {
	return loadTemplateArtifact(mode)
}

// compileFRIWithArgs compiles the FRI contract source with the given
// constructor args and returns the resulting runar.RunarArtifact.
func compileFRIWithArgs(args map[string]interface{}) (*runar.RunarArtifact, error) {
	src := findCovenantContractPath("rollup_fri.runar.go")
	compiled, err := gocompiler.CompileFromSource(src, gocompiler.CompileOptions{
		ConstructorArgs: args,
	})
	if err != nil {
		return nil, err
	}
	return gocompilerArtifactToSDK(compiled)
}

// buildOpReturn wraps a data payload in OP_FALSE OP_RETURN OP_PUSHDATA4
// <len-le4> <payload> so it resembles what the deploy helper emits.
// OP_PUSHDATA4 is fine for any payload size.
func buildOpReturn(payload []byte) string {
	buf := make([]byte, 0, 2+5+len(payload))
	buf = append(buf, 0x00, 0x6a) // OP_FALSE OP_RETURN
	buf = append(buf, 0x4e)       // OP_PUSHDATA4
	var lenLE [4]byte
	binary.LittleEndian.PutUint32(lenLE[:], uint32(len(payload)))
	buf = append(buf, lenLE[:]...)
	buf = append(buf, payload...)
	return hex.EncodeToString(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDeriveShardFromTx_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy test in short mode")
	}
	chainID := int64(31337)
	sp1VK := make([]byte, 32)
	sp1VK[0] = 0xde
	sp1VK[1] = 0xad
	gov := covenant.GovernanceConfig{
		Mode: covenant.GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	stateRoot := types.BytesToHash(sha256.New().Sum([]byte("abc")))
	// Ensure stateRoot is exactly 32 bytes.
	h := sha256.Sum256([]byte("genesis-state-root"))
	stateRoot = types.BytesToHash(h[:])

	alloc := map[string]GenesisAllocEntry{
		"1111111111111111111111111111111111111111": {BalanceWei: "1000"},
	}
	tx, manifest := deriveTestFixture(t, chainID, sp1VK, gov, stateRoot, alloc)

	mf := &mockFetcher{tx: tx}
	ds, err := DeriveShardFromTx(context.Background(), mf, strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("DeriveShardFromTx: %v", err)
	}

	if ds.ChainID != chainID {
		t.Errorf("ChainID = %d, want %d", ds.ChainID, chainID)
	}
	if ds.Verification != covenant.VerifyFRI {
		t.Errorf("Verification = %s, want fri", ds.Verification.String())
	}
	if ds.GenesisStateRoot != stateRoot {
		t.Errorf("GenesisStateRoot mismatch: got %x, want %x", ds.GenesisStateRoot[:], stateRoot[:])
	}
	vkHash := sha256.Sum256(sp1VK)
	if ds.SP1VerifyingKeyHash != vkHash {
		t.Errorf("SP1 VK hash mismatch")
	}
	if len(ds.Alloc) != 1 {
		t.Errorf("Alloc length = %d, want 1", len(ds.Alloc))
	}
	if ds.CovenantSats != 10000 {
		t.Errorf("CovenantSats = %d, want 10000", ds.CovenantSats)
	}
	if ds.Governance.Mode != covenant.GovernanceSingleKey {
		t.Errorf("Governance mode = %v, want single_key", ds.Governance.Mode)
	}
	_ = manifest
}

func TestDeriveShardFromTx_MissingOpReturn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy test in short mode")
	}
	chainID := int64(31337)
	sp1VK := make([]byte, 32)
	gov := covenant.GovernanceConfig{
		Mode: covenant.GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	h := sha256.Sum256([]byte("r"))
	tx, _ := deriveTestFixture(t, chainID, sp1VK, gov, types.BytesToHash(h[:]), nil)

	// Remove the manifest output.
	tx.Outputs = tx.Outputs[:1]

	mf := &mockFetcher{tx: tx}
	_, err := DeriveShardFromTx(context.Background(), mf, strings.Repeat("ab", 32))
	if err == nil {
		t.Fatal("expected error for missing OP_RETURN manifest")
	}
}

func TestDeriveShardFromTx_BadManifestMagic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy test in short mode")
	}
	chainID := int64(31337)
	sp1VK := make([]byte, 32)
	gov := covenant.GovernanceConfig{
		Mode: covenant.GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	h := sha256.Sum256([]byte("r"))
	tx, _ := deriveTestFixture(t, chainID, sp1VK, gov, types.BytesToHash(h[:]), nil)

	// Corrupt the OP_RETURN payload so the magic no longer matches.
	tx.Outputs[1].Script = "006a" // Just OP_FALSE OP_RETURN, no payload
	mf := &mockFetcher{tx: tx}
	_, err := DeriveShardFromTx(context.Background(), mf, strings.Repeat("ab", 32))
	if err == nil {
		t.Fatal("expected error for missing magic")
	}
}

func TestDeriveShardFromTx_ChainIDMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy test in short mode")
	}
	chainID := int64(31337)
	sp1VK := make([]byte, 32)
	gov := covenant.GovernanceConfig{
		Mode: covenant.GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	h := sha256.Sum256([]byte("r"))
	tx, manifest := deriveTestFixture(t, chainID, sp1VK, gov, types.BytesToHash(h[:]), nil)

	// Rewrite the manifest with a wrong chainID.
	manifest.ChainID = 99999
	envelope, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	tx.Outputs[1].Script = buildOpReturn(envelope)

	mf := &mockFetcher{tx: tx}
	_, derr := DeriveShardFromTx(context.Background(), mf, strings.Repeat("ab", 32))
	if derr == nil {
		t.Fatal("expected chainID mismatch error")
	}
	if !strings.Contains(derr.Error(), "chainID") {
		t.Errorf("expected chainID in error, got %v", derr)
	}
}

// TestDeriveShardFromTx_GovernanceKeyMismatch exercises the
// code-section cross-check: if the manifest claims one governance
// key and the deployed covenant was compiled with another, the
// recompile produces a script whose byte pattern differs and
// DeriveShardFromTx refuses to load the shard.
//
// Note: the FRI template does not enforce the SP1 VK hash in the
// locking script (Mode 1 performs no on-chain proof check), so a
// mismatched manifest VK is not caught by this code-section compare
// — operators are trusted for that field on Mode 1 shards. The
// Groth16 / Groth16-WA templates DO bake the VK hash and would
// catch a wrong VK through the same mechanism when those modes
// wire up in a future phase.
func TestDeriveShardFromTx_GovernanceKeyMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy test in short mode")
	}
	chainID := int64(31337)
	sp1VK := make([]byte, 32)
	sp1VK[0] = 0x01
	gov := covenant.GovernanceConfig{
		Mode: covenant.GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	h := sha256.Sum256([]byte("r"))
	tx, manifest := deriveTestFixture(t, chainID, sp1VK, gov, types.BytesToHash(h[:]), nil)

	// Rewrite manifest with a DIFFERENT governance key; the covenant
	// script bakes the key as a compile-time pushdata, so the
	// recompile will differ.
	alt := testKey(2)
	manifest.Governance.Keys = []string{hex.EncodeToString(alt)}
	envelope, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	tx.Outputs[1].Script = buildOpReturn(envelope)

	mf := &mockFetcher{tx: tx}
	_, derr := DeriveShardFromTx(context.Background(), mf, strings.Repeat("ab", 32))
	if derr == nil {
		t.Fatal("expected governance key mismatch error")
	}
	if !strings.Contains(derr.Error(), "disagreement") && !strings.Contains(derr.Error(), "disagree") {
		t.Errorf("expected disagreement error, got %v", derr)
	}
}

func TestDeriveShardFromTx_NilFetcher(t *testing.T) {
	_, err := DeriveShardFromTx(context.Background(), nil, "abc")
	if err == nil {
		t.Fatal("expected error for nil fetcher")
	}
}

func TestDeriveShardFromTx_EmptyTxID(t *testing.T) {
	_, err := DeriveShardFromTx(context.Background(), &mockFetcher{}, "")
	if err == nil {
		t.Fatal("expected error for empty txid")
	}
}

func TestDeriveShardFromTx_FetcherError(t *testing.T) {
	mf := &mockFetcher{err: fmt.Errorf("network down")}
	_, err := DeriveShardFromTx(context.Background(), mf, strings.Repeat("ab", 32))
	if err == nil {
		t.Fatal("expected error from failing fetcher")
	}
}

// Silence unused-import noise for bytes, uint256, big when tests are
// trimmed down during iteration.
var (
	_ = bytes.Compare
	_ = (*uint256.Int)(nil)
	_ = (*big.Int)(nil)
)

// ---------------------------------------------------------------------------
// Phase 9 — DeriveShardFromRawTx / TxIDFromRawTx / VerifyRawTxMatchesTxID
// ---------------------------------------------------------------------------

// buildRawTxFromFixture constructs a real BSV transaction carrying the
// given locking-script outputs and returns (rawHex, txidHex). Used by
// the Phase 9 tests that exercise the raw-bytes derivation path.
// Outputs are encoded as (satoshis LE uint64 || varint scriptLen ||
// scriptBytes).
func buildRawTxFromFixture(t *testing.T, outputs []runar.TxOutput) (string, string) {
	t.Helper()
	// Version (4B LE) = 1. No inputs (VarInt 0). Outputs list.
	// Locktime (4B LE) = 0.
	var out []byte
	out = append(out, 0x01, 0x00, 0x00, 0x00) // version = 1 LE
	out = append(out, 0x00)                   // input count varint = 0
	// output count varint
	out = append(out, byte(len(outputs)))
	for _, o := range outputs {
		// 8 bytes sats LE
		var sats [8]byte
		binary.LittleEndian.PutUint64(sats[:], uint64(o.Satoshis))
		out = append(out, sats[:]...)
		scriptBytes, err := hex.DecodeString(o.Script)
		if err != nil {
			t.Fatalf("decode script hex: %v", err)
		}
		out = append(out, encodeVarInt(uint64(len(scriptBytes)))...)
		out = append(out, scriptBytes...)
	}
	out = append(out, 0x00, 0x00, 0x00, 0x00) // locktime
	rawHex := hex.EncodeToString(out)
	txid, err := TxIDFromRawTx(rawHex)
	if err != nil {
		t.Fatalf("TxIDFromRawTx: %v", err)
	}
	return rawHex, txid
}

func encodeVarInt(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		b := []byte{0xfd, 0, 0}
		binary.LittleEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xffffffff:
		b := []byte{0xfe, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.LittleEndian.PutUint64(b[1:], n)
		return b
	}
}

// TestTxIDFromRawTx verifies double_sha256 + byte-reverse over a
// minimal hand-assembled transaction reproduces the BSV txid.
func TestTxIDFromRawTx(t *testing.T) {
	// Known test vector: empty tx (version=1, no inputs, no outputs,
	// locktime=0). BSV treats this as malformed but the hashing
	// function itself is defined over arbitrary bytes.
	raw := "01000000000000000000"
	got, err := TxIDFromRawTx(raw)
	if err != nil {
		t.Fatalf("TxIDFromRawTx: %v", err)
	}
	// Compute expected via double-sha256 + reverse.
	want := func() string {
		b, _ := hex.DecodeString(raw)
		h1 := sha256.Sum256(b)
		h2 := sha256.Sum256(h1[:])
		rev := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rev[i] = h2[31-i]
		}
		return hex.EncodeToString(rev)
	}()
	if got != want {
		t.Errorf("txid = %s, want %s", got, want)
	}

	// 0x-prefixed input should produce the same result.
	got2, err := TxIDFromRawTx("0x" + raw)
	if err != nil {
		t.Fatalf("TxIDFromRawTx(0x): %v", err)
	}
	if got2 != want {
		t.Errorf("0x-prefixed txid = %s, want %s", got2, want)
	}

	// Empty string is an error.
	if _, err := TxIDFromRawTx(""); err == nil {
		t.Fatal("expected error for empty input")
	}
	// Non-hex input is an error.
	if _, err := TxIDFromRawTx("zz"); err == nil {
		t.Fatal("expected error for non-hex input")
	}
}

// TestVerifyRawTxMatchesTxID spot-checks the centralised hash check.
func TestVerifyRawTxMatchesTxID(t *testing.T) {
	raw := "01000000000000000000"
	txid, err := TxIDFromRawTx(raw)
	if err != nil {
		t.Fatalf("TxIDFromRawTx: %v", err)
	}
	if err := VerifyRawTxMatchesTxID(raw, txid); err != nil {
		t.Errorf("VerifyRawTxMatchesTxID(match) = %v, want nil", err)
	}
	if err := VerifyRawTxMatchesTxID(raw, "0x"+txid); err != nil {
		t.Errorf("VerifyRawTxMatchesTxID(0x-prefixed match) = %v, want nil", err)
	}
	if err := VerifyRawTxMatchesTxID(raw, strings.ToUpper(txid)); err != nil {
		t.Errorf("VerifyRawTxMatchesTxID(upper match) = %v, want nil", err)
	}
	// A deliberately wrong txid must fail.
	wrong := strings.Repeat("00", 32)
	if err := VerifyRawTxMatchesTxID(raw, wrong); err == nil {
		t.Error("expected hash mismatch error")
	}
}

// TestDeriveShardFromRawTx_Equivalence builds a deploy-tx fixture,
// serialises it to raw bytes, and confirms DeriveShardFromRawTx yields
// the same DerivedShard as the fetcher-based DeriveShardFromTx. This
// is the contract the Phase 9 boot layer relies on: both paths MUST
// produce identical results.
func TestDeriveShardFromRawTx_Equivalence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile-heavy test in short mode")
	}
	chainID := int64(31337)
	sp1VK := make([]byte, 32)
	sp1VK[0] = 0xab
	gov := covenant.GovernanceConfig{
		Mode: covenant.GovernanceSingleKey,
		Keys: [][]byte{testKey(1)},
	}
	h := sha256.Sum256([]byte("genesis-state-root-for-raw-tx-test"))
	stateRoot := types.BytesToHash(h[:])
	alloc := map[string]GenesisAllocEntry{
		"2222222222222222222222222222222222222222": {BalanceWei: "42"},
	}
	tx, _ := deriveTestFixture(t, chainID, sp1VK, gov, stateRoot, alloc)

	// Serialise the TransactionData outputs into a real BSV tx so
	// DeriveShardFromRawTx re-parses them via go-sdk and produces the
	// same adapted runar.TransactionData internally.
	rawHex, txid := buildRawTxFromFixture(t, tx.Outputs)

	dsRaw, err := DeriveShardFromRawTx(rawHex)
	if err != nil {
		t.Fatalf("DeriveShardFromRawTx: %v", err)
	}
	// The raw-bytes path records the actual hash of the bytes as the
	// GenesisTxID — compare against our test-computed txid.
	if strings.TrimPrefix(dsRaw.GenesisTxID.Hex(), "0x") != txid {
		t.Errorf("DeriveShardFromRawTx GenesisTxID = %s, want %s", dsRaw.GenesisTxID.Hex(), txid)
	}
	if dsRaw.ChainID != chainID {
		t.Errorf("ChainID = %d, want %d", dsRaw.ChainID, chainID)
	}
	if dsRaw.GenesisStateRoot != stateRoot {
		t.Errorf("GenesisStateRoot mismatch")
	}
	if dsRaw.Verification != covenant.VerifyFRI {
		t.Errorf("Verification = %s, want fri", dsRaw.Verification.String())
	}

	// Now run the fetcher path against the same fixture and confirm
	// both DerivedShards agree on every cross-validated field.
	mf := &mockFetcher{tx: tx}
	dsFetch, ferr := DeriveShardFromTx(context.Background(), mf, txid)
	if ferr != nil {
		t.Fatalf("DeriveShardFromTx: %v", ferr)
	}
	if dsRaw.ChainID != dsFetch.ChainID {
		t.Errorf("ChainID disagree: raw=%d fetch=%d", dsRaw.ChainID, dsFetch.ChainID)
	}
	if dsRaw.GenesisStateRoot != dsFetch.GenesisStateRoot {
		t.Errorf("GenesisStateRoot disagree: raw=%x fetch=%x",
			dsRaw.GenesisStateRoot[:], dsFetch.GenesisStateRoot[:])
	}
	if dsRaw.Verification != dsFetch.Verification {
		t.Errorf("Verification disagree")
	}
	if dsRaw.SP1VerifyingKeyHash != dsFetch.SP1VerifyingKeyHash {
		t.Errorf("SP1 VK hash disagree")
	}
	if len(dsRaw.Alloc) != len(dsFetch.Alloc) {
		t.Errorf("Alloc length disagree")
	}
}

func TestDeriveShardFromRawTx_EmptyInput(t *testing.T) {
	if _, err := DeriveShardFromRawTx(""); err == nil {
		t.Fatal("expected error for empty raw hex")
	}
	if _, err := DeriveShardFromRawTx("not-hex"); err == nil {
		t.Fatal("expected error for non-hex raw")
	}
}
