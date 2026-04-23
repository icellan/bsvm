// Genesis-from-txid derivation: everything a node needs to boot a
// shard comes from the genesis covenant transaction — vout 0 (the
// covenant locking script) and vout 1 (the OP_RETURN GenesisManifest
// envelope). DeriveShardFromTx fetches that one transaction, parses
// both outputs, and returns a DerivedShard struct.
//
// Cross-validation (in DeriveShardFromTx):
//   1. manifest.ChainID   must equal the chainId pushed into the
//      script's readonly slot
//   2. manifest.Governance must equal the governance mode / threshold
//      / keys pushed into the script's readonly slots
//   3. sha256(manifest.SP1VK) must equal the script's SP1VerifyingKey
//      hash slot
//   4. manifest.VerificationMode must equal the mode detected from
//      the script's template pattern (DetectVerificationMode)
//
// Any mismatch returns an error. The manifest is operator-supplied
// metadata; the covenant script is the authoritative source for
// every overlap.
package shard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bsv-blockchain/go-sdk/transaction"
	runar "github.com/icellan/runar/packages/runar-go"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// TxFetcher is the minimum surface DeriveShardFromTx needs from a
// runar.Provider — kept narrow so tests can inject a stub without
// implementing the full Provider interface.
type TxFetcher interface {
	GetTransaction(txid string) (*runar.TransactionData, error)
}

// DerivedShard carries everything needed to bootstrap a node given a
// genesis covenant outpoint. Treat this struct as read-only after
// DeriveShardFromTx returns.
type DerivedShard struct {
	// GenesisTxID is the txid of the genesis covenant transaction.
	GenesisTxID types.Hash
	// GenesisCovenantVout is the output index of the covenant UTXO
	// (always 0 for deploy-shard, but we record it in case future
	// deploy variants change that).
	GenesisCovenantVout uint32
	// CovenantSats is the satoshi value of the covenant UTXO as
	// reported by the on-chain tx — authoritative over the manifest.
	CovenantSats uint64

	// ChainID is the EVM chain id baked into the script.
	ChainID int64
	// GasLimit is the genesis block gas limit from the manifest.
	GasLimit uint64
	// Verification is the verification mode detected from the script
	// template. Authoritative.
	Verification covenant.VerificationMode
	// Governance is the governance config derived from the manifest,
	// cross-validated against the script's readonly slots.
	Governance covenant.GovernanceConfig
	// SP1VerifyingKey is the full SP1 VK bytes from the manifest.
	SP1VerifyingKey []byte
	// SP1VerifyingKeyHash is sha256(SP1VerifyingKey) — also baked
	// into the script. Matched against the manifest before return.
	SP1VerifyingKeyHash [32]byte

	// Alloc is the genesis account allocation recovered from the
	// manifest, ready to hand to block.InitGenesis.
	Alloc map[types.Address]block.GenesisAccount
	// GenesisStateRoot is the state root recorded in the script's
	// stateful slot (the initial CovenantState.StateRoot). The caller
	// MUST re-run InitGenesis on the derived alloc and verify the
	// resulting root equals this value before trusting the shard.
	GenesisStateRoot types.Hash

	// CovenantLockingScript is the raw hex of the script at vout 0.
	// Retained so downstream callers (e.g. wireBSVBroadcast) can
	// re-derive the deployed contract binding without a second tx
	// fetch.
	CovenantLockingScript string
}

// DeriveShardFromTx fetches a genesis covenant transaction from BSV
// and extracts every config dimension a node needs to run the shard.
// The txid is the only thing required (beyond the Provider).
//
//  1. vout 0: locking script → chainID, governance, SP1 VK hash,
//     initial state root, verification mode (template detection).
//  2. vout 1: OP_RETURN manifest → full SP1 VK, gasLimit, alloc, and
//     the operator-supplied governance manifest (cross-validated).
//
// A mismatch between any script-derived field and its manifest
// counterpart returns an error. Node startup must fail loudly in that
// case — a malformed genesis tx is unrecoverable and running against
// it would silently branch onto a different consensus rule set.
//
// This is now a thin wrapper over DeriveShardFromRawTx: the fetcher
// produces the raw tx hex (or its BEEF equivalent, which we flatten
// to the signed tx bytes), and the derivation proceeds offline from
// those bytes. Callers that don't have BSV RPC access (follower nodes
// after Phase 9) can bypass the fetcher entirely and hand raw bytes
// received over P2P to DeriveShardFromRawTx.
func DeriveShardFromTx(ctx context.Context, fetcher TxFetcher, txidHex string) (*DerivedShard, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("derive: tx fetcher must not be nil")
	}
	if txidHex == "" {
		return nil, fmt.Errorf("derive: genesis txid must not be empty")
	}
	// Honour context cancellation cheaply — the Rúnar Provider API
	// doesn't carry a context, so we check once before the potentially
	// slow RPC and propagate the error.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("derive: context cancelled: %w", err)
	}

	// 1. Fetch the genesis tx.
	tx, err := fetcher.GetTransaction(txidHex)
	if err != nil {
		return nil, fmt.Errorf("derive: fetch genesis tx %s: %w", txidHex, err)
	}
	if tx == nil {
		return nil, fmt.Errorf("derive: tx fetcher returned nil for %s", txidHex)
	}
	if tx.Raw != "" {
		// Preferred path: the provider handed us the raw tx bytes.
		// Delegate to the offline derivation so the fetcher-based and
		// file-based paths exercise a single code path.
		derived, derr := DeriveShardFromRawTx(tx.Raw)
		if derr != nil {
			return nil, derr
		}
		// The fetcher was asked for a specific txid; trust that label
		// and set it on the derived shard so callers see the exact
		// value they asked for (no 0x, no casing surprises).
		// txidHex is a BSV txid (big-endian display form) —
		// BSVHashFromHex stores bytes in chainhash little-endian order.
		derived.GenesisTxID = types.BSVHashFromHex(txidHex)
		return derived, nil
	}
	// Fallback for providers that don't populate Raw — derive from the
	// structured outputs as before. This keeps backwards compatibility
	// with any TxFetcher that predates Phase 9.
	return deriveShardFromTxData(tx, txidHex)
}

// DeriveShardFromRawTx derives shard config from the raw transaction
// bytes without any external I/O. The caller is responsible for
// ensuring the bytes correspond to the expected txid — hash verification
// lives at the boot layer (TxIDFromRawTx), which knows the txid the
// node was configured with.
//
// This is the primary entry point for the Phase 9 follower path: a
// node that has received the raw tx hex over P2P (or read it from a
// local cache file) hands the bytes here and gets back a fully
// validated DerivedShard with no BSV RPC round-trip.
func DeriveShardFromRawTx(rawTxHex string) (*DerivedShard, error) {
	cleaned := strings.TrimSpace(strings.TrimPrefix(rawTxHex, "0x"))
	if cleaned == "" {
		return nil, fmt.Errorf("derive: raw tx hex must not be empty")
	}
	parsed, err := transaction.NewTransactionFromHex(cleaned)
	if err != nil {
		return nil, fmt.Errorf("derive: parse raw tx: %w", err)
	}
	if parsed == nil {
		return nil, fmt.Errorf("derive: parsed tx is nil")
	}
	// Compute the canonical BSV txid (double_sha256 reversed) and use
	// it as the DerivedShard's GenesisTxID. If the caller needed txid
	// verification they did it one layer up — we simply record what
	// the bytes hash to.
	txidHex, err := TxIDFromRawTx(cleaned)
	if err != nil {
		return nil, fmt.Errorf("derive: compute txid: %w", err)
	}
	// Convert to the runar.TransactionData shape the existing helpers
	// already understand. The manifest locator and script-extraction
	// code both want hex-encoded scripts and int64 satoshis per output,
	// so this adapter is cheap.
	adapted := txDataFromSDKTransaction(parsed, txidHex)
	return deriveShardFromTxData(adapted, txidHex)
}

// TxIDFromRawTx computes double_sha256 over the raw tx bytes and
// returns the byte-reversed 32-byte result encoded as lowercase hex
// (the standard BSV txid representation). No "0x" prefix.
//
// The function accepts either plain hex or a "0x"-prefixed string,
// and is tolerant of surrounding whitespace. It does NOT attempt to
// re-parse the tx — the hash is computed over whatever bytes the hex
// decodes to, exactly like the network does.
func TxIDFromRawTx(rawTxHex string) (string, error) {
	cleaned := strings.TrimSpace(strings.TrimPrefix(rawTxHex, "0x"))
	if cleaned == "" {
		return "", fmt.Errorf("txid: raw tx hex must not be empty")
	}
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return "", fmt.Errorf("txid: decode hex: %w", err)
	}
	first := sha256.Sum256(raw)
	second := sha256.Sum256(first[:])
	// Reverse the 32-byte digest for BSV's little-endian display form.
	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = second[31-i]
	}
	return hex.EncodeToString(reversed), nil
}

// VerifyRawTxMatchesTxID is the single, auditable hash-verification
// helper. Every path in the boot layer that consumes raw tx bytes
// from an untrusted source (file, peer, RPC) MUST call this before
// trusting the derivation. Returns nil iff the hash of the bytes
// matches the lowercase hex expectedTxID (with any 0x prefix
// stripped on either side).
func VerifyRawTxMatchesTxID(rawTxHex, expectedTxID string) error {
	got, err := TxIDFromRawTx(rawTxHex)
	if err != nil {
		return fmt.Errorf("verify: compute txid: %w", err)
	}
	want := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(expectedTxID, "0x")))
	if got != want {
		return fmt.Errorf("verify: raw tx hash %s does not match expected txid %s", got, want)
	}
	return nil
}

// txDataFromSDKTransaction adapts a parsed *transaction.Transaction
// into the runar.TransactionData shape the existing helpers consume.
// This keeps derive_helpers.go untouched — the helpers accept a single
// input type, and callers with either representation converge here.
func txDataFromSDKTransaction(tx *transaction.Transaction, txidHex string) *runar.TransactionData {
	outs := make([]runar.TxOutput, 0, len(tx.Outputs))
	for _, o := range tx.Outputs {
		scriptHex := ""
		if o.LockingScript != nil {
			scriptHex = hex.EncodeToString(*o.LockingScript)
		}
		// TxOutput.Satoshis is int64 in the runar wire shape; our
		// outputs always fit in positive int64 for BSV.
		outs = append(outs, runar.TxOutput{
			Satoshis: int64(o.Satoshis),
			Script:   scriptHex,
		})
	}
	return &runar.TransactionData{
		Txid:    txidHex,
		Version: int(tx.Version),
		Outputs: outs,
	}
}

// deriveShardFromTxData is the core derivation worker. It's shared
// between the raw-bytes path (DeriveShardFromRawTx) and the fetcher
// path (DeriveShardFromTx) so cross-validation, manifest parsing, and
// alloc reconstruction all happen in exactly one place. No external
// I/O — purely a function of the supplied tx data + txid string.
func deriveShardFromTxData(tx *runar.TransactionData, txidHex string) (*DerivedShard, error) {
	if len(tx.Outputs) < 2 {
		return nil, fmt.Errorf("derive: genesis tx %s has %d outputs, need at least 2 (covenant + manifest)", txidHex, len(tx.Outputs))
	}

	// 2. Parse the covenant output (vout 0). We don't support non-zero
	// covenant vouts yet — the deploy helper always places the
	// covenant at index 0.
	covenantOut := tx.Outputs[0]
	if covenantOut.Script == "" {
		return nil, fmt.Errorf("derive: covenant output (vout 0) has empty script")
	}
	if covenantOut.Satoshis < 0 {
		return nil, fmt.Errorf("derive: covenant output has negative satoshis %d", covenantOut.Satoshis)
	}
	covenantSats := uint64(covenantOut.Satoshis)

	// 3. Locate the OP_RETURN manifest. The manifest can appear in
	// any output (except vout 0) that is OP_FALSE OP_RETURN-prefixed
	// and whose first push starts with the GenesisManifestMagic;
	// vout 1 is the canonical location but tolerate additional
	// prefix outputs so future deploy-tx layouts don't break older
	// nodes.
	manifestBytes, err := findManifestPayload(tx)
	if err != nil {
		return nil, fmt.Errorf("derive: locate manifest OP_RETURN: %w", err)
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("derive: decode manifest: %w", err)
	}

	// 4. Take the manifest's claimed verification mode.
	verifyMode, err := manifest.ToVerificationMode()
	if err != nil {
		return nil, fmt.Errorf("derive: manifest verification mode: %w", err)
	}

	// 5. Build the typed governance config from the manifest and
	// validate it.
	govConfig, err := manifest.ToGovernanceConfig()
	if err != nil {
		return nil, fmt.Errorf("derive: manifest governance: %w", err)
	}
	if err := govConfig.Validate(); err != nil {
		return nil, fmt.Errorf("derive: manifest governance invalid: %w", err)
	}

	// 6. Decode the manifest's SP1 VK.
	sp1VK, err := hex.DecodeString(manifest.SP1VerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("derive: decode manifest sp1VK hex: %w", err)
	}
	vkHashFromManifest := sha256.Sum256(sp1VK)

	// 7. Cross-validate the manifest against the deployed script.
	if err := verifyCovenantCodeMatches(verifyMode, covenantOut.Script, sp1VK, uint64(manifest.ChainID), govConfig); err != nil {
		return nil, fmt.Errorf("derive: script/manifest disagreement: %w", err)
	}

	// 8. Build the alloc map.
	alloc, err := manifest.BuildAlloc()
	if err != nil {
		return nil, fmt.Errorf("derive: build alloc: %w", err)
	}

	// 9. Extract the genesis state root from the deployed script's
	// state section.
	stateRoot, err := extractScriptGenesisStateRoot(verifyMode, covenantOut.Script)
	if err != nil {
		return nil, fmt.Errorf("derive: extract genesis state root: %w", err)
	}

	return &DerivedShard{
		// txidHex is the BSV-canonical big-endian display form
		// (produced by TxIDFromRawTx); reverse into little-endian
		// chainhash bytes for in-memory storage.
		GenesisTxID:           types.BSVHashFromHex(txidHex),
		GenesisCovenantVout:   0,
		CovenantSats:          covenantSats,
		ChainID:               manifest.ChainID,
		GasLimit:              manifest.GasLimit,
		Verification:          verifyMode,
		Governance:            govConfig,
		SP1VerifyingKey:       sp1VK,
		SP1VerifyingKeyHash:   vkHashFromManifest,
		Alloc:                 alloc,
		GenesisStateRoot:      stateRoot,
		CovenantLockingScript: covenantOut.Script,
	}, nil
}
