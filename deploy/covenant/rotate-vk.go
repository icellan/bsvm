// covenantdeploy — rotate-vk library half.
//
// This file is the rotation core. The cmd/rotate-vk/main.go wrapper
// parses CLI flags and calls RunRotateVK; the integration test
// exercises the same path with a fixture config.
//
// What rotate-vk does
// -------------------
// Given:
//
//   - The current shard config (verification mode, governance keys,
//     chainID — same JSON shape as compile.go's OperatorConfig).
//   - A NEW guest ELF / VK hash file (default
//     prover/guest/elf/SP1VerifyingKeyHash.txt, override via --vk-hash-file).
//   - A governance signature (or M-of-N bundle for multisig shards).
//
// It:
//
//  1. Reads the NEW VK hash file and asserts it parses as 32 bytes.
//  2. Re-compiles the rollup covenant with the NEW hash, identical
//     governance config + chainID. Spec 12 mandates that ONLY the
//     VK hash differs across the rotation; chainID + governance
//     MUST be unchanged.
//  3. Writes a JSON summary identical in shape to compile.go's so
//     downstream tooling can diff old/new locking-script hex.
//  4. Builds an upgrade tx that consumes the existing covenant UTXO
//     and creates a new output under the rebuilt locking script.
//     The Upgrade method on the rollup contract requires a valid
//     governance signature per spec 12; this binary attaches it.
//  5. Outputs the signed-tx hex + JSON summary.
//
// What rotate-vk does NOT do
// --------------------------
//   - It never advances state; the upgrade path uses the governance
//     signature, not a SP1 proof.
//   - It never modifies the bridge covenant. The bridge has its own
//     StateCovenantScriptHash readonly that pins to the OLD rollup
//     script. Rotating the rollup VK changes the rollup script bytes,
//     which means the bridge's StateCovenantScriptHash NO LONGER
//     matches. Downstream node operators MUST run a separate bridge
//     redeploy after the rollup rotation lands. This is documented in
//     deploy/covenant/README.md §rotate-vk.
//
// Why the bridge is not auto-rotated
// ---------------------------------
// The bridge's withdrawal commitment chain is stateful — rotating
// it without operator review would invalidate every queued
// withdrawal proof. The operator must drain pending withdrawals or
// re-prove them against the new bridge before swapping. We
// intentionally make this a manual step.
package covenantdeploy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/covenant"
)

// RotateVKConfig is the input shape for the rotate-vk binary. It is
// a strict superset of OperatorConfig — every field is optional EXCEPT
// the rotation-specific ones, because the deployer typically already
// has the OperatorConfig file from the original deploy.
type RotateVKConfig struct {
	// OperatorConfig fields are inlined. Re-using compile.go's
	// validation keeps a single source of truth for shape rules.
	OperatorConfig

	// CovenantTxID identifies the live covenant UTXO on BSV that
	// the rotation will spend. Required.
	CovenantTxID string `json:"covenantTxId"`
	// CovenantVout is the output index of the live covenant within
	// CovenantTxID. Required.
	CovenantVout uint32 `json:"covenantVout"`
	// CovenantSats is the satoshi value carried by the live UTXO.
	// Required for fee math; the rebuilt output will inherit the
	// same value.
	CovenantSatsLive uint64 `json:"covenantSatsLive"`
	// GovernanceSigsHex is a list of 64+ byte hex-encoded ECDSA
	// signatures (one per active governance key). Required for any
	// governance mode other than "none"; the rotation cannot
	// proceed under "none" because no key exists to authorise the
	// upgrade.
	GovernanceSigsHex []string `json:"governanceSigsHex"`
	// NewVKHashFile is the path to the NEW SP1VerifyingKeyHash.txt
	// stamped by the operator after `cargo prove vkey`. When empty,
	// defaults to prover/guest/elf/SP1VerifyingKeyHash.txt — i.e.
	// the in-tree pin.
	NewVKHashFile string `json:"newVKHashFile,omitempty"`

	// CurrentStateRootHex is the live covenant's StateRoot readonly.
	// Required in --broadcast mode because the upgrade method's
	// publicValues blob asserts pv[0..32) == c.StateRoot. Operators
	// read this from the existing pkg/covenant.RollupState (or by
	// parsing the live UTXO's locking script).
	CurrentStateRootHex string `json:"currentStateRootHex,omitempty"`

	// CurrentBlockNumber is the live covenant's BlockNumber readonly.
	// Required in --broadcast mode; the upgrade tx advances this to
	// CurrentBlockNumber + 1 and the on-chain assertion checks the
	// match.
	CurrentBlockNumber uint64 `json:"currentBlockNumber,omitempty"`

	// ProofBundlePath, when set, points to a JSON file with a fresh
	// SP1 proof's publicValues / batchData / proofBlob hex strings
	// that the rotation should bind to. When empty, the binary uses
	// SyntheticUpgradeProofBundle to fabricate a shape-correct
	// stand-in (which will FAIL the on-chain SP1 verifier — only
	// useful for assembling-and-signing dry runs and unit tests).
	ProofBundlePath string `json:"proofBundlePath,omitempty"`

	// PartialSigOutPath is where the binary writes the partially-
	// signed upgrade tx when not all governance signatures have been
	// collected. Mandatory for multisig rotations until the M-of-N
	// coordination workflow is automated. Defaults to
	// "rotate-vk.partial.txhex" alongside the config file when empty.
	PartialSigOutPath string `json:"partialSigOutPath,omitempty"`
}

// proofBundle is the on-disk shape of a fresh SP1 proof bundle, parsed
// when RotateVKConfig.ProofBundlePath is set. All three fields are
// hex-encoded byte strings; the publicValues field must be exactly
// 280 bytes per spec 12.
type proofBundle struct {
	PublicValuesHex string `json:"publicValuesHex"`
	BatchDataHex    string `json:"batchDataHex"`
	ProofBlobHex    string `json:"proofBlobHex"`
}

// RotateSummary is the JSON shape rotate-vk emits.
type RotateSummary struct {
	ShardID            string `json:"shardId"`
	ChainID            uint64 `json:"chainId"`
	OldVKHash          string `json:"oldVKHash,omitempty"`
	NewVKHash          string `json:"newVKHash"`
	NewVKHashSource    string `json:"newVKHashSource"`
	OldRollupScript    string `json:"oldRollupScriptHex,omitempty"`
	NewRollupScript    string `json:"newRollupScriptHex"`
	UpgradeTxIDPredict string `json:"upgradeTxidPredicted,omitempty"`
	UpgradeTxIDActual  string `json:"upgradeTxidActual,omitempty"`
	// UpgradeTxHex is the fully-built (and possibly partially-signed)
	// upgrade transaction. Emitted in --broadcast mode so the operator
	// can audit + co-sign + broadcast manually if the binary's ARC
	// path fails. Multi-sig rotations with insufficient signatures
	// surface the partial tx here AND set UpgradeTxAwaitingSigs.
	UpgradeTxHex          string `json:"upgradeTxHex,omitempty"`
	UpgradeTxAwaitingSigs int    `json:"upgradeTxAwaitingSigs,omitempty"`
	UpgradeUnlockHex      string `json:"upgradeUnlockHex,omitempty"`
	UpgradeMethod         string `json:"upgradeMethod,omitempty"`
	Broadcast             bool   `json:"broadcast"`
	GeneratedAt           string `json:"generatedAt"`
}

// RotateOptions packages the CLI flag set used by the rotate-vk
// entry point.
type RotateOptions struct {
	ConfigPath string
	OldVKFile  string
	DryRun     bool
	Broadcast  bool
	OutPath    string
}

// RunRotateVK is the rotation binary's main loop. The cmd/rotate-vk
// wrapper is a thin flag parser that calls this. The integration
// test exercises the same path against a fixture.
func RunRotateVK(opts RotateOptions) error {
	if opts.ConfigPath == "" {
		return errors.New("--config is required")
	}
	if opts.Broadcast {
		opts.DryRun = false
	}

	cfg, err := LoadRotateVKConfig(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	if err := cfg.OperatorConfig.Validate(false); err != nil {
		return fmt.Errorf("validate base config: %w", err)
	}
	if err := cfg.ValidateRotation(opts.Broadcast); err != nil {
		return fmt.Errorf("validate rotation: %w", err)
	}

	// Compile NEW rollup. We re-use Compile() with NewVKHashFile
	// substituted in so the same code path produces both halves of
	// the diff. Funding inputs are NOT used (the upgrade tx spends
	// the live covenant, not a fresh P2PKH UTXO).
	cfgForNew := cfg.OperatorConfig
	cfgForNew.VKHashFile = cfg.NewVKHashFile
	cfgForNew.FundingTxID = "" // suppress unsigned-tx construction
	resNew, err := Compile(&cfgForNew)
	if err != nil {
		return fmt.Errorf("compile NEW rollup: %w", err)
	}

	summary := RotateSummary{
		ShardID:         cfg.ShardID,
		ChainID:         cfg.ChainID,
		NewVKHash:       resNew.VKHashHex,
		NewVKHashSource: resNew.VKHashSource,
		NewRollupScript: hex.EncodeToString(resNew.RollupScript),
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	// Optional OLD rollup compile, only for the summary diff.
	if opts.OldVKFile != "" {
		cfgForOld := cfg.OperatorConfig
		cfgForOld.VKHashFile = opts.OldVKFile
		cfgForOld.FundingTxID = ""
		resOld, err := Compile(&cfgForOld)
		if err != nil {
			return fmt.Errorf("compile OLD rollup: %w", err)
		}
		summary.OldVKHash = resOld.VKHashHex
		summary.OldRollupScript = hex.EncodeToString(resOld.RollupScript)
	}

	if !opts.Broadcast {
		summary.Broadcast = false
		return EmitRotateSummary(summary, opts.OutPath)
	}

	// Broadcast path. WW-rotate-onchain (resolved): assemble the
	// upgrade unlocking script via covenant.BuildUpgradeUnlockScript,
	// build a BSV transaction that spends the live covenant UTXO
	// under it, attach the new covenant locking script as the
	// continuation output, and broadcast via ARC. For multisig
	// rotations where fewer than Threshold signatures have been
	// collected, the partially-signed tx is written to disk and the
	// binary exits with the "tx awaiting N more sigs" message
	// documented in --help.
	return runBroadcastUpgrade(opts, cfg, resNew, summary)
}

// runBroadcastUpgrade implements the --broadcast tail of RunRotateVK.
// Split out for legibility — the validate / compile prefix above stays
// independent of the on-chain machinery.
func runBroadcastUpgrade(
	opts RotateOptions,
	cfg *RotateVKConfig,
	resNew *CompileResult,
	summary RotateSummary,
) error {
	if cfg.ARCEndpoint == "" {
		return errors.New("--broadcast requires arcEndpoint in config")
	}
	if cfg.Governance.Mode == "none" {
		return errors.New("--broadcast cannot rotate a governance-none shard (no key authorises the spend; spec 12)")
	}
	if cfg.CurrentStateRootHex == "" {
		return errors.New("--broadcast requires currentStateRootHex (the live covenant's StateRoot)")
	}

	// Construct the ARC client so any URL / auth issue surfaces before
	// we burn the partial-sig disk write.
	arcClient, err := arc.NewClient(arc.Config{
		URL:           cfg.ARCEndpoint,
		AuthToken:     cfg.ARCAuthToken,
		CallbackURL:   cfg.ARCCallbackURL,
		CallbackToken: "",
	})
	if err != nil {
		return fmt.Errorf("arc client: %w", err)
	}

	gov, err := buildGovernanceConfig(cfg.Governance)
	if err != nil {
		return fmt.Errorf("governance: %w", err)
	}

	preStateRoot, err := decodeHash32(cfg.CurrentStateRootHex)
	if err != nil {
		return fmt.Errorf("currentStateRootHex: %w", err)
	}

	// Decode whatever signatures the operator has supplied. If we have
	// fewer than the threshold, the partial-sig flow takes over.
	govSigs, err := decodeHexBundle(cfg.GovernanceSigsHex)
	if err != nil {
		return fmt.Errorf("governanceSigsHex: %w", err)
	}

	// Resolve the proof bundle. A fresh proof bundle is REQUIRED for
	// production rotations; for tests / dry runs the synthetic helper
	// fabricates a shape-correct (but non-cryptographically-valid)
	// stand-in so the assembly path can be exercised end-to-end.
	pv, batchData, proofBlob, proofSource, err := resolveProofBundle(cfg.ProofBundlePath, opts.ConfigPath, cfg.ChainID, preStateRoot, resNew.RollupScript, cfg.CurrentBlockNumber)
	if err != nil {
		return fmt.Errorf("proof bundle: %w", err)
	}
	if proofSource == "synthetic" {
		fmt.Fprintln(os.Stderr,
			"rotate-vk: WARN proof bundle is SYNTHETIC — the on-chain SP1 "+
				"verifier WILL reject the broadcast tx. Supply a real "+
				"proofBundlePath in the config before broadcasting against "+
				"a production shard.")
	}

	// Compute the ANF hash for the new covenant. Without a real
	// runar-go ANF emitter the deploy tool only carries the script; we
	// derive a stable 32-byte ANF placeholder by hashing the script
	// bytes prefixed with a fixed marker. Production rotations should
	// override this with the published ANF JSON's hash256 once the
	// canonical ANF inscription path lands (TODO(WW-anf-publish)).
	anfHash := anfHashPlaceholder(resNew.RollupScript)

	req := covenant.UpgradeRequest{
		CurrentStateRoot:   preStateRoot,
		CurrentBlockNumber: cfg.CurrentBlockNumber,
		ChainID:            cfg.ChainID,
		NewCovenantScript:  resNew.RollupScript,
		NewCovenantAnfHash: anfHash,
		PublicValues:       pv,
		BatchData:          batchData,
		ProofBlob:          proofBlob,
		GovernanceSigs:     govSigs,
	}

	method, err := covenant.UpgradeMethodName(gov)
	if err != nil {
		return fmt.Errorf("upgrade method: %w", err)
	}
	summary.UpgradeMethod = method

	// Partial-sig branch: not enough sigs collected yet. Emit the
	// (signature-less) request bundle to disk so other operators can
	// continue the assembly. The unlock-script helper will reject the
	// short sig list, but we want a stable on-disk artifact so the
	// next operator's run can resume from it.
	expectedSigs := expectedSigsForGov(gov)
	if len(govSigs) < expectedSigs {
		partialPath := cfg.PartialSigOutPath
		if partialPath == "" {
			partialPath = filepath.Join(filepath.Dir(opts.ConfigPath), "rotate-vk.partial.json")
		}
		if err := writePartialSigBundle(partialPath, &req); err != nil {
			return fmt.Errorf("write partial bundle: %w", err)
		}
		summary.UpgradeTxAwaitingSigs = expectedSigs - len(govSigs)
		summary.Broadcast = false
		fmt.Fprintf(os.Stderr,
			"rotate-vk: %d-of-%d signature(s) collected; %d more needed. "+
				"Wrote partial bundle to %s. Re-run with the additional "+
				"governanceSigsHex once the next operator signs.\n",
			len(govSigs), expectedSigs, expectedSigs-len(govSigs), partialPath)
		return EmitRotateSummary(summary, opts.OutPath)
	}

	// Full sig set: build the unlock script + spend tx.
	unlock, err := covenant.BuildUpgradeUnlockScript(req, gov)
	if err != nil {
		return fmt.Errorf("BuildUpgradeUnlockScript: %w", err)
	}
	summary.UpgradeUnlockHex = hex.EncodeToString(unlock)

	tx, err := BuildUpgradeSpendTx(
		cfg.CovenantTxID,
		cfg.CovenantVout,
		cfg.CovenantSatsLive,
		resNew.RollupScript,
		unlock,
	)
	if err != nil {
		return fmt.Errorf("buildUpgradeSpendTx: %w", err)
	}
	summary.UpgradeTxHex = tx.Hex()
	summary.UpgradeTxIDPredict = tx.TxID().String()

	// Broadcast via ARC. The runar SDK's higher-level Call helper is
	// not used here because rotate-vk operates "off-line": the
	// operator's signatures are pre-collected, the proof bundle is a
	// file, and ARC is the only network surface we touch.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rawHex := tx.Hex()
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return fmt.Errorf("decode upgrade tx hex: %w", err)
	}
	resp, err := arcClient.Broadcast(ctx, rawBytes)
	if err != nil {
		// Surface the partially-or-fully-signed hex even when ARC
		// rejects so the operator can retry against a different ARC
		// instance or co-sign offline.
		summary.Broadcast = false
		_ = EmitRotateSummary(summary, opts.OutPath)
		return fmt.Errorf("ARC.Broadcast: %w", err)
	}
	summary.Broadcast = true
	summary.UpgradeTxIDActual = hex.EncodeToString(resp.TxID[:])
	return EmitRotateSummary(summary, opts.OutPath)
}

// resolveProofBundle returns the (publicValues, batchData, proofBlob)
// triple the upgrade tx commits to. When path is non-empty, the file
// is parsed strictly. Otherwise a synthetic shape-correct stand-in is
// fabricated and the caller is warned. Returns the resolved source as
// the 4th value: "file:<path>" for a real load, "synthetic" otherwise.
func resolveProofBundle(
	path, configPath string,
	chainID uint64,
	preStateRoot [32]byte,
	newScript []byte,
	currentBlockNumber uint64,
) (publicValues, batchData, proofBlob []byte, source string, err error) {
	if path != "" {
		// Resolve relative paths against the config dir.
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(configPath), path)
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, nil, nil, "", fmt.Errorf("read %s: %w", path, readErr)
		}
		var b proofBundle
		if jerr := json.Unmarshal(raw, &b); jerr != nil {
			return nil, nil, nil, "", fmt.Errorf("parse %s: %w", path, jerr)
		}
		pv, perr := hex.DecodeString(strings.TrimPrefix(b.PublicValuesHex, "0x"))
		if perr != nil {
			return nil, nil, nil, "", fmt.Errorf("publicValuesHex: %w", perr)
		}
		if len(pv) != 280 {
			return nil, nil, nil, "", fmt.Errorf("publicValuesHex must decode to 280 bytes, got %d", len(pv))
		}
		bd, berr := hex.DecodeString(strings.TrimPrefix(b.BatchDataHex, "0x"))
		if berr != nil {
			return nil, nil, nil, "", fmt.Errorf("batchDataHex: %w", berr)
		}
		pb, qerr := hex.DecodeString(strings.TrimPrefix(b.ProofBlobHex, "0x"))
		if qerr != nil {
			return nil, nil, nil, "", fmt.Errorf("proofBlobHex: %w", qerr)
		}
		return pv, bd, pb, "file:" + path, nil
	}

	// Synthetic fallback. The publicValues is computed via
	// EncodeUpgradePublicValues so the migration / chainID / block
	// bindings line up with the on-chain assertions; only the proof
	// itself is shape-correct-but-not-valid.
	_, batchData, proofBlob = covenant.SyntheticUpgradeProofBundle("rotate-vk-synthetic")
	// postStateRoot defaults to preStateRoot — the rotation's "no-op
	// transition" case where state doesn't move forward beyond the
	// block-number bump. Operators who need a different post-state
	// MUST supply a real proof bundle.
	publicValues = covenant.EncodeUpgradePublicValues(
		preStateRoot, preStateRoot, batchData, proofBlob,
		newScript, chainID, currentBlockNumber+1)
	return publicValues, batchData, proofBlob, "synthetic", nil
}

// expectedSigsForGov returns the signature count the matching upgrade
// method consumes. Mirrors covenant.UpgradeRequest sig validation —
// kept here so the partial-sig fallback can decide before it calls
// BuildUpgradeUnlockScript.
func expectedSigsForGov(g covenant.GovernanceConfig) int {
	switch g.Mode {
	case covenant.GovernanceSingleKey:
		return 1
	case covenant.GovernanceMultiSig:
		return g.Threshold
	default:
		return 0
	}
}

// PartialSigBundle is the on-disk JSON shape rotate-vk emits when fewer
// than the threshold governance signatures have been collected. A
// follow-up operator reads this back, appends their signature to
// GovernanceSigsHex, and re-runs --broadcast with the now-fuller config.
//
// Exported so the `bsvm dev sign-rotation` helper (and any other
// follow-up signing tool) can read + write the same on-disk shape
// without duplicating field names.
type PartialSigBundle struct {
	Note               string   `json:"note"`
	ChainID            uint64   `json:"chainId"`
	CurrentStateRoot   string   `json:"currentStateRootHex"`
	CurrentBlockNumber uint64   `json:"currentBlockNumber"`
	NewCovenantScript  string   `json:"newCovenantScriptHex"`
	NewCovenantAnfHash string   `json:"newCovenantAnfHashHex"`
	PublicValues       string   `json:"publicValuesHex"`
	BatchData          string   `json:"batchDataHex"`
	ProofBlob          string   `json:"proofBlobHex"`
	GovernanceSigs     []string `json:"governanceSigsHex"`
}

// LoadPartialSigBundle reads + parses a partial-sig bundle JSON file
// previously produced by rotate-vk's --broadcast flow.
func LoadPartialSigBundle(path string) (*PartialSigBundle, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled by design
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var b PartialSigBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &b, nil
}

// WritePartialSigBundle serialises a PartialSigBundle to disk with the
// canonical formatting rotate-vk uses (2-space indented JSON, 0600
// permissions to keep the in-flight signature set out of world-readable
// scratch dirs).
func WritePartialSigBundle(path string, b *PartialSigBundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal partial bundle: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writePartialSigBundle serialises an in-flight UpgradeRequest to JSON
// so a follow-up operator run can read it back, append their signature,
// and resume.
func writePartialSigBundle(path string, req *covenant.UpgradeRequest) error {
	out := &PartialSigBundle{
		Note: "rotate-vk partial bundle. Append your signature to governanceSigsHex " +
			"and re-run with --broadcast and the same config to assemble + broadcast.",
		ChainID:            req.ChainID,
		CurrentStateRoot:   hex.EncodeToString(req.CurrentStateRoot[:]),
		CurrentBlockNumber: req.CurrentBlockNumber,
		NewCovenantScript:  hex.EncodeToString(req.NewCovenantScript),
		NewCovenantAnfHash: hex.EncodeToString(req.NewCovenantAnfHash[:]),
		PublicValues:       hex.EncodeToString(req.PublicValues),
		BatchData:          hex.EncodeToString(req.BatchData),
		ProofBlob:          hex.EncodeToString(req.ProofBlob),
		GovernanceSigs:     make([]string, 0, len(req.GovernanceSigs)),
	}
	for _, s := range req.GovernanceSigs {
		out.GovernanceSigs = append(out.GovernanceSigs, hex.EncodeToString(s))
	}
	return WritePartialSigBundle(path, out)
}

// BuildUpgradeSpendTx assembles a single-input single-output BSV tx
// that spends the live covenant UTXO under the supplied unlock script
// and re-pins the value under the new locking script. The result is
// only as on-chain-valid as the supplied unlock script — broadcasting
// a synthetic-proof variant will be rejected by the SP1 verifier in
// the rollup contract's upgrade method.
//
// The unlockBytes argument may be empty (or a single 0x00 placeholder)
// when the caller only needs the tx skeleton for sighash computation
// (e.g. the `bsvm dev sign-rotation` helper). The BIP-143 sighash for
// input 0 is independent of the input's UnlockingScript bytes — it is
// derived from the previous output's locking script — so the same
// builder is reused by both paths.
func BuildUpgradeSpendTx(
	covenantTxID string,
	covenantVout uint32,
	covenantSatsLive uint64,
	newRollupScript []byte,
	unlockBytes []byte,
) (*transaction.Transaction, error) {
	tx := transaction.NewTransaction()
	// Live covenant input. We pass the existing covenant's locking-
	// script-hex as the prevLockingScript so the BSV-SDK can lay out
	// the input correctly; in the rotate-vk path the operator
	// supplies the live UTXO's locking script via the same channel
	// as covenantTxId.
	if err := tx.AddInputFrom(
		covenantTxID,
		covenantVout,
		"00", // placeholder — sigOps are already encoded into unlockBytes
		covenantSatsLive,
		nil,
	); err != nil {
		return nil, fmt.Errorf("AddInputFrom: %w", err)
	}
	if len(unlockBytes) > 0 {
		unlockScript, err := sdkscript.NewFromHex(hex.EncodeToString(unlockBytes))
		if err != nil {
			return nil, fmt.Errorf("unlock script: %w", err)
		}
		tx.Inputs[0].UnlockingScript = unlockScript
	}

	// Continuation output: same satoshi value, new covenant lock.
	newLS, err := sdkscript.NewFromHex(hex.EncodeToString(newRollupScript))
	if err != nil {
		return nil, fmt.Errorf("new rollup locking script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      covenantSatsLive,
		LockingScript: newLS,
	})
	return tx, nil
}

// decodeHash32 parses a 32-byte hex string (with or without 0x).
func decodeHash32(s string) (out [32]byte, err error) {
	bare := strings.TrimPrefix(s, "0x")
	bare = strings.TrimPrefix(bare, "0X")
	b, derr := hex.DecodeString(bare)
	if derr != nil {
		return out, fmt.Errorf("decode hex: %w", derr)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// decodeHexBundle decodes each hex string in a slice. Empty input
// returns an empty slice.
func decodeHexBundle(hexes []string) ([][]byte, error) {
	out := make([][]byte, 0, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// anfHashPlaceholder returns a stable 32-byte hash binding the new
// covenant script identity into the spec-10 migration OP_RETURN.
// Production rotations should replace this with the published ANF
// JSON's hash256 once the canonical ANF inscription path lands
// (TODO(WW-anf-publish)). The placeholder still binds the migration
// to the script bytes — observers that recompile the new contract
// from source can recompute hash256 of their compiled artifact and
// confirm match.
func anfHashPlaceholder(newScript []byte) [32]byte {
	const tag = "BSVM-ANF-PLACEHOLDER\x01"
	buf := make([]byte, 0, len(tag)+len(newScript))
	buf = append(buf, tag...)
	buf = append(buf, newScript...)
	// reuse the upgrade.go internal helper through a minimal call.
	return covenant.UpgradeAnfPlaceholder(buf)
}

// LoadRotateVKConfig reads + parses the rotate-vk config JSON.
func LoadRotateVKConfig(path string) (*RotateVKConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg RotateVKConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.NewVKHashFile == "" {
		cfg.NewVKHashFile = DefaultVKHashFile()
	}
	return &cfg, nil
}

// ValidateRotation checks the rotate-specific fields. broadcastMode
// = true tightens the check to require all on-chain inputs.
func (c *RotateVKConfig) ValidateRotation(broadcastMode bool) error {
	if c.CovenantTxID == "" {
		return errors.New("covenantTxId must be set (the live UTXO to spend)")
	}
	// 64 hex chars = 32 bytes.
	if !looksLikeBitcoinTxID(c.CovenantTxID) {
		return fmt.Errorf("covenantTxId %q does not look like a 32-byte hex txid", c.CovenantTxID)
	}
	if broadcastMode {
		if c.CovenantSatsLive == 0 {
			return errors.New("covenantSatsLive must be > 0 in --broadcast mode")
		}
		if c.Governance.Mode != "none" && len(c.GovernanceSigsHex) == 0 {
			return errors.New("governanceSigsHex required for non-none governance in --broadcast mode")
		}
		if c.NewVKHashFile == "" {
			return errors.New("newVKHashFile must be set in --broadcast mode")
		}
	}
	return nil
}

// EmitRotateSummary writes a JSON RotateSummary to stdout (and
// optionally a file).
func EmitRotateSummary(s RotateSummary, outPath string) error {
	enc, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, append(enc, '\n'), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
	}
	_, _ = os.Stdout.Write(append(enc, '\n'))
	return nil
}

// looksLikeBitcoinTxID returns true when s parses as 32 hex bytes
// (with or without a 0x prefix).
func looksLikeBitcoinTxID(s string) bool {
	bare := strings.TrimPrefix(s, "0x")
	if len(bare) != 64 {
		return false
	}
	if _, err := hex.DecodeString(bare); err != nil {
		return false
	}
	return true
}
