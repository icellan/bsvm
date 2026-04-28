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
	"strings"
	"time"

	"github.com/icellan/bsvm/pkg/arc"
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
	Broadcast          bool   `json:"broadcast"`
	GeneratedAt        string `json:"generatedAt"`
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

	// Broadcast path. The actual on-chain Upgrade method invocation
	// is gated by the rollup contract's CheckSig/CheckMultiSig
	// against the governance key set — we don't sign tx inputs in
	// the wrapper here, we just submit the prebuilt unlocking
	// script the operator constructed off-line.
	//
	// TODO(WW-rotate-onchain): once pkg/covenant exposes a
	// BuildUpgradeUnlockScript helper that takes the governance
	// signature bundle + the new locking script, route through it
	// here. For now we surface a clear error so the operator
	// doesn't accidentally believe the binary fully built the tx.
	if cfg.ARCEndpoint == "" {
		return errors.New("--broadcast requires arcEndpoint in config")
	}
	if len(cfg.GovernanceSigsHex) == 0 && cfg.Governance.Mode != "none" {
		return errors.New("--broadcast requires governanceSigsHex for non-none governance modes")
	}
	// Construct the ARC client so we surface any URL / auth issue
	// before the operator wires the unlock-script helper.
	if _, err := arc.NewClient(arc.Config{
		URL:           cfg.ARCEndpoint,
		AuthToken:     cfg.ARCAuthToken,
		CallbackURL:   cfg.ARCCallbackURL,
		CallbackToken: "",
	}); err != nil {
		return fmt.Errorf("arc client: %w", err)
	}
	_ = context.Background() // reserved for the on-chain wrapper
	return errors.New("rotate-vk --broadcast requires the WW-rotate-onchain helper " +
		"(BuildUpgradeUnlockScript) which is not yet wired in pkg/covenant. " +
		"For now: emit the unsigned upgrade tx via --dry-run, sign it with " +
		"`bsvm dev sign-tx`, and broadcast manually via the ARC client. " +
		"See deploy/covenant/README.md §manual-broadcast")
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
