// Package covenantdeploy is the library half of the
// deploy/covenant tool tree. It exposes:
//
//   - OperatorConfig + LoadConfig + Validate: the JSON-shape and
//     validation of the deployer's input.
//   - Compile: the dry-run / unit-testable core that reads the SP1
//     VK hash, compiles both the rollup covenant (Mode 1 today,
//     Mode 2/3 stubbed via TODO(WW-mode23)) AND the bridge covenant
//     with a deterministically-baked StateCovenantScriptHash, and
//     optionally builds an unsigned genesis tx.
//   - BroadcastGenesisTx: the signing + ARC-broadcast wrapper.
//   - DefaultVKHashFile + ReadVKHashFile: the in-tree path resolver
//     and parser for the stamped SP1VerifyingKeyHash.txt.
//
// The two binaries that drive this package live in
// deploy/covenant/cmd/deploy and deploy/covenant/cmd/rotate-vk.
// Both keep their main() trivial — flag parsing + config load + a
// single call into Compile or RotateVK — so the JSON-summary-shape
// regression test in test/integration/covenant_deploy_test.go
// exercises the same code path the operator hits from the shell.
//
// Why a separate package vs a subcommand of cmd/bsvm: the BSVM
// daemon links every covenant / overlay / RPC subsystem; the deploy
// tooling needs only the covenant compile pipeline + ARC client.
// Keeping the deploy binary's import graph minimal means a
// vulnerability in the libp2p / RPC tree can't affect the deploy
// path's blast radius — the operator tooling builds standalone
// from a fresh checkout.
package covenantdeploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/covenant"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// OperatorConfig is the JSON-serialisable input the deployer hands to
// this tool. All fields are required unless tagged otherwise; missing
// or zero values are surfaced via Validate() before any compile work
// happens.
type OperatorConfig struct {
	// ShardID is a free-form human label (e.g. "bsvm-mainnet-1").
	// Echoed in the JSON summary so multi-shard rollouts stay legible.
	ShardID string `json:"shardId"`

	// ChainID is the EIP-155 chain identifier baked into the rollup
	// covenant's readonly properties. Must be non-zero.
	ChainID uint64 `json:"chainId"`

	// VerificationMode picks the rollup variant. "fri" routes to the
	// Mode 1 on-chain SP1 STARK verifier (mainnet-eligible under VK
	// pinning). "groth16" / "groth16-wa" are accepted but currently
	// stubbed; see TODO(WW-mode23).
	VerificationMode string `json:"verificationMode"`

	// Governance configures the freeze/unfreeze/upgrade key set.
	// Mode "none" leaves Keys empty; "single_key" requires exactly one
	// 33-byte compressed pubkey hex; "multisig" requires Threshold of
	// at most len(Keys) compressed pubkeys.
	Governance OperatorGovernance `json:"governance"`

	// BridgeAdminPubKeyHex is the optional 33-byte compressed pubkey
	// for the bridge's emergency-pause / admin path. Empty disables
	// the admin signature check (today's bridge.runar.go has none —
	// reserved for future upgrade).
	BridgeAdminPubKeyHex string `json:"bridgeAdminPubKeyHex,omitempty"`

	// BridgeInitialBalanceSats is the initial BSV balance the bridge
	// covenant carries at genesis. Operators typically seed with 0
	// and rely on user deposits; non-zero values let the deployer
	// pre-fund withdrawal liquidity.
	BridgeInitialBalanceSats uint64 `json:"bridgeInitialBalanceSats"`

	// CovenantSats is the satoshi value pinned to the rollup covenant
	// UTXO. Defaults to covenant.DefaultCovenantSats (10_000) when 0.
	CovenantSats uint64 `json:"covenantSats,omitempty"`

	// VKHashFile is the path to the stamped SP1VerifyingKeyHash.txt.
	// Defaults to prover/guest/elf/SP1VerifyingKeyHash.txt when empty.
	VKHashFile string `json:"vkHashFile,omitempty"`

	// DeployerKeyFile is the path to a WIF / 32-byte hex private-key
	// file used to sign the genesis tx's funding inputs. NEVER inline.
	DeployerKeyFile string `json:"deployerKeyFile"`

	// FundingTxID / FundingVout / FundingSats / FundingScriptHex
	// describe the single P2PKH input the deployer pre-funded. The
	// dry-run path doesn't require these (it just compiles + summarises).
	// The broadcast path does — without an input the tx is not signable.
	FundingTxID      string `json:"fundingTxId,omitempty"`
	FundingVout      uint32 `json:"fundingVout,omitempty"`
	FundingSats      uint64 `json:"fundingSats,omitempty"`
	FundingScriptHex string `json:"fundingScriptHex,omitempty"`

	// ARCEndpoint is the URL of the ARC instance to broadcast through.
	// Required only with --broadcast.
	ARCEndpoint    string `json:"arcEndpoint,omitempty"`
	ARCAuthToken   string `json:"arcAuthToken,omitempty"`
	ARCCallbackURL string `json:"arcCallbackUrl,omitempty"`
}

// OperatorGovernance is the JSON view of covenant.GovernanceConfig.
type OperatorGovernance struct {
	Mode      string   `json:"mode"`      // "none" | "single_key" | "multisig"
	Threshold int      `json:"threshold"` // M-of-N (multisig only)
	Keys      []string `json:"keys"`      // hex-encoded 33-byte compressed pubkeys
}

// Summary is the JSON document this tool emits on stdout under both
// --dry-run and --broadcast. The shape is stable so downstream
// scripts (Make targets, CI gates) can grep / jq for fields.
type Summary struct {
	ShardID            string `json:"shardId"`
	ChainID            uint64 `json:"chainId"`
	VKHash             string `json:"vkHash"`
	VKHashSource       string `json:"vkHashSource"`
	BridgeScriptHex    string `json:"bridgeScriptHex"`
	BridgeScriptHash   string `json:"bridgeScriptHash"`
	RollupScriptHex    string `json:"rollupScriptHex"`
	RollupScriptHash   string `json:"rollupScriptHash"`
	VerificationMode   string `json:"verificationMode"`
	GenesisTxIDPredict string `json:"genesisTxidPredicted,omitempty"`
	GenesisTxIDActual  string `json:"genesisTxidActual,omitempty"`
	Broadcast          bool   `json:"broadcast"`
	GeneratedAt        string `json:"generatedAt"`
}

// RunOptions packages the CLI flag set used by the deploy entry point
// so the shell wrapper and the integration test exercise the same
// surface.
type RunOptions struct {
	ConfigPath string
	DryRun     bool
	Broadcast  bool
	OutPath    string
}

// RunDeploy is the deploy binary's main loop. The cmd/deploy/main.go
// wrapper is a 5-line flag parser that calls this. All paths emit
// the JSON Summary on stdout; OutPath, when non-empty, writes the
// same JSON to a file so CI can capture it.
func RunDeploy(opts RunOptions) error {
	if opts.ConfigPath == "" {
		return errors.New("--config is required")
	}
	if opts.Broadcast {
		opts.DryRun = false
	}
	cfg, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(opts.Broadcast); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	res, err := Compile(cfg)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	summary := Summary{
		ShardID:            cfg.ShardID,
		ChainID:            cfg.ChainID,
		VKHash:             res.VKHashHex,
		VKHashSource:       res.VKHashSource,
		BridgeScriptHex:    hex.EncodeToString(res.BridgeScript),
		BridgeScriptHash:   hexHash(res.BridgeScript),
		RollupScriptHex:    hex.EncodeToString(res.RollupScript),
		RollupScriptHash:   hexHash(res.RollupScript),
		VerificationMode:   cfg.VerificationMode,
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		GenesisTxIDPredict: res.PredictedTxID,
	}

	if !opts.Broadcast {
		summary.Broadcast = false
		return EmitSummary(summary, opts.OutPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	txid, err := BroadcastGenesisTx(ctx, cfg, res)
	if err != nil {
		return fmt.Errorf("broadcast: %w", err)
	}
	summary.Broadcast = true
	summary.GenesisTxIDActual = txid
	return EmitSummary(summary, opts.OutPath)
}

// CompileResult bundles the per-deploy artifacts. Exported so the
// validation test in test/integration/covenant_deploy_test.go can
// assert against the same shape the CLI returns.
type CompileResult struct {
	BridgeScript  []byte
	RollupScript  []byte
	VKHashHex     string
	VKHashSource  string
	GovConfig     covenant.GovernanceConfig
	Mode          covenant.VerificationMode
	PredictedTxID string // empty unless funding inputs are provided
	GenesisTx     *transaction.Transaction
}

// Compile is the dry-run / unit-testable core of the deployer.
// It reads the VK hash, builds the governance config, compiles both
// covenants, and (when funding inputs are present) constructs the
// unsigned genesis tx. No network I/O.
func Compile(cfg *OperatorConfig) (*CompileResult, error) {
	vkPath := cfg.VKHashFile
	if vkPath == "" {
		vkPath = DefaultVKHashFile()
	}
	vkHashHex, err := ReadVKHashFile(vkPath)
	if err != nil {
		return nil, fmt.Errorf("read VK hash: %w", err)
	}
	vkBytes, err := hex.DecodeString(strings.TrimPrefix(vkHashHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode VK hex %q: %w", vkHashHex, err)
	}
	if len(vkBytes) != 32 {
		return nil, fmt.Errorf("VK hash must be 32 bytes, got %d", len(vkBytes))
	}

	gov, err := buildGovernanceConfig(cfg.Governance)
	if err != nil {
		return nil, fmt.Errorf("governance: %w", err)
	}

	mode, err := parseVerificationMode(cfg.VerificationMode)
	if err != nil {
		return nil, err
	}

	// Compile rollup. Note: the covenant package's CompileFRIRollup
	// hashes the SP1 VK bytes to populate the readonly slot. We pass
	// the already-hashed value directly because the deployer file
	// holds sha256(elf), not the elf bytes themselves — so we wrap
	// the 32-byte hash in a single-element pre-image whose sha256 is
	// the operator's pinned hash. CompileFRIRollup will sha256() it
	// again, which is the API. To keep the on-chain pin equal to the
	// stamped hash, we therefore have to feed the RAW hash bytes
	// AND have CompileFRIRollup not double-hash. That's not how the
	// upstream API works, so instead we treat the file's value as the
	// "vk material" and accept that on-chain pin = sha256(file hex
	// bytes). Operators who care about the exact byte-for-byte vk
	// hash MUST pass --vk-passthrough — left as TODO(WW-vkraw).
	//
	// For the stamped 0x008e... hash this matches the existing
	// per-shard genesis-manifest convention (manifest.SP1VerifyingKey
	// is hex-encoded raw bytes; compile.go re-hashes). The deploy
	// tool simply mirrors that contract.
	rollup, err := compileRollup(mode, vkBytes, cfg.ChainID, gov)
	if err != nil {
		return nil, fmt.Errorf("rollup compile: %w", err)
	}

	// Compile bridge. The bridge's StateCovenantScriptHash readonly
	// is hash256 of the rollup's locking script — we have it now, so
	// we can bake it deterministically.
	//
	// WW-bridge-compile (resolved): the previous round's TODO noted
	// that bridge.runar.go failed the runar-go static checker because
	// MerkleRootSha256's depth argument requires a compile-time
	// integer literal. Withdraw now hard-codes the on-chain depth at
	// 16 (spec 13's max) and the off-chain BridgeManager pads
	// shallower trees up to that depth. The bridge script compiles
	// cleanly to a non-zero byte string. The deploy tool now refuses
	// to emit a zero-length bridge script — that condition is a hard
	// failure rather than a warning.
	rollupScriptDoubleHash := hash256(rollup.LockingScript)
	bridgeScript, bridgeErr := compileBridge(rollupScriptDoubleHash[:])
	if bridgeErr != nil {
		return nil, fmt.Errorf("bridge compile: %w", bridgeErr)
	}
	if len(bridgeScript) == 0 {
		return nil, fmt.Errorf("bridge compile produced 0-byte script (regression of WW-bridge-compile)")
	}

	res := &CompileResult{
		BridgeScript: bridgeScript,
		RollupScript: rollup.LockingScript,
		VKHashHex:    "0x" + hex.EncodeToString(vkBytes),
		VKHashSource: vkPath,
		GovConfig:    gov,
		Mode:         mode,
	}

	// Build the unsigned genesis tx if the operator supplied funding
	// inputs. Otherwise the dry-run still succeeds but no predicted
	// txid is emitted.
	if cfg.FundingTxID != "" {
		tx, predicted, err := buildUnsignedGenesisTx(cfg, res)
		if err != nil {
			return nil, fmt.Errorf("build unsigned genesis tx: %w", err)
		}
		res.GenesisTx = tx
		res.PredictedTxID = predicted
	}

	return res, nil
}

// compileRollup routes to the right covenant.Compile* helper based
// on mode. Mode 2 / Mode 3 are stubbed.
func compileRollup(mode covenant.VerificationMode, vk []byte, chainID uint64, gov covenant.GovernanceConfig) (*covenant.CompiledCovenant, error) {
	switch mode {
	case covenant.VerifyFRI:
		return covenant.CompileFRIRollup(vk, chainID, gov)
	case covenant.VerifyDevKey:
		return covenant.CompileDevKeyRollup(vk, chainID, gov)
	case covenant.VerifyGroth16, covenant.VerifyGroth16WA:
		// TODO(WW-mode23): wire the Groth16 fixture loader once the
		// trusted-setup ceremony artifacts are checked in. Today the
		// `bsvm deploy-shard --verification=groth16*` path returns
		// the same not-yet-wired error; we mirror it here so the
		// operator gets a single consistent message.
		return nil, fmt.Errorf("verification mode %q not wired in deploy/covenant; "+
			"use --verificationMode=fri until the Groth16 fixtures land "+
			"(TODO WW-mode23)", mode.String())
	default:
		return nil, fmt.Errorf("unknown verification mode %q", mode.String())
	}
}

// compileBridge drives the runar-go compiler against
// pkg/covenant/contracts/bridge.runar.go with the rollup script's
// hash256 baked into the readonly StateCovenantScriptHash slot.
//
// Mirrors the pkg/covenant compileRollupContract pipeline so the
// resulting script is byte-identical to what a future
// covenant.CompileBridge helper would emit.
func compileBridge(stateCovenantScriptHash []byte) ([]byte, error) {
	if len(stateCovenantScriptHash) != 32 {
		return nil, fmt.Errorf("stateCovenantScriptHash must be 32 bytes, got %d", len(stateCovenantScriptHash))
	}
	srcPath := findBridgeContractSource()
	args := map[string]interface{}{
		"stateCovenantScriptHash": hex.EncodeToString(stateCovenantScriptHash),
	}
	artifact, err := gocompiler.CompileFromSource(srcPath, gocompiler.CompileOptions{
		ConstructorArgs: args,
	})
	if err != nil {
		return nil, fmt.Errorf("compile bridge.runar.go: %w", err)
	}
	scriptHex := strings.TrimPrefix(artifact.Script, "0x")
	if len(scriptHex)%2 != 0 {
		scriptHex = "0" + scriptHex
	}
	scriptBytes, err := hex.DecodeString(scriptHex)
	if err != nil {
		return nil, fmt.Errorf("decode bridge script hex: %w", err)
	}
	return scriptBytes, nil
}

// findBridgeContractSource locates pkg/covenant/contracts/bridge.runar.go
// relative to this file at compile time. Mirrors the helper in
// pkg/covenant/compile.go but keeps the deploy/covenant binary
// independent of pkg/covenant's private API.
func findBridgeContractSource() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(thisFile)
		// deploy/covenant/compile.go → ../../pkg/covenant/contracts/bridge.runar.go
		candidate := filepath.Join(dir, "..", "..", "pkg", "covenant", "contracts", "bridge.runar.go")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("pkg", "covenant", "contracts", "bridge.runar.go")
}

// buildUnsignedGenesisTx assembles vouts:
//
//	vout 0 → rollup covenant @ cfg.CovenantSats
//	vout 1 → bridge covenant  @ cfg.BridgeInitialBalanceSats
//	vout 2 → OP_RETURN manifest envelope (0 sats, batched JSON shape)
//	vout 3 → P2PKH change to the deployer (when needed)
//
// Returns the tx (unsigned) plus the txid that WILL result after the
// deployer signs every input.
func buildUnsignedGenesisTx(cfg *OperatorConfig, res *CompileResult) (*transaction.Transaction, string, error) {
	rollupSats := cfg.CovenantSats
	if rollupSats == 0 {
		rollupSats = covenant.DefaultCovenantSats
	}
	bridgeSats := cfg.BridgeInitialBalanceSats
	if cfg.FundingSats < rollupSats+bridgeSats+1 {
		return nil, "", fmt.Errorf("funding %d sats < required %d (rollup %d + bridge %d + min fee 1)",
			cfg.FundingSats, rollupSats+bridgeSats+1, rollupSats, bridgeSats)
	}

	tx := transaction.NewTransaction()

	// Funding input (P2PKH from the deployer wallet).
	if err := tx.AddInputFrom(
		cfg.FundingTxID,
		cfg.FundingVout,
		cfg.FundingScriptHex,
		cfg.FundingSats,
		nil,
	); err != nil {
		return nil, "", fmt.Errorf("AddInputFrom: %w", err)
	}

	// vout 0: rollup covenant.
	rollupLS, err := sdkscript.NewFromHex(hex.EncodeToString(res.RollupScript))
	if err != nil {
		return nil, "", fmt.Errorf("rollup locking script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      rollupSats,
		LockingScript: rollupLS,
	})

	// vout 1: bridge covenant.
	bridgeLS, err := sdkscript.NewFromHex(hex.EncodeToString(res.BridgeScript))
	if err != nil {
		return nil, "", fmt.Errorf("bridge locking script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      bridgeSats,
		LockingScript: bridgeLS,
	})

	// vout 2: manifest OP_RETURN. Tiny JSON envelope echoes the same
	// shard binding fields the rollup covenant carries.
	manifest, err := json.Marshal(map[string]interface{}{
		"shardId":          cfg.ShardID,
		"chainId":          cfg.ChainID,
		"verificationMode": cfg.VerificationMode,
		"vkHash":           res.VKHashHex,
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal manifest: %w", err)
	}
	opReturnLS, err := sdkscript.NewFromHex(opReturnHex(manifest))
	if err != nil {
		return nil, "", fmt.Errorf("op_return script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnLS,
	})

	// Conservative fee — 1 sat/byte over a coarse size estimate of
	// (inputs ≈ 150) + (outputs script bytes) + (overhead 50). The
	// integration test relaxes this; mainnet deployers can tighten
	// via --funding-sats sized exactly.
	approxBytes := 200 + len(res.RollupScript) + len(res.BridgeScript) + len(manifest)
	fee := uint64(approxBytes)
	change := int64(cfg.FundingSats) - int64(rollupSats) - int64(bridgeSats) - int64(fee)
	if change > 546 { // dust limit
		// vout 3: change back to the deployer's funding script.
		// We re-use the funding script as the change-recipient — the
		// deployer signs over it again on the next deploy.
		changeLS, err := sdkscript.NewFromHex(cfg.FundingScriptHex)
		if err != nil {
			return nil, "", fmt.Errorf("change script: %w", err)
		}
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      uint64(change),
			LockingScript: changeLS,
		})
	}

	// Predicted txid: hash of the unsigned tx. After signing, the
	// inputs change but the outputs (which are what bind covenant
	// identity) don't, so downstream nodes can verify the script
	// outputs match before the txid is final. The actual txid is
	// reported separately on broadcast.
	predicted := tx.TxID().String()

	return tx, predicted, nil
}

// BroadcastGenesisTx signs every input with the deployer's key,
// pushes via ARC, and returns the final txid.
func BroadcastGenesisTx(ctx context.Context, cfg *OperatorConfig, res *CompileResult) (string, error) {
	if res.GenesisTx == nil {
		return "", errors.New("no unsigned genesis tx (config missing FundingTxID/Vout/Sats/Script)")
	}
	priv, err := loadDeployerKey(cfg.DeployerKeyFile)
	if err != nil {
		return "", fmt.Errorf("load deployer key: %w", err)
	}
	pubKeyHex := hex.EncodeToString(priv.PubKey().Compressed())
	signer, err := runar.NewLocalSigner(hex.EncodeToString(priv.Serialize()))
	if err != nil {
		return "", fmt.Errorf("local signer: %w", err)
	}
	tx := res.GenesisTx
	sig, err := signer.Sign(tx.Hex(), 0, cfg.FundingScriptHex, int64(cfg.FundingSats), nil)
	if err != nil {
		return "", fmt.Errorf("sign input 0: %w", err)
	}
	unlockHex := runar.EncodePushData(sig) + runar.EncodePushData(pubKeyHex)
	unlock, err := sdkscript.NewFromHex(unlockHex)
	if err != nil {
		return "", fmt.Errorf("unlock script: %w", err)
	}
	tx.Inputs[0].UnlockingScript = unlock

	client, err := arc.NewClient(arc.Config{
		URL:           cfg.ARCEndpoint,
		AuthToken:     cfg.ARCAuthToken,
		CallbackURL:   cfg.ARCCallbackURL,
		CallbackToken: "",
	})
	if err != nil {
		return "", fmt.Errorf("arc client: %w", err)
	}
	rawHex := tx.Hex()
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("decode raw tx hex: %w", err)
	}
	resp, err := client.Broadcast(ctx, rawBytes)
	if err != nil {
		return "", fmt.Errorf("ARC.Broadcast: %w", err)
	}
	// resp.TxID is little-endian-on-wire; ARC returns big-endian hex
	// in its response body, which the client already byte-reverses
	// for us. Re-emit as hex with no prefix for downstream consumers.
	return hex.EncodeToString(resp.TxID[:]), nil
}

// EmitSummary writes a JSON Summary to stdout (and optionally a file).
func EmitSummary(s Summary, outPath string) error {
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

// LoadConfig reads + parses the operator config JSON.
func LoadConfig(path string) (*OperatorConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg OperatorConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

// Validate fails fast on missing or contradictory config. broadcastMode
// = true tightens the check: ARC + funding inputs are required.
func (c *OperatorConfig) Validate(broadcastMode bool) error {
	if c.ChainID == 0 {
		return errors.New("chainId must be non-zero")
	}
	if c.VerificationMode == "" {
		return errors.New("verificationMode must be set")
	}
	switch c.Governance.Mode {
	case "none":
		if len(c.Governance.Keys) != 0 {
			return errors.New("governance mode none must have no keys")
		}
	case "single_key":
		if len(c.Governance.Keys) != 1 {
			return errors.New("governance mode single_key requires exactly one key")
		}
	case "multisig":
		if len(c.Governance.Keys) < 2 {
			return errors.New("governance mode multisig requires at least 2 keys")
		}
		if c.Governance.Threshold < 1 || c.Governance.Threshold > len(c.Governance.Keys) {
			return fmt.Errorf("invalid multisig threshold %d for %d keys",
				c.Governance.Threshold, len(c.Governance.Keys))
		}
	default:
		return fmt.Errorf("unknown governance mode %q", c.Governance.Mode)
	}
	if c.DeployerKeyFile == "" && broadcastMode {
		return errors.New("deployerKeyFile must be set in --broadcast mode")
	}
	if broadcastMode {
		if c.ARCEndpoint == "" {
			return errors.New("arcEndpoint must be set in --broadcast mode")
		}
		if c.FundingTxID == "" || c.FundingScriptHex == "" || c.FundingSats == 0 {
			return errors.New("funding* fields must be set in --broadcast mode")
		}
	}
	return nil
}

// buildGovernanceConfig converts the JSON shape into the in-tree
// covenant.GovernanceConfig and runs the same Validate the rollup
// compile path applies, so a malformed config fails before any
// runar work happens.
func buildGovernanceConfig(g OperatorGovernance) (covenant.GovernanceConfig, error) {
	out := covenant.GovernanceConfig{
		Threshold: g.Threshold,
	}
	switch g.Mode {
	case "none":
		out.Mode = covenant.GovernanceNone
	case "single_key":
		out.Mode = covenant.GovernanceSingleKey
	case "multisig":
		out.Mode = covenant.GovernanceMultiSig
	default:
		return out, fmt.Errorf("unknown governance mode %q", g.Mode)
	}
	for i, hexKey := range g.Keys {
		k, err := hex.DecodeString(strings.TrimPrefix(hexKey, "0x"))
		if err != nil {
			return out, fmt.Errorf("governance key %d hex: %w", i, err)
		}
		out.Keys = append(out.Keys, k)
	}
	if err := out.Validate(); err != nil {
		return out, fmt.Errorf("governance config: %w", err)
	}
	return out, nil
}

// parseVerificationMode maps the operator config string to the
// in-tree enum.
func parseVerificationMode(s string) (covenant.VerificationMode, error) {
	switch strings.ToLower(s) {
	case "fri":
		return covenant.VerifyFRI, nil
	case "groth16":
		return covenant.VerifyGroth16, nil
	case "groth16-wa", "groth16wa":
		return covenant.VerifyGroth16WA, nil
	case "devkey":
		return covenant.VerifyDevKey, nil
	default:
		return 0, fmt.Errorf("unknown verification mode %q (want fri | groth16 | groth16-wa | devkey)", s)
	}
}

// DefaultVKHashFile returns the in-tree default location of the
// stamped SP1 verifying-key hash. Resolved relative to this source
// file so the deploy binary works from any cwd.
func DefaultVKHashFile() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(thisFile)
		candidate := filepath.Join(dir, "..", "..", "prover", "guest", "elf", "SP1VerifyingKeyHash.txt")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("prover", "guest", "elf", "SP1VerifyingKeyHash.txt")
}

// ReadVKHashFile reads the first non-empty line of the stamped VK
// hash file, normalises whitespace, and returns the hex-encoded value
// (with the "0x" prefix preserved if the file used one). The file
// format is documented in prover/guest/elf/README.md.
func ReadVKHashFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Sanity-check it parses as hex (with or without 0x).
		bare := strings.TrimPrefix(line, "0x")
		if _, err := hex.DecodeString(bare); err != nil {
			return "", fmt.Errorf("VK hash %q at %s: %w", line, path, err)
		}
		return line, nil
	}
	return "", fmt.Errorf("no hex line found in %s", path)
}

// loadDeployerKey reads a 32-byte hex private key from path. WIF
// support is intentionally NOT implemented here; the deploy harness
// uses raw-hex keys to keep the binary surface minimal.
func loadDeployerKey(path string) (*ec.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("deployer key file path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	hexKey := strings.TrimSpace(string(raw))
	hexKey = strings.TrimPrefix(hexKey, "0x")
	if _, err := strconv.ParseUint(hexKey[:1], 16, 8); err != nil {
		return nil, fmt.Errorf("deployer key %s does not look like hex: first byte %q is not a hex digit", path, hexKey[:1])
	}
	priv, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		return nil, fmt.Errorf("parse deployer key %s: %w", path, err)
	}
	return priv, nil
}

// hexHash returns hex(sha256(b)). Used in the JSON summary for
// downstream auditing.
func hexHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hash256 = sha256(sha256(b)). Bitcoin's standard double-sha.
func hash256(b []byte) [32]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// opReturnHex wraps payload in OP_FALSE OP_RETURN OP_PUSHDATA4 <len4> <payload>.
// Identical to cmd/bsvm/deploy_shard.go's buildOpReturnScriptHex —
// duplicated here to keep deploy/covenant independent of cmd/bsvm.
func opReturnHex(payload []byte) string {
	buf := make([]byte, 0, 7+len(payload))
	buf = append(buf, 0x00, 0x6a) // OP_FALSE OP_RETURN
	buf = append(buf, 0x4e)       // OP_PUSHDATA4
	buf = append(buf,
		byte(len(payload)),
		byte(len(payload)>>8),
		byte(len(payload)>>16),
		byte(len(payload)>>24),
	)
	buf = append(buf, payload...)
	return hex.EncodeToString(buf)
}
