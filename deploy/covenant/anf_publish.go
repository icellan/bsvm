// covenantdeploy — ANF inscription publish path.
//
// Replaces the legacy `anfHashPlaceholder` shortcut (which derived a
// 32-byte commitment from sha256("BSVM-ANF-PLACEHOLDER\x01" || newScript))
// with the spec-10 §"Migration OP_RETURN" canonical flow:
//
//  1. Build a versioned ANF Document from the compile result + operator
//     config (BuildANFDocument). The Document carries the rollup script
//     bytes, the runar-go ANF IR (when available), governance,
//     verification mode, SP1 VK hash, and a small metadata envelope.
//  2. Compute hash256(canonical-JSON(Document)) — this is the value the
//     on-chain UpgradeRequest.NewCovenantAnfHash binds to.
//  3. Optionally publish the canonical JSON as a BSV transaction whose
//     vout 0 is OP_FALSE OP_RETURN OP_PUSHDATA <doc> (PublishANFDocument).
//     The deploy / rotate-vk binaries gate this behind --anf-publish so
//     the operator first dry-runs and inspects the JSON.
//
// Closes TODO(WW-anf-publish). The runar-go SDK does not yet expose a
// first-class ANF inscription API; this package's pkg/covenant/anf is
// the local stub. When upstream lands runar.PublishANF, swap
// PublishANFDocument's ARC plumbing for a thin wrapper.
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

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/covenant/anf"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ANFOptions controls BuildANFDocument's per-call knobs. Empty values
// are treated as "use the helper's default": Kind defaults to
// KindRotation (the rotate-vk path is the more common ANF-publish
// caller), and GeneratedAt defaults to time.Now().UTC().
type ANFOptions struct {
	// Kind selects the document subtype. Use anf.KindGenesis on the
	// initial deploy, anf.KindRotation on rotate-vk. The on-chain
	// commitment ignores the field — it's purely descriptive.
	Kind anf.Kind

	// PreviousAnfHash, when non-zero, links a rotation document to the
	// shard's last published ANF (the one currently committed on-chain).
	// Genesis documents leave this empty.
	PreviousAnfHash [32]byte

	// IncludeBridge controls whether the document carries the bridge
	// covenant binding. Auto-true when Kind is KindGenesis, auto-false
	// when Kind is KindRotation; explicit values override the default.
	IncludeBridge *bool

	// IncludeRawSP1VK, when true, embeds the SP1 verifying-key hex
	// in the document (the field is otherwise empty — only the hash
	// is published, matching the on-chain pin).
	IncludeRawSP1VK bool

	// SP1VKBytesHex is the raw VK pre-image. Honoured only when
	// IncludeRawSP1VK is true. Operators usually leave this empty
	// because the deploy tool only carries sha256(elf), not the elf
	// itself.
	SP1VKBytesHex string

	// GeneratedAt overrides the default time.Now().UTC(). Useful for
	// reproducible test fixtures.
	GeneratedAt time.Time
}

// BuildANFDocument assembles a canonical anf.Document from the deploy
// pipeline outputs. Returns the document AND the canonical JSON bytes
// — the latter is what the inscription tx's OP_RETURN commits to AND
// what the on-chain hash256 binds to.
func BuildANFDocument(
	cfg *OperatorConfig,
	res *CompileResult,
	opts ANFOptions,
) (*anf.Document, []byte, error) {
	if cfg == nil {
		return nil, nil, errors.New("operator config is required")
	}
	if res == nil {
		return nil, nil, errors.New("compile result is required")
	}
	if len(res.RollupScript) == 0 {
		return nil, nil, errors.New("rollup script is empty")
	}

	kind := opts.Kind
	if kind == "" {
		kind = anf.KindRotation
	}
	includeBridge := kind == anf.KindGenesis
	if opts.IncludeBridge != nil {
		includeBridge = *opts.IncludeBridge
	}

	generatedAt := opts.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	// Verification + VK binding. The on-chain pin is sha256(file
	// contents) per compile.go's contract; we re-emit it lower-cased
	// for canonical-form stability across operators that paste hex with
	// mixed case.
	vkHashHex := strings.ToLower(strings.TrimPrefix(res.VKHashHex, "0x"))
	if !strings.HasPrefix(strings.ToLower(res.VKHashHex), "0x") {
		// Be tolerant: accept bare hex even though Compile() always
		// emits the 0x prefix. The output is normalised either way.
	}
	verification := anf.VerificationDoc{
		Mode:      cfg.VerificationMode,
		SP1VKHash: "0x" + vkHashHex,
	}
	if opts.IncludeRawSP1VK {
		verification.SP1VKBytes = strings.ToLower(strings.TrimPrefix(opts.SP1VKBytesHex, "0x"))
	}

	governance := anf.GovernanceDoc{
		Mode:      cfg.Governance.Mode,
		Threshold: cfg.Governance.Threshold,
	}
	if len(cfg.Governance.Keys) > 0 {
		// SortedHexKeys takes [][]byte; convert from the operator
		// config's []string form.
		raw := make([][]byte, 0, len(cfg.Governance.Keys))
		for i, k := range cfg.Governance.Keys {
			b, err := hex.DecodeString(strings.TrimPrefix(k, "0x"))
			if err != nil {
				return nil, nil, fmt.Errorf("governance key %d hex: %w", i, err)
			}
			raw = append(raw, b)
		}
		governance.Keys = anf.SortedHexKeys(raw)
	}

	rollup := anf.CovenantBinding{
		ScriptHex:        hex.EncodeToString(res.RollupScript),
		ScriptHashSHA256: hexHash(res.RollupScript),
	}
	if len(res.RollupANF) > 0 {
		rollup.ANFIR = json.RawMessage(res.RollupANF)
	}

	doc := &anf.Document{
		Schema:       anf.SchemaVersion,
		Kind:         kind,
		ShardID:      cfg.ShardID,
		ChainID:      cfg.ChainID,
		Verification: verification,
		Governance:   governance,
		Rollup:       rollup,
		GeneratedAt:  anf.FormatGeneratedAt(generatedAt),
	}

	if includeBridge {
		if len(res.BridgeScript) == 0 {
			return nil, nil, errors.New("IncludeBridge=true but compile result has no bridge script")
		}
		bridge := anf.CovenantBinding{
			ScriptHex:        hex.EncodeToString(res.BridgeScript),
			ScriptHashSHA256: hexHash(res.BridgeScript),
		}
		if len(res.BridgeANF) > 0 {
			bridge.ANFIR = json.RawMessage(res.BridgeANF)
		}
		doc.Bridge = &bridge
	}

	if opts.PreviousAnfHash != ([32]byte{}) {
		doc.PreviousAnfHashHex = hex.EncodeToString(opts.PreviousAnfHash[:])
	}

	canon, err := doc.CanonicalJSON()
	if err != nil {
		return nil, nil, fmt.Errorf("canonical JSON: %w", err)
	}
	return doc, canon, nil
}

// ANFDocumentHash is a thin convenience over BuildANFDocument +
// anf.Hash256. Returns the 32-byte hash256(canonical-JSON) that the
// on-chain UpgradeRequest.NewCovenantAnfHash binds to. Used by the
// rotate-vk broadcast path so callers don't have to keep the canonical
// bytes in scope.
func ANFDocumentHash(cfg *OperatorConfig, res *CompileResult, opts ANFOptions) ([32]byte, error) {
	_, canon, err := BuildANFDocument(cfg, res, opts)
	if err != nil {
		return [32]byte{}, err
	}
	return anf.Hash256(canon), nil
}

// PublishANFDocument broadcasts the canonical ANF JSON as a BSV
// transaction whose vout 0 is OP_FALSE OP_RETURN OP_PUSHDATA4 <bytes>.
// The transaction is funded from the deployer's funding UTXO (cfg's
// Funding* fields) and signed with the deployer key. Returns the
// broadcast txid (hex, no prefix).
//
// This call MUST be gated behind an operator-supplied opt-in (the
// --anf-publish flag) — publishing is irreversible and the JSON
// payload is permanently visible on-chain. Dry-run callers should
// invoke BuildANFDocument and inspect the bytes before broadcasting.
//
// The published JSON is byte-identical to BuildANFDocument's output
// so observers re-fetching the inscription via any BSV indexer can
// hash256 it and confirm it matches the on-chain commitment.
func PublishANFDocument(
	ctx context.Context,
	cfg *OperatorConfig,
	canonicalJSON []byte,
) (string, error) {
	if cfg == nil {
		return "", errors.New("operator config is required")
	}
	if len(canonicalJSON) == 0 {
		return "", errors.New("canonical JSON is empty")
	}
	if cfg.ARCEndpoint == "" {
		return "", errors.New("anf-publish requires arcEndpoint in config")
	}
	if cfg.DeployerKeyFile == "" {
		return "", errors.New("anf-publish requires deployerKeyFile in config")
	}
	if cfg.FundingTxID == "" || cfg.FundingScriptHex == "" || cfg.FundingSats == 0 {
		return "", errors.New("anf-publish requires funding* fields in config")
	}

	priv, err := loadDeployerKey(cfg.DeployerKeyFile)
	if err != nil {
		return "", fmt.Errorf("load deployer key: %w", err)
	}

	tx, err := buildANFInscriptionTx(cfg, canonicalJSON, priv)
	if err != nil {
		return "", fmt.Errorf("build inscription tx: %w", err)
	}

	arcClient, err := arc.NewClient(arc.Config{
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
		return "", fmt.Errorf("decode inscription tx hex: %w", err)
	}
	resp, err := arcClient.Broadcast(ctx, rawBytes)
	if err != nil {
		return "", fmt.Errorf("ARC.Broadcast: %w", err)
	}
	return hex.EncodeToString(resp.TxID[:]), nil
}

// WriteANFDocument writes the canonical JSON bytes to path with mode
// 0o644 (world-readable; the document is meant for public audit). A
// trailing newline is appended for shell-tooling friendliness. Used by
// the deploy / rotate-vk dry-run paths so the operator can inspect the
// bytes BEFORE opting in to --anf-publish.
func WriteANFDocument(path string, canonical []byte) error {
	if path == "" {
		return errors.New("path is empty")
	}
	if len(canonical) == 0 {
		return errors.New("canonical bytes are empty")
	}
	return os.WriteFile(path, append(canonical, '\n'), 0o644)
}

// buildANFInscriptionTx assembles a single-input single-output BSV
// transaction whose only output is OP_FALSE OP_RETURN OP_PUSHDATA4
// <canonical>. The funding input is the deployer's pre-funded P2PKH
// UTXO; any over-pay above the fee is left as miner fee (the helper
// does not emit a change output to keep the inscription tx layout
// trivial — operators who need change should size FundingSats more
// tightly).
func buildANFInscriptionTx(
	cfg *OperatorConfig,
	canonical []byte,
	priv *ec.PrivateKey,
) (*transaction.Transaction, error) {
	tx := transaction.NewTransaction()
	if err := tx.AddInputFrom(
		cfg.FundingTxID,
		cfg.FundingVout,
		cfg.FundingScriptHex,
		cfg.FundingSats,
		nil,
	); err != nil {
		return nil, fmt.Errorf("AddInputFrom: %w", err)
	}

	opReturnLS, err := sdkscript.NewFromHex(opReturnHex(canonical))
	if err != nil {
		return nil, fmt.Errorf("op_return script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnLS,
	})

	// Sign the funding input. Same shape as compile.go's
	// BroadcastGenesisTx.
	pubKeyHex := hex.EncodeToString(priv.PubKey().Compressed())
	signer, err := runar.NewLocalSigner(hex.EncodeToString(priv.Serialize()))
	if err != nil {
		return nil, fmt.Errorf("local signer: %w", err)
	}
	sig, err := signer.Sign(tx.Hex(), 0, cfg.FundingScriptHex, int64(cfg.FundingSats), nil)
	if err != nil {
		return nil, fmt.Errorf("sign input 0: %w", err)
	}
	unlockHex := runar.EncodePushData(sig) + runar.EncodePushData(pubKeyHex)
	unlock, err := sdkscript.NewFromHex(unlockHex)
	if err != nil {
		return nil, fmt.Errorf("unlock script: %w", err)
	}
	tx.Inputs[0].UnlockingScript = unlock
	return tx, nil
}
