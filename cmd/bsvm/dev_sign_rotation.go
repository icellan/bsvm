package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	cli "github.com/urfave/cli/v2"

	covenantdeploy "github.com/icellan/bsvm/deploy/covenant"
)

// devSignRotationCommand registers the `bsvm dev sign-rotation`
// subcommand. The helper signs the input-0 BIP-143 sighash of a
// rotate-vk upgrade transaction with a governance WIF and emits the
// resulting BSV-canonical signature (DER + 0x41 sighashType byte) in
// hex. It closes the operator-side signing gap documented in
// docs/operator/vk-rotation.md §1 (formerly tracked as
// WW-rotation-sign).
//
// Two input modes are supported:
//
//   - "raw tx" mode (--upgrade-tx-hex + --prev-locking-script-hex +
//     --prev-sats): the helper does NOT touch the rotation config or
//     partial bundle; it only computes the input-0 sighash and signs
//     it. Useful for HSM/airgap workflows where the unsigned upgrade
//     tx has been produced offline.
//
//   - "partial bundle" mode (--partial-bundle + --covenant-txid +
//     --covenant-vout + --covenant-sats + --prev-locking-script-hex):
//     the helper rebuilds the upgrade-tx skeleton via
//     covenantdeploy.BuildUpgradeSpendTx using the bundle's
//     newCovenantScriptHex, computes the sighash, signs, and
//     either prints the new signature hex on stdout OR appends it
//     to the bundle's governanceSigsHex when --out is set. The
//     latter shape matches what rotate-vk --broadcast consumes.
//
// Sighash format: BIP-143 SIGHASH_ALL | SIGHASH_FORKID = 0x41 against
// input 0, with prevLockScript = current covenant locking script and
// prevSats = covenantSatsLive. The signature shape emitted is the
// BSV-canonical DER encoding of the ECDSA signature followed by the
// single sighashType byte (0x41), matching what
// covenant.BuildUpgradeUnlockScript embeds and what the on-chain
// upgrade method's CheckMultiSig consumes (see UpgradeRequest.GovernanceSigs
// doc — "raw 71/72-byte ECDSA signature (DER + sighashType byte)").
//
// Note on the task brief's "64-byte" wording: the BIP-143 raw R||S
// pair is 64 bytes, but the BSV covenant always consumes
// DER+sighashType (~71-72 bytes). We emit the latter so the operator
// can paste the hex straight into the rotation config's
// governanceSigsHex array.
func devSignRotationCommand() *cli.Command {
	return &cli.Command{
		Name:  "sign-rotation",
		Usage: "Sign a rotate-vk upgrade tx's input-0 sighash with a governance WIF",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "wif",
				Usage: "path to a governance WIF file (BSV-canonical WIF; falls back to 32-byte hex)",
			},
			&cli.StringFlag{
				Name:  "upgrade-tx-hex",
				Usage: "raw upgrade tx hex; mutually exclusive with --partial-bundle",
			},
			&cli.StringFlag{
				Name:  "prev-locking-script-hex",
				Usage: "live covenant locking-script hex (required for sighash computation)",
			},
			&cli.Uint64Flag{
				Name:  "prev-sats",
				Usage: "live covenant satoshi value (covenantSatsLive in rotation config)",
			},
			&cli.StringFlag{
				Name:  "partial-bundle",
				Usage: "path to rotate-vk.partial.json; mutually exclusive with --upgrade-tx-hex",
			},
			&cli.StringFlag{
				Name:  "covenant-txid",
				Usage: "live covenant outpoint txid (required with --partial-bundle)",
			},
			&cli.UintFlag{
				Name:  "covenant-vout",
				Usage: "live covenant outpoint vout (required with --partial-bundle)",
			},
			&cli.Uint64Flag{
				Name:  "covenant-sats",
				Usage: "live covenant satoshi value (required with --partial-bundle); aliased by --prev-sats when set",
			},
			&cli.StringFlag{
				Name:  "out",
				Usage: "optional path to write the updated partial bundle (only meaningful in --partial-bundle mode)",
			},
		},
		Action: cmdDevSignRotation,
	}
}

// cmdDevSignRotation implements the helper. See devSignRotationCommand
// for the input-mode matrix.
func cmdDevSignRotation(ctx *cli.Context) error {
	wifPath := strings.TrimSpace(ctx.String("wif"))
	if wifPath == "" {
		return errors.New("--wif is required")
	}

	upgradeTxHex := strings.TrimSpace(ctx.String("upgrade-tx-hex"))
	partialPath := strings.TrimSpace(ctx.String("partial-bundle"))
	if upgradeTxHex == "" && partialPath == "" {
		return errors.New("supply either --upgrade-tx-hex or --partial-bundle")
	}
	if upgradeTxHex != "" && partialPath != "" {
		return errors.New("--upgrade-tx-hex and --partial-bundle are mutually exclusive")
	}

	prevLockHex := strings.TrimSpace(ctx.String("prev-locking-script-hex"))
	if prevLockHex == "" {
		return errors.New("--prev-locking-script-hex is required for BIP-143 sighash computation")
	}
	prevLockHex = strings.TrimPrefix(prevLockHex, "0x")
	prevLockBytes, err := hex.DecodeString(prevLockHex)
	if err != nil {
		return fmt.Errorf("--prev-locking-script-hex: %w", err)
	}
	if len(prevLockBytes) == 0 {
		return errors.New("--prev-locking-script-hex must decode to a non-empty script")
	}

	priv, err := loadGovernanceWIF(wifPath)
	if err != nil {
		return fmt.Errorf("load wif: %w", err)
	}

	// Build (or load) the upgrade tx skeleton.
	var (
		tx       *transaction.Transaction
		bundle   *covenantdeploy.PartialSigBundle
		prevSats uint64
	)
	if upgradeTxHex != "" {
		prevSats = ctx.Uint64("prev-sats")
		if prevSats == 0 {
			return errors.New("--prev-sats must be > 0 in --upgrade-tx-hex mode")
		}
		tx, err = transaction.NewTransactionFromHex(strings.TrimPrefix(upgradeTxHex, "0x"))
		if err != nil {
			return fmt.Errorf("parse --upgrade-tx-hex: %w", err)
		}
		if tx.InputCount() == 0 {
			return errors.New("upgrade tx has no inputs")
		}
	} else {
		// --partial-bundle path.
		bundle, err = covenantdeploy.LoadPartialSigBundle(partialPath)
		if err != nil {
			return err
		}
		tx, prevSats, err = rebuildUpgradeTxFromBundle(ctx, bundle)
		if err != nil {
			return fmt.Errorf("rebuild upgrade tx from bundle: %w", err)
		}
	}

	// Pin the previous output (locking script + sats) on input 0 so
	// CalcInputSignatureHash gets the right BIP-143 inputs. This is
	// required even when AddInputFrom seeded a placeholder script —
	// the live covenant's locking script bytes drive the sighash.
	prevScript := sdkscript.NewFromBytes(prevLockBytes)
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      prevSats,
		LockingScript: prevScript,
	})

	// SIGHASH_ALL | SIGHASH_FORKID = 0x41 — the BSV-canonical post-UAHF
	// sighash type for governance signatures over a single covenant
	// spend.
	const shf = sighash.AllForkID
	digest, err := tx.CalcInputSignatureHash(0, shf)
	if err != nil {
		return fmt.Errorf("CalcInputSignatureHash: %w", err)
	}

	sig, err := priv.Sign(digest)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	// BSV signatures embedded in unlock scripts are DER + sighashType.
	// The covenant's CheckMultiSig consumes exactly this shape — see
	// covenant.UpgradeRequest.GovernanceSigs ("raw 71/72-byte ECDSA
	// signature (DER + sighashType byte)").
	der := sig.Serialize()
	signed := append(der, byte(shf))
	sigHex := hex.EncodeToString(signed)

	outPath := strings.TrimSpace(ctx.String("out"))
	if outPath == "" || bundle == nil {
		// Stdout-only path. --out is ignored in --upgrade-tx-hex mode
		// because there is no bundle to update; the operator can paste
		// the printed hex into the rotation config's governanceSigsHex.
		fmt.Println(sigHex)
		return nil
	}

	// Append to the bundle's governanceSigsHex and write back. We
	// preserve any existing signatures so M-of-N collection can chain
	// across operators without dropping prior contributions.
	bundle.GovernanceSigs = append(bundle.GovernanceSigs, sigHex)
	if err := covenantdeploy.WritePartialSigBundle(outPath, bundle); err != nil {
		return fmt.Errorf("write updated bundle: %w", err)
	}
	// Also surface the signature on stdout so the operator can audit
	// the value that was appended without re-reading the file.
	fmt.Println(sigHex)
	return nil
}

// rebuildUpgradeTxFromBundle reconstructs the upgrade-spend tx
// skeleton needed for sighash computation from a partial-sig bundle
// + the operator-supplied outpoint coordinates (which the bundle
// intentionally does NOT carry).
func rebuildUpgradeTxFromBundle(
	ctx *cli.Context,
	bundle *covenantdeploy.PartialSigBundle,
) (*transaction.Transaction, uint64, error) {
	covTxID := strings.TrimSpace(ctx.String("covenant-txid"))
	if covTxID == "" {
		return nil, 0, errors.New("--covenant-txid is required in --partial-bundle mode")
	}
	covTxID = strings.TrimPrefix(covTxID, "0x")
	covVout := uint32(ctx.Uint("covenant-vout"))
	covSats := ctx.Uint64("covenant-sats")
	if covSats == 0 {
		// Fall back to --prev-sats if --covenant-sats was not set;
		// they are the same value (the live covenant's satoshi
		// payload), the alias just keeps the flag set readable in
		// either ordering.
		covSats = ctx.Uint64("prev-sats")
	}
	if covSats == 0 {
		return nil, 0, errors.New("--covenant-sats (or --prev-sats) must be > 0 in --partial-bundle mode")
	}

	newScriptHex := strings.TrimPrefix(bundle.NewCovenantScript, "0x")
	newScript, err := hex.DecodeString(newScriptHex)
	if err != nil {
		return nil, 0, fmt.Errorf("bundle.newCovenantScriptHex: %w", err)
	}
	if len(newScript) == 0 {
		return nil, 0, errors.New("bundle.newCovenantScriptHex is empty")
	}

	// We pass nil unlockBytes so BuildUpgradeSpendTx skips embedding
	// the unlock script — sighash is independent of the unlock and the
	// helper's caller hasn't collected enough signatures to assemble
	// it yet anyway.
	tx, err := covenantdeploy.BuildUpgradeSpendTx(covTxID, covVout, covSats, newScript, nil)
	if err != nil {
		return nil, 0, err
	}
	return tx, covSats, nil
}

// loadGovernanceWIF parses a WIF file into a *ec.PrivateKey. The file
// content is trimmed of surrounding whitespace; both BSV-canonical WIF
// (starts with K/L/c/9) and 32-byte hex are accepted because operators'
// secret stores standardise on different formats. The WIF path is
// preferred — falling back to hex matches the existing
// loadDeployerKey/LoadOrCreateFeeWalletKey precedent in the codebase
// (which only accepts hex; we keep that working while also accepting
// real WIF for governance keys, which are typically issued in WIF form).
func loadGovernanceWIF(path string) (*ec.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled by design
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	val := strings.TrimSpace(string(raw))
	val = strings.TrimPrefix(val, "0x")
	if val == "" {
		return nil, fmt.Errorf("%s is empty", path)
	}

	// Try WIF first — operators issuing governance keys typically use
	// WIF (it carries the network byte + checksum for paste safety).
	if priv, werr := ec.PrivateKeyFromWif(val); werr == nil {
		return priv, nil
	}

	// Fall back to raw hex. PrivateKeyFromHex accepts a 32-byte hex
	// string (no 0x prefix); we already stripped any prefix above.
	priv, err := ec.PrivateKeyFromHex(val)
	if err != nil {
		return nil, fmt.Errorf("parse %s: not a valid WIF or 32-byte hex private key", path)
	}
	return priv, nil
}

// rebuildUpgradeTxJSON dumps a debugging-friendly representation of
// the rebuilt tx + sighash inputs. Reserved for future verbose-flag
// wiring; kept here so the partial-bundle path can be inspected from
// a test harness without reaching into the SDK internals.
//
//nolint:unused // exported via tests only; retained for future --debug wiring.
func rebuildUpgradeTxJSON(tx *transaction.Transaction, prevLockHex string, prevSats uint64) string {
	type dump struct {
		TxHex            string `json:"txHex"`
		PrevLockingHex   string `json:"prevLockingScriptHex"`
		PrevSats         uint64 `json:"prevSats"`
		Input0OutpointTx string `json:"input0OutpointTxid"`
	}
	d := dump{
		TxHex:          tx.Hex(),
		PrevLockingHex: prevLockHex,
		PrevSats:       prevSats,
	}
	if tx.InputCount() > 0 {
		d.Input0OutpointTx = tx.Inputs[0].SourceTXID.String()
	}
	enc, _ := json.MarshalIndent(d, "", "  ")
	return string(enc)
}
