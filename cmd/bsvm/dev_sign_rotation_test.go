package main

import (
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	cli "github.com/urfave/cli/v2"

	covenantdeploy "github.com/icellan/bsvm/deploy/covenant"
)

// fixtureWIF / fixtureTxID are stable test vectors. The WIF is the
// same key used across the bsv-blockchain go-sdk's own
// transaction_test.go corpus, which gives us a canonical signing key
// that's known-good.
const (
	fixtureWIF  = "KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS"
	fixtureTxID = "493a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651" // 65 chars - intentional bad value to exercise validation
	// goodTxID is a real 32-byte hex (64 chars). Picked from the SDK's
	// own signaturehash_test.go fixture so the value is canonically
	// shaped.
	goodTxID = "93a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651"
	// fixturePrevLockHex is a P2PKH locking script for the fixture WIF.
	// We don't need it to be P2PKH for a covenant rotation in
	// production, but for the sighash test the script bytes just need
	// to be the previous output's lock — any non-empty script works.
	fixturePrevLockHex = "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac"
	fixturePrevSats    = uint64(100_000_000)
)

// newSignRotationContext returns a *cli.Context with the provided
// flag values applied. Lets the test exercise cmdDevSignRotation
// without spawning the full app.
func newSignRotationContext(t *testing.T, args map[string]string) *cli.Context {
	t.Helper()
	app := cli.NewApp()
	cmd := devSignRotationCommand()
	set := flag.NewFlagSet("sign-rotation", 0)
	for _, f := range cmd.Flags {
		// Apply the registered defaults first so unset flags behave
		// like a real invocation.
		if err := f.Apply(set); err != nil {
			t.Fatalf("flag.Apply: %v", err)
		}
	}
	for k, v := range args {
		if err := set.Set(k, v); err != nil {
			t.Fatalf("set --%s=%q: %v", k, v, err)
		}
	}
	return cli.NewContext(app, set, nil)
}

// writeWIF persists the test WIF to a temp file and returns the path.
func writeWIF(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "gov.wif")
	if err := os.WriteFile(p, []byte(fixtureWIF+"\n"), 0o600); err != nil {
		t.Fatalf("write wif: %v", err)
	}
	return p
}

// pubKeyOfFixtureWIF returns the compressed pubkey for the fixture
// WIF — used by the verification half of the round-trip test.
func pubKeyOfFixtureWIF(t *testing.T) *ec.PublicKey {
	t.Helper()
	priv, err := ec.PrivateKeyFromWif(fixtureWIF)
	if err != nil {
		t.Fatalf("PrivateKeyFromWif: %v", err)
	}
	return priv.PubKey()
}

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns
// whatever fn wrote. Used to capture the helper's printed signature
// hex so we can verify it against the fixture pubkey.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })

	doneCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		doneCh <- string(buf[:n])
	}()

	fn()
	_ = w.Close()
	return <-doneCh
}

// buildUnsignedUpgradeTx returns an unsigned upgrade-spend tx skeleton
// for the fixture inputs. Used by the --upgrade-tx-hex mode path.
func buildUnsignedUpgradeTx(t *testing.T, newScript []byte) *transaction.Transaction {
	t.Helper()
	tx, err := covenantdeploy.BuildUpgradeSpendTx(goodTxID, 0, fixturePrevSats, newScript, nil)
	if err != nil {
		t.Fatalf("BuildUpgradeSpendTx: %v", err)
	}
	return tx
}

// TestDevSignRotation_RawTxMode_ProducesValidSignature drives the
// helper's --upgrade-tx-hex path and asserts the printed signature
// hex parses to a DER ECDSA signature that verifies against the
// fixture WIF's public key over the BIP-143 sighash.
func TestDevSignRotation_RawTxMode_ProducesValidSignature(t *testing.T) {
	wifPath := writeWIF(t)
	newScript := []byte{0x51} // OP_1 — minimal placeholder for the new covenant lock

	tx := buildUnsignedUpgradeTx(t, newScript)
	out := captureStdout(t, func() {
		ctx := newSignRotationContext(t, map[string]string{
			"wif":                     wifPath,
			"upgrade-tx-hex":          tx.Hex(),
			"prev-locking-script-hex": fixturePrevLockHex,
			"prev-sats":               itoa(fixturePrevSats),
		})
		if err := cmdDevSignRotation(ctx); err != nil {
			t.Fatalf("cmdDevSignRotation: %v", err)
		}
	})
	sigHex := strings.TrimSpace(out)
	if sigHex == "" {
		t.Fatal("expected signature on stdout, got empty string")
	}

	verifySignatureRoundTrip(t, sigHex, tx, fixturePrevLockHex, fixturePrevSats)
}

// TestDevSignRotation_PartialBundleMode_AppendsToBundle drives the
// helper's --partial-bundle path with --out, asserts the new sig
// shows up in the bundle, and verifies it against the fixture pubkey.
func TestDevSignRotation_PartialBundleMode_AppendsToBundle(t *testing.T) {
	wifPath := writeWIF(t)
	newScript := []byte{0x51}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "rotate-vk.partial.json")
	startBundle := &covenantdeploy.PartialSigBundle{
		Note:               "test fixture",
		ChainID:            8453111,
		CurrentBlockNumber: 12847,
		NewCovenantScript:  hex.EncodeToString(newScript),
		// Fields irrelevant for sighash computation can be empty.
		GovernanceSigs: []string{strings.Repeat("aa", 71)}, // pretend op #1 already signed
	}
	if err := covenantdeploy.WritePartialSigBundle(bundlePath, startBundle); err != nil {
		t.Fatalf("seed bundle: %v", err)
	}

	outPath := filepath.Join(dir, "rotate-vk.partial.updated.json")
	out := captureStdout(t, func() {
		ctx := newSignRotationContext(t, map[string]string{
			"wif":                     wifPath,
			"partial-bundle":          bundlePath,
			"covenant-txid":           goodTxID,
			"covenant-vout":           "0",
			"covenant-sats":           itoa(fixturePrevSats),
			"prev-locking-script-hex": fixturePrevLockHex,
			"out":                     outPath,
		})
		if err := cmdDevSignRotation(ctx); err != nil {
			t.Fatalf("cmdDevSignRotation: %v", err)
		}
	})
	sigHex := strings.TrimSpace(out)
	if sigHex == "" {
		t.Fatal("expected signature on stdout, got empty")
	}

	updated, err := covenantdeploy.LoadPartialSigBundle(outPath)
	if err != nil {
		t.Fatalf("LoadPartialSigBundle: %v", err)
	}
	if got, want := len(updated.GovernanceSigs), 2; got != want {
		t.Fatalf("updated bundle should have %d sigs, got %d", want, got)
	}
	if updated.GovernanceSigs[0] != strings.Repeat("aa", 71) {
		t.Errorf("seed signature was not preserved at index 0")
	}
	if updated.GovernanceSigs[1] != sigHex {
		t.Errorf("appended signature mismatch: bundle[1]=%s stdout=%s",
			updated.GovernanceSigs[1], sigHex)
	}

	// The reconstructed tx for verification: same inputs the helper
	// used internally.
	tx, err := covenantdeploy.BuildUpgradeSpendTx(goodTxID, 0, fixturePrevSats, newScript, nil)
	if err != nil {
		t.Fatalf("BuildUpgradeSpendTx: %v", err)
	}
	verifySignatureRoundTrip(t, sigHex, tx, fixturePrevLockHex, fixturePrevSats)
}

// TestDevSignRotation_RejectsConflictingInputModes asserts the helper
// surfaces a clear error when both --upgrade-tx-hex and
// --partial-bundle are supplied.
func TestDevSignRotation_RejectsConflictingInputModes(t *testing.T) {
	wifPath := writeWIF(t)
	ctx := newSignRotationContext(t, map[string]string{
		"wif":                     wifPath,
		"upgrade-tx-hex":          "00",
		"partial-bundle":          "/dev/null",
		"prev-locking-script-hex": fixturePrevLockHex,
		"prev-sats":               itoa(fixturePrevSats),
	})
	err := cmdDevSignRotation(ctx)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

// TestDevSignRotation_RejectsMissingPrevLockingScript asserts the
// helper rejects an invocation that omits the previous locking script
// (BIP-143 sighash is undefined without it).
func TestDevSignRotation_RejectsMissingPrevLockingScript(t *testing.T) {
	wifPath := writeWIF(t)
	ctx := newSignRotationContext(t, map[string]string{
		"wif":            wifPath,
		"upgrade-tx-hex": "00",
		"prev-sats":      itoa(fixturePrevSats),
	})
	err := cmdDevSignRotation(ctx)
	if err == nil || !strings.Contains(err.Error(), "prev-locking-script-hex") {
		t.Fatalf("expected prev-locking-script-hex error, got %v", err)
	}
}

// TestLoadGovernanceWIF_AcceptsHexFallback asserts the helper accepts
// a 32-byte hex private-key file in addition to canonical WIF — this
// mirrors the loadDeployerKey precedent in deploy/covenant/compile.go
// so operators with hex-only secret stores aren't blocked.
func TestLoadGovernanceWIF_AcceptsHexFallback(t *testing.T) {
	priv, err := ec.PrivateKeyFromWif(fixtureWIF)
	if err != nil {
		t.Fatalf("decode fixture wif: %v", err)
	}
	hexKey := hex.EncodeToString(priv.Serialize())

	dir := t.TempDir()
	p := filepath.Join(dir, "hexkey.txt")
	if err := os.WriteFile(p, []byte(hexKey), 0o600); err != nil {
		t.Fatalf("write hex key: %v", err)
	}

	got, err := loadGovernanceWIF(p)
	if err != nil {
		t.Fatalf("loadGovernanceWIF(hex): %v", err)
	}
	if hex.EncodeToString(got.Serialize()) != hexKey {
		t.Errorf("hex key round-trip mismatch")
	}
}

// verifySignatureRoundTrip parses the helper's emitted hex (DER +
// sighashType byte), strips the trailing 0x41, and confirms the DER
// signature verifies against the fixture pubkey over the same BIP-143
// sighash the helper computed.
func verifySignatureRoundTrip(t *testing.T, sigHex string, tx *transaction.Transaction, prevLockHex string, prevSats uint64) {
	t.Helper()

	signed, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode emitted sig hex: %v", err)
	}
	if len(signed) < 8 {
		t.Fatalf("emitted sig too short: %d bytes", len(signed))
	}
	if got := signed[len(signed)-1]; got != byte(sighash.AllForkID) {
		t.Errorf("expected trailing sighashType=0x41, got 0x%02x", got)
	}
	der := signed[:len(signed)-1]

	sig, err := ec.ParseDERSignature(der)
	if err != nil {
		t.Fatalf("ParseDERSignature: %v (sigHex=%s)", err, sigHex)
	}

	// Re-pin the prev output on input 0 for a clean digest derivation
	// (the helper does the same thing internally).
	prevLockBytes, err := hex.DecodeString(prevLockHex)
	if err != nil {
		t.Fatalf("decode prevLockHex: %v", err)
	}
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      prevSats,
		LockingScript: sdkscript.NewFromBytes(prevLockBytes),
	})
	digest, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("CalcInputSignatureHash: %v", err)
	}

	pub := pubKeyOfFixtureWIF(t)
	if !sig.Verify(digest, pub) {
		t.Fatalf("signature does not verify against fixture pubkey")
	}
}

// itoa is a tiny helper that converts a uint64 to a base-10 string —
// used so the test reads naturally without sprinkling
// strconv.FormatUint everywhere.
func itoa(v uint64) string {
	return strings.TrimSpace(uint64String(v))
}

func uint64String(v uint64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
