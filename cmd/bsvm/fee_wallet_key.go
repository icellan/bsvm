package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
)

// feeWalletKeyFilename is the on-disk filename. The content is hex, not
// WIF, but the extension is kept operator-friendly to match the rollout
// plan wording ("fee_wallet.wif").
const feeWalletKeyFilename = "fee_wallet.wif"

// LoadOrCreateFeeWalletKey ensures a BSV fee-wallet private key exists
// at <dir>/fee_wallet.wif and returns the loaded key. On first call the
// key is generated randomly and persisted with mode 0600; subsequent
// calls load the existing key.
//
// The persisted format is the 64-char hex-encoded 32-byte secp256k1
// private key (same format as pkg/rpc/auth/wallet.go uses for server
// identity). Despite the .wif extension, the content is hex not WIF —
// the extension is kept for operator-friendliness and matches the
// plan's wording.
func LoadOrCreateFeeWalletKey(dir string) (*ec.PrivateKey, error) {
	if dir == "" {
		return nil, fmt.Errorf("fee wallet directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating fee wallet dir: %w", err)
	}

	path := filepath.Join(dir, feeWalletKeyFilename)
	raw, err := os.ReadFile(path)
	if err == nil {
		priv, err := ec.PrivateKeyFromHex(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generating fee wallet key: %w", err)
	}
	hexKey := hex.EncodeToString(buf)
	priv, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		return nil, fmt.Errorf("loading generated fee wallet key: %w", err)
	}
	// 0600 because this key spends BSV that pays covenant-advance mining
	// fees; leaking it lets an attacker drain the node's fee balance.
	if err := os.WriteFile(path, []byte(hexKey), 0o600); err != nil {
		return nil, fmt.Errorf("persisting fee wallet key to %s: %w", path, err)
	}
	return priv, nil
}

// FeeWalletBSVAddress returns the P2PKH BSV address for the given
// private key. Intended for auto-funding and logging. The network
// argument selects the address prefix: "mainnet" yields a mainnet
// address; "regtest" and "testnet" yield the testnet/regtest address
// form (the go-sdk does not distinguish the two at the prefix level —
// both use 0x6f).
func FeeWalletBSVAddress(priv *ec.PrivateKey, network string) (string, error) {
	if priv == nil {
		return "", fmt.Errorf("nil private key")
	}
	var mainnet bool
	switch strings.ToLower(network) {
	case "mainnet":
		mainnet = true
	case "regtest", "testnet":
		mainnet = false
	default:
		return "", fmt.Errorf("unknown network %q (want mainnet, testnet, or regtest)", network)
	}
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), mainnet)
	if err != nil {
		return "", fmt.Errorf("deriving P2PKH address: %w", err)
	}
	return addr.AddressString, nil
}
