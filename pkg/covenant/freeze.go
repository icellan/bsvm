// Package covenant: freeze / unfreeze unlock-script assembly.
//
// Spec 12 §"Multisig governance actions" defines three governance
// entry points on the rollup contract: freeze, unfreeze, upgrade.
// pkg/covenant/upgrade.go covers the upgrade path; this file covers
// freeze + unfreeze.
//
// Both freeze and unfreeze take ONLY governance signatures as inputs:
//
//   - Freeze*  : assert frozen == 0, verify sig(s), set frozen = 1
//   - Unfreeze*: assert frozen == 1, verify sig(s), set frozen = 0
//
// The covenant locking script is unchanged across freeze/unfreeze
// (only the encoded `frozen` state byte flips). The continuation
// output therefore re-uses the live UTXO's current locking script.
//
// Like BuildUpgradeUnlockScript, the helpers below assemble the args
// slice the runar SDK feeds to contract.Call. They do NOT compute
// BIP-143 sighashes — the caller (cmd/bsvm OnReady) supplies pre-
// signed governance signatures collected from the proposal workflow.
package covenant

import (
	"errors"
	"fmt"
)

// FreezeMethodName picks the contract method that applies for a
// given governance configuration. Mirrors UpgradeMethodName but
// targets the freeze entry points.
//
//   - "freezeSingleKey"   for single_key governance
//   - "freezeMultiSig2"   for 2-of-N multisig (Threshold == 2)
//   - "freezeMultiSig3"   for 3-of-N multisig (Threshold == 3)
//
// Returns ("", error) for governance modes that have no freeze
// path (mode "none" — the trustless profile is intentionally
// excluded; a none-governance shard cannot be frozen, by design).
func FreezeMethodName(g GovernanceConfig) (string, error) {
	switch g.Mode {
	case GovernanceNone:
		return "", errors.New("freeze not permitted under governance mode 'none' (no key authorises the spend)")
	case GovernanceSingleKey:
		return "freezeSingleKey", nil
	case GovernanceMultiSig:
		switch g.Threshold {
		case 2:
			return "freezeMultiSig2", nil
		case 3:
			return "freezeMultiSig3", nil
		default:
			return "", fmt.Errorf("multisig threshold %d not supported on-chain (only 2-of-N and 3-of-N freeze methods exist)", g.Threshold)
		}
	default:
		return "", fmt.Errorf("unknown governance mode %v", g.Mode)
	}
}

// UnfreezeMethodName picks the contract method that applies for a
// given governance configuration. Mirrors FreezeMethodName.
func UnfreezeMethodName(g GovernanceConfig) (string, error) {
	switch g.Mode {
	case GovernanceNone:
		return "", errors.New("unfreeze not permitted under governance mode 'none' (no key authorises the spend)")
	case GovernanceSingleKey:
		return "unfreezeSingleKey", nil
	case GovernanceMultiSig:
		switch g.Threshold {
		case 2:
			return "unfreezeMultiSig2", nil
		case 3:
			return "unfreezeMultiSig3", nil
		default:
			return "", fmt.Errorf("multisig threshold %d not supported on-chain (only 2-of-N and 3-of-N unfreeze methods exist)", g.Threshold)
		}
	default:
		return "", fmt.Errorf("unknown governance mode %v", g.Mode)
	}
}

// BuildFreezeUnlockScript returns the unlock-script bytes for the
// rollup contract's freeze method matching the supplied governance
// config. The only inputs are governance signatures — freeze does not
// take public values, batch data, proof, or block-number arguments.
//
// Returns the raw unlock-script bytes (NOT hex-encoded). The caller
// wraps these into a sdkscript.Script for embedding into the spend
// tx's input.
func BuildFreezeUnlockScript(sigs [][]byte, gov GovernanceConfig) ([]byte, error) {
	method, err := FreezeMethodName(gov)
	if err != nil {
		return nil, err
	}
	if want := expectedSigCount(gov); len(sigs) != want {
		return nil, fmt.Errorf("freeze method %s requires %d governance signature(s), got %d",
			method, want, len(sigs))
	}
	return encodeGovernanceSigArgs(sigs), nil
}

// BuildUnfreezeUnlockScript returns the unlock-script bytes for the
// rollup contract's unfreeze method. Mirrors BuildFreezeUnlockScript.
func BuildUnfreezeUnlockScript(sigs [][]byte, gov GovernanceConfig) ([]byte, error) {
	method, err := UnfreezeMethodName(gov)
	if err != nil {
		return nil, err
	}
	if want := expectedSigCount(gov); len(sigs) != want {
		return nil, fmt.Errorf("unfreeze method %s requires %d governance signature(s), got %d",
			method, want, len(sigs))
	}
	return encodeGovernanceSigArgs(sigs), nil
}

// encodeGovernanceSigArgs concatenates push-encoded governance
// signature args. Shared by freeze + unfreeze (which take only sigs)
// so both paths agree byte-for-byte on the wire format.
func encodeGovernanceSigArgs(sigs [][]byte) []byte {
	out := make([]byte, 0, len(sigs)*80)
	for _, sig := range sigs {
		out = append(out, encodePushData(sig)...)
	}
	return out
}
