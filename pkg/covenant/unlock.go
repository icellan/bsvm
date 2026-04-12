package covenant

import (
	"fmt"
)

// scriptPushData encodes data as a Bitcoin Script push operation.
// For data <= 75 bytes, a single-byte length prefix is used.
// For data <= 255 bytes, OP_PUSHDATA1 (0x4c) + 1-byte length is used.
// For data <= 65535 bytes, OP_PUSHDATA2 (0x4d) + 2-byte little-endian length is used.
// For larger data, OP_PUSHDATA4 (0x4e) + 4-byte little-endian length is used.
func scriptPushData(data []byte) []byte {
	n := len(data)
	switch {
	case n == 0:
		// OP_0
		return []byte{0x00}
	case n <= 75:
		result := make([]byte, 1+n)
		result[0] = byte(n)
		copy(result[1:], data)
		return result
	case n <= 255:
		result := make([]byte, 2+n)
		result[0] = 0x4c // OP_PUSHDATA1
		result[1] = byte(n)
		copy(result[2:], data)
		return result
	case n <= 65535:
		result := make([]byte, 3+n)
		result[0] = 0x4d // OP_PUSHDATA2
		result[1] = byte(n)
		result[2] = byte(n >> 8)
		copy(result[3:], data)
		return result
	default:
		result := make([]byte, 5+n)
		result[0] = 0x4e // OP_PUSHDATA4
		result[1] = byte(n)
		result[2] = byte(n >> 8)
		result[3] = byte(n >> 16)
		result[4] = byte(n >> 24)
		copy(result[5:], data)
		return result
	}
}

// BuildUnlockScript builds the unlocking script for an advanceState covenant spend.
// The unlocking script pushes the proof data, new state, public values, and
// batch data onto the stack for the covenant's locking script to verify.
//
// Stack layout (bottom to top, as pushed):
//
//	<newStateEncoded> <publicValues> <batchData> <proof>
//
// The covenant's locking script pops these values and verifies:
//   - Block number increments by 1
//   - Pre-state root matches current state
//   - Post-state root matches new state
//   - Batch data hash matches proof commitment
//   - STARK proof is valid
func BuildUnlockScript(advance *AdvanceData) ([]byte, error) {
	if advance == nil {
		return nil, fmt.Errorf("advance data must not be nil")
	}
	if len(advance.Proof) == 0 {
		return nil, fmt.Errorf("proof must not be empty")
	}
	if len(advance.PublicValues) == 0 {
		return nil, fmt.Errorf("public values must not be empty")
	}
	if len(advance.BatchData) == 0 {
		return nil, fmt.Errorf("batch data must not be empty")
	}

	stateBytes := advance.NewState.Encode()

	var script []byte
	script = append(script, scriptPushData(stateBytes)...)
	script = append(script, scriptPushData(advance.PublicValues)...)
	script = append(script, scriptPushData(advance.BatchData)...)
	script = append(script, scriptPushData(advance.Proof)...)

	return script, nil
}

// BuildFreezeUnlockScript builds the unlocking script for a freeze governance
// action. The governance key holder signs a message to authorize freezing the
// shard, blocking all advanceState calls until unfrozen.
func BuildFreezeUnlockScript(signature []byte) ([]byte, error) {
	if len(signature) == 0 {
		return nil, fmt.Errorf("signature must not be empty")
	}
	return scriptPushData(signature), nil
}

// BuildUnfreezeUnlockScript builds the unlocking script for an unfreeze
// governance action. The governance key holder signs a message to authorize
// unfreezing the shard, re-enabling advanceState calls.
func BuildUnfreezeUnlockScript(signature []byte) ([]byte, error) {
	if len(signature) == 0 {
		return nil, fmt.Errorf("signature must not be empty")
	}
	return scriptPushData(signature), nil
}

// BuildUpgradeUnlockScript builds the unlocking script for a covenant upgrade.
// The governance key holder signs a message to authorize replacing the covenant
// script. The shard must be frozen first (enforced by the locking script).
// The new covenant script is included in the unlocking script so the locking
// script can verify the governance signature covers it.
func BuildUpgradeUnlockScript(signature []byte, newCovenantScript []byte) ([]byte, error) {
	if len(signature) == 0 {
		return nil, fmt.Errorf("signature must not be empty")
	}
	if len(newCovenantScript) == 0 {
		return nil, fmt.Errorf("new covenant script must not be empty")
	}

	var script []byte
	script = append(script, scriptPushData(signature)...)
	script = append(script, scriptPushData(newCovenantScript)...)

	return script, nil
}
