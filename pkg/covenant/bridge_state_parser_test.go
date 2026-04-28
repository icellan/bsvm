package covenant

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// pushdataPrefix returns the minimal pushdata opcode + length prefix
// for a payload of length n (matches the encoder Rúnar codegen
// emits). Used to construct synthetic bridge-covenant scripts.
func pushdataPrefix(n int) []byte {
	switch {
	case n <= 0x4b:
		return []byte{byte(n)}
	case n <= 0xff:
		return []byte{0x4c, byte(n)}
	case n <= 0xffff:
		return []byte{0x4d, byte(n & 0xff), byte((n >> 8) & 0xff)}
	default:
		return []byte{0x4e,
			byte(n & 0xff), byte((n >> 8) & 0xff),
			byte((n >> 16) & 0xff), byte((n >> 24) & 0xff),
		}
	}
}

// buildSyntheticBridgeScript synthesises a locking-script byte
// sequence that mirrors the structure Rúnar codegen emits for the
// bridge covenant: one 48-byte BridgeState pushdata, one 32-byte
// readonly StateCovenantScriptHash pushdata, plus an OP_RETURN-style
// data marker. The exact ordering doesn't matter — the parser scans
// in source order and picks the first 48-byte pushdata that decodes.
func buildSyntheticBridgeScript(state BridgeState, stateHash types.Hash) []byte {
	encoded := state.Encode()
	var out []byte
	// 32-byte readonly slot (StateCovenantScriptHash).
	out = append(out, pushdataPrefix(32)...)
	out = append(out, stateHash[:]...)
	// 48-byte mutable BridgeState slot.
	out = append(out, pushdataPrefix(48)...)
	out = append(out, encoded...)
	// Some non-push opcodes to mirror the verifier preamble that
	// follows the readonly + state slots in real artifacts.
	out = append(out, 0x76 /* OP_DUP */, 0xa9 /* OP_HASH160 */, 0x88 /* OP_EQUALVERIFY */)
	return out
}

// TestParseBridgeStateFromScript_RoundTrip verifies that a synthetic
// bridge-covenant script with a known BridgeState pushdata round-trips
// through the parser.
func TestParseBridgeStateFromScript_RoundTrip(t *testing.T) {
	want := BridgeState{
		Balance:               5_000_000_000,
		WithdrawalNonce:       42,
		WithdrawalsCommitment: types.HexToHash("0xc0ffee"),
	}
	stateHash := types.HexToHash("0xfeedface")

	scriptHex := hex.EncodeToString(buildSyntheticBridgeScript(want, stateHash))
	got, err := ParseBridgeStateFromScript(scriptHex)
	if err != nil {
		t.Fatalf("ParseBridgeStateFromScript: %v", err)
	}
	if got.Balance != want.Balance {
		t.Errorf("Balance = %d, want %d", got.Balance, want.Balance)
	}
	if got.WithdrawalNonce != want.WithdrawalNonce {
		t.Errorf("WithdrawalNonce = %d, want %d", got.WithdrawalNonce, want.WithdrawalNonce)
	}
	if got.WithdrawalsCommitment != want.WithdrawalsCommitment {
		t.Errorf("WithdrawalsCommitment = %x, want %x",
			got.WithdrawalsCommitment, want.WithdrawalsCommitment)
	}
}

// TestParseBridgeStateFromScript_PushDataOpcodes verifies that the
// parser tolerates each of the four push opcode encodings (direct
// push, PUSHDATA1, PUSHDATA2, PUSHDATA4).
func TestParseBridgeStateFromScript_PushDataOpcodes(t *testing.T) {
	state := BridgeState{
		Balance:               1234,
		WithdrawalNonce:       5,
		WithdrawalsCommitment: types.Hash{},
	}
	encoded := state.Encode()

	cases := []struct {
		name   string
		prefix []byte
	}{
		{"direct-push-48", []byte{48}},           // 0x30 — direct push
		{"pushdata1", []byte{0x4c, 48}},          // OP_PUSHDATA1
		{"pushdata2", []byte{0x4d, 48, 0}},       // OP_PUSHDATA2 little-endian
		{"pushdata4", []byte{0x4e, 48, 0, 0, 0}}, // OP_PUSHDATA4 little-endian
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := append([]byte(nil), tc.prefix...)
			script = append(script, encoded...)
			got, err := ParseBridgeStateFromScript(hex.EncodeToString(script))
			if err != nil {
				t.Fatalf("ParseBridgeStateFromScript: %v", err)
			}
			if got.Balance != state.Balance {
				t.Errorf("Balance = %d, want %d", got.Balance, state.Balance)
			}
		})
	}
}

// TestParseBridgeStateFromScript_RejectsMalformed pins the error
// surface for malformed scripts: empty input, truncated pushdata,
// scripts with no 48-byte pushdata.
func TestParseBridgeStateFromScript_RejectsMalformed(t *testing.T) {
	t.Run("empty-script", func(t *testing.T) {
		_, err := ParseBridgeStateFromScript("")
		if err == nil {
			t.Fatal("expected error for empty script")
		}
	})
	t.Run("invalid-hex", func(t *testing.T) {
		_, err := ParseBridgeStateFromScript("zzz")
		if err == nil {
			t.Fatal("expected error for invalid hex")
		}
	})
	t.Run("truncated-push", func(t *testing.T) {
		// 0x30 = direct push of 48 bytes; payload is only 5 bytes.
		_, err := ParseBridgeStateFromScript("3001020304" + "05")
		if err == nil {
			t.Fatal("expected error for truncated push")
		}
		if !strings.Contains(err.Error(), "truncated") {
			t.Errorf("error %q does not mention truncated", err.Error())
		}
	})
	t.Run("no-48-byte-push", func(t *testing.T) {
		// 32-byte and 20-byte pushes only — no BridgeState slot.
		var script []byte
		script = append(script, pushdataPrefix(32)...)
		script = append(script, make([]byte, 32)...)
		script = append(script, pushdataPrefix(20)...)
		script = append(script, make([]byte, 20)...)
		_, err := ParseBridgeStateFromScript(hex.EncodeToString(script))
		if err == nil {
			t.Fatal("expected error when no 48-byte pushdata is present")
		}
		if !strings.Contains(err.Error(), "BridgeState") {
			t.Errorf("error %q does not mention BridgeState", err.Error())
		}
	})
}

// TestWalkScriptPushdata_HandlesNonPushOpcodes verifies the walker
// treats non-push opcodes as zero-payload (script position advances
// by one) — important because real locking scripts interleave
// arithmetic / control opcodes between pushdata.
func TestWalkScriptPushdata_HandlesNonPushOpcodes(t *testing.T) {
	// Build: OP_DUP, push(3), OP_HASH160, push(1).
	script := []byte{
		0x76,          // OP_DUP
		0x03, 1, 2, 3, // push 3 bytes
		0xa9,    // OP_HASH160
		0x01, 9, // push 1 byte
		0x88, // OP_EQUALVERIFY
	}
	pushes, err := walkScriptPushdata(script)
	if err != nil {
		t.Fatalf("walkScriptPushdata: %v", err)
	}
	if len(pushes) != 2 {
		t.Fatalf("got %d pushes, want 2", len(pushes))
	}
	if string(pushes[0]) != string([]byte{1, 2, 3}) {
		t.Errorf("push 0 = %x, want 010203", pushes[0])
	}
	if string(pushes[1]) != string([]byte{9}) {
		t.Errorf("push 1 = %x, want 09", pushes[1])
	}
}
