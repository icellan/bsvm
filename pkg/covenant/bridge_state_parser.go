package covenant

import (
	"encoding/hex"
	"fmt"
)

// ParseBridgeStateFromScript decodes the bridge covenant's
// BridgeState from its on-chain locking script by walking the script
// for a 48-byte pushdata that successfully decodes via
// DecodeBridgeState.
//
// The Rúnar codegen embeds the encoded BridgeState (Balance | nonce
// | WithdrawalsCommitment, 48 bytes total) as a single pushdata at
// the head of the locking script, alongside fixed configuration
// pushdata for the readonly StateCovenantScriptHash (32 bytes) and
// any verification-mode-specific preamble. The parser scans pushdata
// in order and returns the first 48-byte payload that decodes
// successfully — i.e. the first pushdata that holds a valid
// BridgeState. This is robust to compiler reorderings as long as
// the state slot is the only 48-byte pushdata in the script (which
// it is for the bridge covenant; verification keys are larger).
//
// Returns an error when the script is malformed (truncated pushdata)
// or contains no 48-byte pushdata that decodes as a BridgeState.
//
// Note (TODO(QQ-state-parse)): the current heuristic walks every
// pushdata and picks the first 48-byte payload. If the runar codegen
// ever adds another 48-byte readonly slot to the bridge covenant
// (which would shadow the state slot), this parser must be tightened
// to use a positional / typed cue from the codegen artifact instead.
// As of spec 13 the bridge covenant's only 48-byte pushdata is the
// BridgeState slot.
func ParseBridgeStateFromScript(scriptHex string) (*BridgeState, error) {
	raw, err := hex.DecodeString(scriptHex)
	if err != nil {
		return nil, fmt.Errorf("decode script hex: %w", err)
	}
	return ParseBridgeStateFromScriptBytes(raw)
}

// ParseBridgeStateFromScriptBytes is the raw-bytes form of
// ParseBridgeStateFromScript. Callers that already hold the locking
// script as a byte slice should prefer this entry point to avoid the
// hex round-trip.
func ParseBridgeStateFromScriptBytes(script []byte) (*BridgeState, error) {
	if len(script) == 0 {
		return nil, fmt.Errorf("bridge state parser: empty script")
	}
	pushes, err := walkScriptPushdata(script)
	if err != nil {
		return nil, fmt.Errorf("bridge state parser: %w", err)
	}
	for _, p := range pushes {
		if len(p) != bridgeStateEncodedSize {
			continue
		}
		state, derr := DecodeBridgeState(p)
		if derr == nil {
			return state, nil
		}
	}
	return nil, fmt.Errorf("bridge state parser: no valid 48-byte BridgeState pushdata found in script (len=%d)", len(script))
}

// WalkScriptPushdata is the exported alias of walkScriptPushdata.
// External callers (cmd/bsvm BEEF extractors, etc.) need to walk push
// payloads of arbitrary BSV scripts (covenant unlocks, OP_RETURN
// outputs). Re-exporting under a stable name keeps the parser in one
// place rather than copying it across packages.
func WalkScriptPushdata(script []byte) ([][]byte, error) {
	return walkScriptPushdata(script)
}

// walkScriptPushdata returns every pushdata payload found in script
// in source order. Non-push opcodes are skipped silently. Returns an
// error only on a truncated push (the script claims more bytes than
// are present).
//
// Recognised push opcodes:
//   - 0x01..0x4b: direct push of N bytes
//   - 0x4c (OP_PUSHDATA1): 1-byte length prefix
//   - 0x4d (OP_PUSHDATA2): 2-byte little-endian length prefix
//   - 0x4e (OP_PUSHDATA4): 4-byte little-endian length prefix
//
// All other opcodes are non-push and consume only the opcode byte.
func walkScriptPushdata(script []byte) ([][]byte, error) {
	var out [][]byte
	pos := 0
	for pos < len(script) {
		op := script[pos]
		pos++
		switch {
		case op >= 0x01 && op <= 0x4b:
			n := int(op)
			if pos+n > len(script) {
				return nil, fmt.Errorf("truncated push at offset %d: want %d bytes, have %d",
					pos-1, n, len(script)-pos)
			}
			out = append(out, append([]byte(nil), script[pos:pos+n]...))
			pos += n
		case op == 0x4c:
			if pos+1 > len(script) {
				return nil, fmt.Errorf("truncated OP_PUSHDATA1 length at offset %d", pos-1)
			}
			n := int(script[pos])
			pos++
			if pos+n > len(script) {
				return nil, fmt.Errorf("truncated OP_PUSHDATA1 payload at offset %d: want %d bytes, have %d",
					pos-2, n, len(script)-pos)
			}
			out = append(out, append([]byte(nil), script[pos:pos+n]...))
			pos += n
		case op == 0x4d:
			if pos+2 > len(script) {
				return nil, fmt.Errorf("truncated OP_PUSHDATA2 length at offset %d", pos-1)
			}
			n := int(script[pos]) | int(script[pos+1])<<8
			pos += 2
			if pos+n > len(script) {
				return nil, fmt.Errorf("truncated OP_PUSHDATA2 payload at offset %d: want %d bytes, have %d",
					pos-3, n, len(script)-pos)
			}
			out = append(out, append([]byte(nil), script[pos:pos+n]...))
			pos += n
		case op == 0x4e:
			if pos+4 > len(script) {
				return nil, fmt.Errorf("truncated OP_PUSHDATA4 length at offset %d", pos-1)
			}
			n := int(script[pos]) | int(script[pos+1])<<8 |
				int(script[pos+2])<<16 | int(script[pos+3])<<24
			pos += 4
			if n < 0 || pos+n > len(script) {
				return nil, fmt.Errorf("truncated OP_PUSHDATA4 payload at offset %d: want %d bytes, have %d",
					pos-5, n, len(script)-pos)
			}
			out = append(out, append([]byte(nil), script[pos:pos+n]...))
			pos += n
		default:
			// Non-push opcode (OP_DUP, OP_HASH160, OP_CHECKSIG,
			// OP_RETURN, etc). No payload to consume.
		}
	}
	return out, nil
}
