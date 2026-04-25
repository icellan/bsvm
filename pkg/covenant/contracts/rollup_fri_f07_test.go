package contracts

import (
	"encoding/binary"
	"testing"
)

// F07 — spec-12 OP_RETURN data-output coverage for Mode 1
// (trust-minimized FRI bridge).
//
// Mode 1 now emits batchData in a BSVM\x02 OP_RETURN output alongside
// the state continuation. Rúnar's auto-injected continuation hash check
// includes the data output in declaration order (after state outputs,
// before change), and the runar-go SDK's BuildCallTransaction resolves
// AddDataOutput ANF bindings at call time and emits the output as a
// real tx output — so on-chain hashOutputs matches the compiled
// script's pinned continuation-hash constant. Mirrors the Mode 2 / Mode
// 3 F07 suites.
//
// Format (identical across all three modes):
//
//	OP_FALSE OP_RETURN OP_PUSHDATA4 <payload_len_le4> "BSVM\x02" <batchData>

// TestFRIRollup_F07_EmitsSpec12OpReturn pins that every Mode 1 advance
// emits exactly one data output carrying batchData in the spec-12
// OP_RETURN format.
func TestFRIRollup_F07_EmitsSpec12OpReturn(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)

	got := extractDataOutputScript(t, c.DataOutputs())
	want := expectedOpReturnScript([]byte(args.batchData))
	if string(got) != string(want) {
		t.Errorf("OP_RETURN script mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestFRIRollup_F07_MagicPrefix validates the first 3 header bytes and
// the 5-byte "BSVM\x02" magic independently of the rest of the payload.
func TestFRIRollup_F07_MagicPrefix(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)

	script := extractDataOutputScript(t, c.DataOutputs())
	if len(script) < 3+4+5 {
		t.Fatalf("script too short: %d bytes", len(script))
	}
	if script[0] != opReturnHdr0 || script[1] != opReturnHdr1 || script[2] != opReturnPushData {
		t.Errorf("bad OP_FALSE OP_RETURN OP_PUSHDATA4 prefix: got %02x %02x %02x",
			script[0], script[1], script[2])
	}
	magic := script[7 : 7+5]
	if string(magic) != string(advanceMagic) {
		t.Errorf("bad BSVM\\x02 magic at offset 7: got %x, want %x", magic, advanceMagic)
	}
}

// TestFRIRollup_F07_LengthEncoding pins the OP_PUSHDATA4 length field
// matches payload size (BSVM\x02 + batchData).
func TestFRIRollup_F07_LengthEncoding(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)

	script := extractDataOutputScript(t, c.DataOutputs())
	declaredLen := binary.LittleEndian.Uint32(script[3:7])
	wantLen := uint32(len(advanceMagic) + len(args.batchData))
	if declaredLen != wantLen {
		t.Errorf("OP_PUSHDATA4 length: got %d, want %d", declaredLen, wantLen)
	}
}

// TestFRIRollup_F07_BatchDataRoundTrip verifies batchData can be
// recovered byte-for-byte from the emitted OP_RETURN.
func TestFRIRollup_F07_BatchDataRoundTrip(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)

	script := extractDataOutputScript(t, c.DataOutputs())
	recovered := script[3+4+len(advanceMagic):]
	if string(recovered) != string(args.batchData) {
		t.Errorf("batchData not recoverable from OP_RETURN:\n  got  %x\n  want %x",
			recovered, []byte(args.batchData))
	}
}

// TestFRIRollup_F07_NoAdvanceNoDataOutput — frozen-reject path must NOT
// emit a data output (AddDataOutput happens AFTER the frozen assertion,
// so an early panic means no output was recorded).
func TestFRIRollup_F07_NoAdvanceNoDataOutput(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on frozen advance")
		}
	}()
	c := newFRIRollup(zeros32(), 0, 1) // frozen
	args := buildFRIArgs(zeros32(), 1)
	defer func() {
		if outs := c.DataOutputs(); len(outs) != 0 {
			t.Errorf("rejected advance leaked %d data outputs", len(outs))
		}
	}()
	callFRIAdvance(c, args)
}
