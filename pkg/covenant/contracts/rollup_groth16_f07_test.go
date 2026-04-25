package contracts

import (
	"encoding/binary"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// F07 — spec-12 OP_RETURN data-output coverage.
//
// Both Mode 2 (Groth16RollupContract) and Mode 3 WA
// (Groth16WARollupContract) now emit batchData in an OP_RETURN output
// via c.AddDataOutput(0, ...). Rúnar's auto-injected continuation hash
// check includes data outputs in declaration order after state outputs
// and before the change output, so the on-chain BSV tx is required to
// carry the emitted script verbatim.
//
// Format:
//
//	OP_FALSE OP_RETURN OP_PUSHDATA4 <payload_len_le4> "BSVM\x02" <batchData>
//
// The "BSVM\x02" magic mirrors the "BSVM\x01" genesis prefix in
// pkg/covenant/genesis.go. Indexers can filter covenant-advance
// OP_RETURNs from unrelated OP_RETURN traffic by matching the magic.

const (
	// Script-level header bytes.
	opReturnHdr0     = byte(0x00) // OP_FALSE
	opReturnHdr1     = byte(0x6a) // OP_RETURN
	opReturnPushData = byte(0x4e) // OP_PUSHDATA4
)

// advanceMagic is the BSVM advance OP_RETURN magic ("BSVM\x02").
var advanceMagic = []byte{'B', 'S', 'V', 'M', 0x02}

// expectedOpReturnScript builds the reference script the contract should
// emit for a given batchData. Used to compare against the mock-captured
// DataOutputs entry.
func expectedOpReturnScript(batchData []byte) []byte {
	payload := append([]byte{}, advanceMagic...)
	payload = append(payload, batchData...)
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(payload)))

	script := []byte{opReturnHdr0, opReturnHdr1, opReturnPushData}
	script = append(script, lenBytes...)
	script = append(script, payload...)
	return script
}

// extractDataOutputScript fetches the single data-output script from a
// mock-recorded StatefulSmartContract. Fails the test if shape is wrong.
func extractDataOutputScript(t *testing.T, outs []runar.OutputSnapshot) []byte {
	t.Helper()
	if len(outs) != 1 {
		t.Fatalf("expected 1 data output, got %d", len(outs))
	}
	if outs[0].Satoshis != 0 {
		t.Errorf("expected 0 satoshis on OP_RETURN, got %d", outs[0].Satoshis)
	}
	if outs[0].Kind != runar.OutputKindData {
		t.Errorf("expected OutputKindData, got %s", outs[0].Kind)
	}
	if len(outs[0].Values) != 1 {
		t.Fatalf("expected 1 Values entry in data output, got %d", len(outs[0].Values))
	}
	script, ok := outs[0].Values[0].(runar.ByteString)
	if !ok {
		t.Fatalf("data output value is %T, expected runar.ByteString", outs[0].Values[0])
	}
	return []byte(script)
}

// ---------------------------------------------------------------------------
// Mode 2 (generic Groth16) — F07 coverage
// ---------------------------------------------------------------------------

// TestGroth16Rollup_F07_EmitsSpec12OpReturn pins that every Mode 2
// advance emits exactly one data output carrying the batchData in the
// spec-12 OP_RETURN format.
func TestGroth16Rollup_F07_EmitsSpec12OpReturn(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)

	got := extractDataOutputScript(t, c.DataOutputs())
	want := expectedOpReturnScript([]byte(args.batchData))
	if string(got) != string(want) {
		t.Errorf("OP_RETURN script mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestGroth16Rollup_F07_MagicPrefix validates the first 3 header bytes
// and the 5-byte "BSVM\x02" magic independently of the rest of the
// payload. Separates header regressions from length encoding bugs.
func TestGroth16Rollup_F07_MagicPrefix(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)

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

// TestGroth16Rollup_F07_LengthEncoding pins the OP_PUSHDATA4 length
// field matches payload size (BSVM\x02 + batchData).
func TestGroth16Rollup_F07_LengthEncoding(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)

	script := extractDataOutputScript(t, c.DataOutputs())
	declaredLen := binary.LittleEndian.Uint32(script[3:7])
	wantLen := uint32(len(advanceMagic) + len(args.batchData))
	if declaredLen != wantLen {
		t.Errorf("OP_PUSHDATA4 length: got %d, want %d", declaredLen, wantLen)
	}
}

// TestGroth16Rollup_F07_BatchDataRoundTrip verifies batchData can be
// recovered byte-for-byte from the emitted OP_RETURN. This is the
// end-to-end "node replay reads batchData from OP_RETURN" story.
func TestGroth16Rollup_F07_BatchDataRoundTrip(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)

	script := extractDataOutputScript(t, c.DataOutputs())
	recovered := script[3+4+len(advanceMagic):]
	if string(recovered) != string(args.batchData) {
		t.Errorf("batchData not recoverable from OP_RETURN:\n  got  %x\n  want %x",
			recovered, []byte(args.batchData))
	}
}

// TestGroth16Rollup_F07_DifferentBatchesProduceDifferentScripts pins
// the continuation-hash binding's purpose: swapping batchData between
// advances changes the OP_RETURN bytes, so an attacker cannot reuse
// one tx's OP_RETURN with another batch without regenerating the
// advance.
func TestGroth16Rollup_F07_DifferentBatchesProduceDifferentScripts(t *testing.T) {
	c1 := newGroth16Rollup(zeros32(), 0, 0)
	args1 := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c1, args1)
	script1 := extractDataOutputScript(t, c1.DataOutputs())

	c2 := newGroth16Rollup(zeros32(), 0, 0)
	args2 := buildGroth16Args(zeros32(), 1)
	// Mutate batchData (and its hash in publicValues so pv check still
	// passes) so the script payload is demonstrably different.
	altBatch := []byte(args2.batchData)
	altBatch[0] ^= 0xFF
	args2.batchData = runar.ByteString(altBatch)
	// Rebuild publicValues with the altered batchData's hash so the
	// covenant's pvBatchDataHash check still accepts.
	pv := buildPublicValues(zeros32(), stateRootForBlock(1), string(altBatch), string(args2.proofBlob), chainId, 1)
	args2.publicValues = runar.ByteString(pv)
	args2.g16Input1 = expectedG16Input1(pv)
	callGroth16Advance(c2, args2)
	script2 := extractDataOutputScript(t, c2.DataOutputs())

	if string(script1) == string(script2) {
		t.Fatal("expected different OP_RETURN scripts for different batchData")
	}
}

// ---------------------------------------------------------------------------
// Mode 3 WA — F07 coverage
// ---------------------------------------------------------------------------

// TestGroth16WARollup_F07_EmitsSpec12OpReturn pins that every Mode 3
// WA advance emits exactly one data output carrying batchData in the
// spec-12 OP_RETURN format.
func TestGroth16WARollup_F07_EmitsSpec12OpReturn(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)

	got := extractDataOutputScript(t, c.DataOutputs())
	want := expectedOpReturnScript([]byte(args.batchData))
	if string(got) != string(want) {
		t.Errorf("OP_RETURN script mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestGroth16WARollup_F07_MagicPrefix validates the first 3 header
// bytes and the 5-byte "BSVM\x02" magic.
func TestGroth16WARollup_F07_MagicPrefix(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)

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

// TestGroth16WARollup_F07_LengthEncoding pins the OP_PUSHDATA4 length
// field matches payload size (BSVM\x02 + batchData).
func TestGroth16WARollup_F07_LengthEncoding(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)

	script := extractDataOutputScript(t, c.DataOutputs())
	declaredLen := binary.LittleEndian.Uint32(script[3:7])
	wantLen := uint32(len(advanceMagic) + len(args.batchData))
	if declaredLen != wantLen {
		t.Errorf("OP_PUSHDATA4 length: got %d, want %d", declaredLen, wantLen)
	}
}

// TestGroth16WARollup_F07_BatchDataRoundTrip verifies batchData can be
// recovered byte-for-byte from the emitted OP_RETURN.
func TestGroth16WARollup_F07_BatchDataRoundTrip(t *testing.T) {
	c := newGroth16WARollup(zeros32(), 0, 0)
	args := buildGroth16WAArgs(zeros32(), 1)
	callGroth16WAAdvance(c, args)

	script := extractDataOutputScript(t, c.DataOutputs())
	recovered := script[3+4+len(advanceMagic):]
	if string(recovered) != string(args.batchData) {
		t.Errorf("batchData not recoverable from OP_RETURN:\n  got  %x\n  want %x",
			recovered, []byte(args.batchData))
	}
}

// TestGroth16Rollup_F07_NoAdvanceNoDataOutput — frozen-reject path must
// NOT emit a data output (AddDataOutput happens AFTER the frozen
// assertion, so an early panic means no output was recorded).
func TestGroth16Rollup_F07_NoAdvanceNoDataOutput(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on frozen advance")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 1) // frozen
	args := buildGroth16Args(zeros32(), 1)
	defer func() {
		if outs := c.DataOutputs(); len(outs) != 0 {
			t.Errorf("rejected advance leaked %d data outputs", len(outs))
		}
	}()
	callGroth16Advance(c, args)
}
