package contracts

import (
	"encoding/binary"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// F07 — spec-12 OP_RETURN data-output coverage for Mode 1 (trust-minimized
// FRI bridge). Shares the magic + helpers defined in rollup_groth16_f07_test.go.

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

func TestFRIRollup_F07_DifferentBatchesProduceDifferentScripts(t *testing.T) {
	c1 := newFRIRollup(zeros32(), 0, 0)
	args1 := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c1, args1)
	script1 := extractDataOutputScript(t, c1.DataOutputs())

	c2 := newFRIRollup(zeros32(), 0, 0)
	args2 := buildFRIArgs(zeros32(), 1)
	altBatch := []byte(args2.batchData)
	altBatch[0] ^= 0xFF
	args2.batchData = runar.ByteString(altBatch)
	pv := buildPublicValues(zeros32(), stateRootForBlock(1), string(altBatch), string(args2.proofBlob), chainId)
	args2.publicValues = runar.ByteString(pv)
	callFRIAdvance(c2, args2)
	script2 := extractDataOutputScript(t, c2.DataOutputs())

	if string(script1) == string(script2) {
		t.Fatal("expected different OP_RETURN scripts for different batchData")
	}
}
