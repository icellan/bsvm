package contracts

import (
	"testing"
)

// F07 — spec-12 OP_RETURN data-output coverage for Mode 1 (trust-minimized
// FRI bridge).
//
// These tests previously asserted that AdvanceState emits a BSVM\x02
// OP_RETURN output carrying the raw batchData. That behaviour has been
// withdrawn in the trust-minimized FRI bridge because the Rúnar Go SDK
// does not yet honour `add_data_output` ANF bindings when assembling
// the call transaction — `BuildCallTransaction` only emits the state
// continuation and change outputs, so every compiled script that used
// `AddDataOutput` for its continuation-hash check failed on-chain with
// "Script evaluated without error but finished with a false/empty top
// stack element". The covenant still binds the batchData via
// `pvBatchDataHash == hash256(batchData)`, so the hash commitment is
// preserved; only the raw-bytes DA channel has moved from BSV to P2P
// gossip. When the SDK learns to walk a method's ANF for data outputs
// and emit them between the contract continuation and the change
// output, the F07 OP_RETURN contract-level guarantee (and these tests)
// can be restored verbatim.

// TestFRIRollup_F07_NoOpReturn asserts the advance method records NO
// data outputs on the contract instance. The companion Mode 2 / Mode 3
// Groth16 variants keep the OP_RETURN envelope since they declare it
// via AddDataOutput (but they're guarded by the same SDK limitation —
// fixing either requires the runar-go tx builder to honour
// add_data_output ANF bindings).
func TestFRIRollup_F07_NoOpReturn(t *testing.T) {
	c := newFRIRollup(zeros32(), 0, 0)
	args := buildFRIArgs(zeros32(), 1)
	callFRIAdvance(c, args)

	if got := len(c.DataOutputs()); got != 0 {
		t.Errorf("Mode 1 FRI AdvanceState must NOT emit any data outputs "+
			"(SDK limitation — see file header); got %d data outputs", got)
	}
}
